//! What the program prints.
//!
//! Until an invocation is certain to be answered here, nothing may reach the
//! terminal: it might still be handed back to the JavaScript, which then
//! prints everything itself. So output is collected, in order and per
//! stream, and written when the command is over — or from the moment the
//! command starts changing files (`go_live`), after which there is no way
//! back anyway and a message should not wait for the work to end.
//!
//! bun prints `console.error` in red where it takes the output for a
//! terminal's, and its idea of that is its own (see `error_colour`). Where
//! the rule is known it is reproduced: standard error a terminal is enough,
//! so is FORCE_COLOR, and neither stream a terminal is plain. Where standard
//! output is a terminal and standard error is not (`dede status 2> log`),
//! bun decides by TERM, COLORTERM, CI, TMUX and more, in a way that was not
//! worked out; a command that would print to standard error there is handed
//! back, before it prints or changes anything.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::env::HandBack;

/// Set once a command has started to write (see `go_live`): from then on the
/// invocation cannot be handed back any more, whatever happens.
static LIVE: AtomicBool = AtomicBool::new(false);

pub fn has_gone_live() -> bool {
    LIVE.load(Ordering::Relaxed)
}

pub struct Out {
    pending: Vec<(Stream, String)>,
    live: bool,
    /// `None`: what bun would do is not known; nothing may go to standard
    /// error natively then.
    red_errors: Option<bool>,
}

/// Does bun colour `console.error`? Read off bun 1.4.0 for each combination
/// below, under TERM unset, empty, dumb, xterm and xterm-256color, and with
/// COLORTERM, CI, TMUX, TERM_PROGRAM and NODE_DISABLE_COLORS set and unset.
/// `None` where the answer depends on more than this: a value of NO_COLOR or
/// FORCE_COLOR that was not tried, and standard output a terminal with
/// standard error not one, unless NO_COLOR or FORCE_COLOR decides. (Only
/// the real environment counts: bun has decided before it loads a `.env`
/// file.)
pub fn error_colour(no_color: Option<&str>, force_color: Option<&str>, stdout_is_terminal: bool, stderr_is_terminal: bool) -> Option<bool> {
    let disabled = match no_color {
        None | Some("" | "0" | "false" | "no") => false,
        Some("1" | "true" | "2" | "00" | " ") => true,
        Some(_) => return None,
    };
    let forced = match force_color {
        None => None,
        Some("" | "1" | "true" | "2" | " ") => Some(true),
        Some("0" | "false" | "no" | "00") => Some(false),
        Some(_) => return None,
    };
    match forced {
        Some(true) => Some(true),
        _ if disabled => Some(false),
        // Switched "off", it still colours what goes to a terminal directly.
        Some(false) => Some(stderr_is_terminal),
        None if stderr_is_terminal => Some(true),
        // Here bun asks TERM, COLORTERM, CI, TMUX, … (`TERM=xterm` red,
        // `TERM=dumb` or unset plain, unset with CI=true red again).
        None if stdout_is_terminal => None,
        None => Some(false),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Stream {
    Out,
    Err,
}

impl Out {
    /// The output of this process, coloured as bun would colour it, where
    /// that is known.
    pub fn for_this_process() -> Out {
        let variable = |name: &str| match std::env::var_os(name) {
            None => Some(None),
            Some(value) => value.into_string().ok().map(Some),
        };
        let red_errors = match (variable("NO_COLOR"), variable("FORCE_COLOR")) {
            (Some(no_color), Some(force_color)) => error_colour(no_color.as_deref(), force_color.as_deref(), std::io::stdout().is_terminal(), std::io::stderr().is_terminal()),
            _ => None,
        };
        Out { pending: Vec::new(), live: false, red_errors }
    }

    /// `console.log(text)`
    pub fn log(&mut self, text: &str) {
        self.push(Stream::Out, format!("{text}\n"));
    }

    /// `console.error(text)`. Where the colour is not known this is never
    /// printed: `finish` hands the invocation back.
    pub fn error(&mut self, text: &str) {
        if self.red_errors == Some(true) {
            self.push(Stream::Err, format!("\x1b[0m\x1b[31m{text}\x1b[0m\n"));
        } else {
            self.push(Stream::Err, format!("{text}\n"));
        }
    }

    /// `process.stdout.write(text)`
    pub fn write(&mut self, text: &str) {
        self.push(Stream::Out, text.to_string());
    }

    fn push(&mut self, stream: Stream, text: String) {
        self.pending.push((stream, text));
        if self.live {
            self.flush();
        }
    }

    /// Is it known how bun would print to standard error? Everything that
    /// changes a file and then prints there asks before the change.
    pub fn colour_is_known(&self) -> bool {
        self.red_errors.is_some()
    }

    /// From here on everything is written as it comes. Refused where the
    /// colour of errors is not known: a command that changes files prints
    /// to standard error.
    pub fn go_live(&mut self) -> Result<(), HandBack> {
        if !self.colour_is_known() {
            return Err(HandBack);
        }
        self.live = true;
        LIVE.store(true, Ordering::Relaxed);
        self.flush();
        Ok(())
    }

    /// Has the command passed the point where it can still be handed back?
    pub fn is_live(&self) -> bool {
        self.live
    }

    /// At the end of the command: writes what was collected, or hands the
    /// invocation back if any of it would go to standard error in a colour
    /// that is not known.
    pub fn finish(&mut self) -> Result<(), HandBack> {
        if !self.live && !self.colour_is_known() && self.pending.iter().any(|(stream, _)| *stream == Stream::Err) {
            return Err(HandBack);
        }
        self.flush();
        Ok(())
    }

    /// Would `process.stdout.write(text)` of `len` bytes, with `process.exit()`
    /// right after it, get all of it out under bun? Into a pipe or a socket
    /// bun writes without waiting, and what the pipe has no room for is lost
    /// at the exit (`dede get BIG | slow-reader` printed 65,536 bytes of
    /// 70,000 under bun 1.4.0); into a file or a terminal it writes it all.
    /// So this says yes only where the room is certain: a file, a terminal,
    /// /dev/null, and on Linux a pipe or a Unix socket with room for it now,
    /// after what this process prints there first (the room only grows
    /// while the JavaScript would start). `console.log` and `console.error`
    /// are not like this: under bun they wait for the reader, as every write
    /// here does (and where another program has left the pipe without
    /// waiting, bun and this lose the same messages).
    pub fn stdout_takes(&self, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let shared = room::stderr_is_stdout();
        let before: Vec<usize> = self.pending.iter().filter(|(stream, _)| *stream == Stream::Out || shared).map(|(_, text)| text.len()).collect();
        room::for_stdout(before.iter().sum(), before.len()).is_some_and(|room| len <= room)
    }

    /// Writes what was collected, one write per message, in order. A closed
    /// pipe is not this program's problem. Into a pipe that another program
    /// left without waiting (bun does that), a message there is no room for
    /// is lost, as it is under bun.
    pub fn flush(&mut self) {
        for (stream, text) in self.pending.drain(..) {
            let _ = match stream {
                Stream::Out => {
                    let mut out = std::io::stdout().lock();
                    out.write_all(text.as_bytes()).and_then(|_| out.flush())
                }
                Stream::Err => {
                    let mut err = std::io::stderr().lock();
                    err.write_all(text.as_bytes()).and_then(|_| err.flush())
                }
            };
        }
    }
}

/// How much standard output takes in one write without waiting, where that
/// is certain.
#[cfg(unix)]
mod room {
    use std::fs::{File, Metadata};
    use std::mem::ManuallyDrop;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    fn stat(fd: i32) -> Option<Metadata> {
        // SAFETY: the descriptor is only looked at, and never closed here.
        let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        file.metadata().ok()
    }

    /// Are standard error and standard output the same pipe or file (`2>&1`)?
    pub fn stderr_is_stdout() -> bool {
        match (stat(1), stat(2)) {
            (Some(out), Some(err)) => out.dev() == err.dev() && out.ino() == err.ino(),
            _ => true,
        }
    }

    /// The room for one more write on standard output, after `before` bytes
    /// in `writes` writes of this process: `None` for no room that is
    /// certain, `Some(usize::MAX)` where a write is never cut short.
    pub fn for_stdout(before: usize, writes: usize) -> Option<usize> {
        let meta = stat(1)?;
        let kind = meta.file_type();
        if kind.is_file() {
            return Some(usize::MAX);
        }
        if kind.is_char_device() {
            // SAFETY: isatty only looks at the descriptor.
            let terminal = unsafe { libc::isatty(1) } == 1;
            let dev_null = std::fs::metadata("/dev/null").is_ok_and(|null| null.file_type().is_char_device() && null.rdev() == meta.rdev());
            return (terminal || dev_null).then_some(usize::MAX);
        }
        if kind.is_fifo() {
            return pipe(before, writes);
        }
        if kind.is_socket() {
            return socket(before);
        }
        None
    }

    /// A pipe holds a number of pages; a write that does not fill a page
    /// may be added to the last one, and the first may be partly read. So
    /// what is certainly free: every page but those the bytes waiting in it
    /// can take up, one more for a part read and one for each write of this
    /// process that may have left a page partly filled.
    #[cfg(target_os = "linux")]
    fn pipe(before: usize, writes: usize) -> Option<usize> {
        // SAFETY: plain queries of the descriptor, into a local.
        let capacity = unsafe { libc::fcntl(1, libc::F_GETPIPE_SZ) };
        let mut waiting: libc::c_int = 0;
        let asked = unsafe { libc::ioctl(1, libc::FIONREAD, &mut waiting) };
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if capacity <= 0 || asked != 0 || waiting < 0 || page <= 0 {
            return None;
        }
        let (capacity, page) = (capacity as usize, page as usize);
        let queued = waiting as usize + before;
        let used = if queued == 0 { 0 } else { queued.div_ceil(page) + 1 + writes };
        Some((capacity / page).saturating_sub(used) * page)
    }

    /// A Unix stream socket with nothing waiting in it takes one write of up
    /// to 32 KiB in one buffer, as long as that is well below its send
    /// buffer. Anything else is not certain.
    #[cfg(target_os = "linux")]
    fn socket(before: usize) -> Option<usize> {
        let option = |name: libc::c_int| -> Option<libc::c_int> {
            let mut value: libc::c_int = 0;
            let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: getsockopt writes at most `size` bytes into `value`.
            let done = unsafe { libc::getsockopt(1, libc::SOL_SOCKET, name, (&mut value as *mut libc::c_int).cast(), &mut size) };
            (done == 0).then_some(value)
        };
        if before > 0 || option(libc::SO_DOMAIN)? != libc::AF_UNIX || option(libc::SO_TYPE)? != libc::SOCK_STREAM {
            return None;
        }
        let mut unsent: libc::c_int = 0;
        // SAFETY: SIOCOUTQ writes one int.
        if unsafe { libc::ioctl(1, libc::TIOCOUTQ, &mut unsent) } != 0 || unsent != 0 {
            return None;
        }
        let half = usize::try_from(option(libc::SO_SNDBUF)?).ok()? / 2;
        Some(half.saturating_sub(4096).min(32768))
    }

    /// Elsewhere (macOS) a pipe's or a socket's room is not known.
    #[cfg(not(target_os = "linux"))]
    fn pipe(_before: usize, _writes: usize) -> Option<usize> {
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn socket(_before: usize) -> Option<usize> {
        None
    }
}

#[cfg(not(unix))]
mod room {
    pub fn stderr_is_stdout() -> bool {
        true
    }

    pub fn for_stdout(_before: usize, _writes: usize) -> Option<usize> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::error_colour;

    /// Whether bun 1.4.0 prints `console.error` in red, recorded for standard
    /// output and standard error being (pipe, pipe), (pipe, terminal),
    /// (terminal, pipe) and (terminal, terminal). `?`: bun asks TERM and
    /// other variables there, and the binary hands back.
    #[test]
    fn colour_follows_bun() {
        let row = |no_color: Option<&str>, force_color: Option<&str>| -> String {
            [(false, false), (false, true), (true, false), (true, true)]
                .iter()
                .map(|(out, err)| match error_colour(no_color, force_color, *out, *err) {
                    Some(true) => 'C',
                    Some(false) => '-',
                    None => '?',
                })
                .collect()
        };
        assert_eq!(row(None, None), "-C?C");
        for (value, forced, alone, with_force_off) in [
            ("", "CCCC", "-C?C", "-C-C"),
            ("0", "-C-C", "-C?C", "-C-C"),
            ("1", "CCCC", "----", "----"),
            ("true", "CCCC", "----", "----"),
            ("false", "-C-C", "-C?C", "-C-C"),
            ("2", "CCCC", "----", "----"),
            ("00", "-C-C", "----", "----"),
            ("no", "-C-C", "-C?C", "-C-C"),
            (" ", "CCCC", "----", "----"),
        ] {
            assert_eq!(row(None, Some(value)), forced, "FORCE_COLOR={value:?}");
            assert_eq!(row(Some(value), None), alone, "NO_COLOR={value:?}");
            assert_eq!(row(Some(value), Some("0")), with_force_off, "NO_COLOR={value:?} FORCE_COLOR=0");
        }
        assert_eq!(row(Some("1"), Some("1")), "CCCC");
        assert_eq!(row(Some("yes"), None), "????");
        assert_eq!(row(None, Some("3")), "????");
    }
}
