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
//! terminal's, and its idea of that is its own (see `error_colour`): either
//! of standard output and standard error being a terminal is enough, so
//! `dede status 2> log` on a terminal writes the escape codes into the file.
//! That is reproduced, since it is what users of the published dede see.

use std::io::{IsTerminal, Write};

pub struct Out {
    pending: Vec<(Stream, String)>,
    live: bool,
    red_errors: bool,
}

/// Does bun colour `console.error`? Read off bun 1.4.0 for each combination
/// below; `None` for a value of NO_COLOR or FORCE_COLOR that was not tried.
/// (Only the real environment counts: bun has decided before it loads a
/// `.env` file.)
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
    Some(match forced {
        Some(true) => true,
        _ if disabled => false,
        // Switched "off", it still colours what goes to a terminal directly.
        Some(false) => stderr_is_terminal,
        None => stdout_is_terminal || stderr_is_terminal,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum Stream {
    Out,
    Err,
}

impl Out {
    /// The output of this process, coloured as bun would colour it; `None`
    /// where that is not known.
    pub fn for_this_process() -> Option<Out> {
        let variable = |name: &str| match std::env::var_os(name) {
            None => Some(None),
            Some(value) => value.into_string().ok().map(Some),
        };
        let (no_color, force_color) = (variable("NO_COLOR")?, variable("FORCE_COLOR")?);
        let red_errors = error_colour(no_color.as_deref(), force_color.as_deref(), std::io::stdout().is_terminal(), std::io::stderr().is_terminal())?;
        Some(Out { pending: Vec::new(), live: false, red_errors })
    }

    /// `console.log(text)`
    pub fn log(&mut self, text: &str) {
        self.push(Stream::Out, format!("{text}\n"));
    }

    /// `console.error(text)`
    pub fn error(&mut self, text: &str) {
        if self.red_errors {
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

    /// From here on everything is written as it comes.
    pub fn go_live(&mut self) {
        self.live = true;
        self.flush();
    }

    /// Has the command passed the point where it can still be handed back?
    pub fn is_live(&self) -> bool {
        self.live
    }

    /// Writes what was collected, one write per message, in order. A closed
    /// pipe is not this program's problem.
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

#[cfg(test)]
mod tests {
    use super::error_colour;

    /// Whether bun 1.4.0 prints `console.error` in red, recorded for standard
    /// output and standard error being (pipe, pipe), (pipe, terminal),
    /// (terminal, pipe) and (terminal, terminal).
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
        assert_eq!(row(None, None), "-CCC");
        for (value, forced, alone, with_force_off) in [
            ("", "CCCC", "-CCC", "-C-C"),
            ("0", "-C-C", "-CCC", "-C-C"),
            ("1", "CCCC", "----", "----"),
            ("true", "CCCC", "----", "----"),
            ("false", "-C-C", "-CCC", "-C-C"),
            ("2", "CCCC", "----", "----"),
            ("00", "-C-C", "----", "----"),
            ("no", "-C-C", "-CCC", "-C-C"),
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
