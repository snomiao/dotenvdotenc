//! What the program prints.
//!
//! Until an invocation is certain to be answered here, nothing may reach the
//! terminal: it might still be handed back to the JavaScript, which then
//! prints everything itself. So output is collected, in order and per
//! stream, and written when the command is over — or from the moment the
//! command starts changing files (`go_live`), after which there is no way
//! back anyway and a message should not wait for the work to end.

use std::io::Write;

#[derive(Default)]
pub struct Out {
    pending: Vec<(Stream, String)>,
    live: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Stream {
    Out,
    Err,
}

impl Out {
    /// `console.log(text)`
    pub fn log(&mut self, text: &str) {
        self.push(Stream::Out, format!("{text}\n"));
    }

    /// `console.error(text)`
    pub fn error(&mut self, text: &str) {
        self.push(Stream::Err, format!("{text}\n"));
    }

    /// `process.stdout.write(text)`
    pub fn write(&mut self, text: &str) {
        self.push(Stream::Out, text.to_string());
    }

    /// `process.stderr.write(text)`
    pub fn write_error(&mut self, text: &str) {
        self.push(Stream::Err, text.to_string());
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
