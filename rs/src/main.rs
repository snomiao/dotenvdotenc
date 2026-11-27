//! dotenvdotenc — Rust entry point.
//!
//! Installed from npm, this binary is the command users run. A command runs
//! here once it has been ported and a parity test shows it behaves like the
//! TypeScript; until then it is handed back to the JavaScript the package
//! still ships, so nothing changes for users.

mod cli;
mod dede;
mod env;
mod js;
mod js_fallback;
mod out;
mod path;
mod primitives;

/// The package's JavaScript entry, relative to the package root.
const JS_ENTRY: &str = "dede.ts";

/// `DOTENVDOTENC_NO_NATIVE=1` hands every command back to the JavaScript: the way
/// out for a user if a ported command misbehaves.
fn native() -> bool {
    std::env::var_os("DOTENVDOTENC_NO_NATIVE").is_none()
}

fn main() {
    // Arguments that are not valid UTF-8 are for the JavaScript to deal with.
    let args: Option<Vec<String>> = std::env::args_os().skip(1).map(|arg| arg.into_string().ok()).collect();
    if let Some(args) = args.filter(|_| native()) {
        // `cli::run` answers what has been ported and proven, and says
        // `HandBack` for everything else: an invocation or a state of the
        // machine it does not imitate exactly. It says so before anything has
        // been printed or changed.
        if let Ok(code) = cli::run(&args) {
            std::process::exit(code);
        }
    }
    js_fallback::run(JS_ENTRY)
}
