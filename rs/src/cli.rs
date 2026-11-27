//! `main()` of dede.ts: the flags every command shares, the switch on the
//! first argument, and what becomes of an error.
//!
//! `Err(HandBack)` leaves here only while nothing has been printed and
//! nothing on disk has changed. Commands that only read collect their output
//! and print it at the end. `enc` and `dec` first read everything they are
//! going to read (`precheck`), which is where anything this port does not
//! imitate would show, and only then start to write.

use std::io::IsTerminal;

use crate::dede::{self, die, Dede, Mode, Pair, Stop, R};
use crate::env::{Env, HandBack};
use crate::path::join;

/// The commands the binary answers itself. Each was switched on when its
/// parity cases (rs/parity.json) passed; see parity/dotenvdotenc.toml in
/// rustify for what that covers.
fn is_ported(command: Option<&str>) -> bool {
    match command {
        // Usage: `dede`, `dede help`, and what is no command at all.
        None => true,
        Some("get" | "status" | "diff" | "keys" | "dec" | "enc") => true,
        Some("guard" | "health" | "setup") => false,
        Some(_) => true,
    }
}

/// What stays with the JavaScript on every platform but the ones the parity
/// cases run on: Windows has its own path rules, mode bits and symlinks, and
/// no case has ever run there.
fn platform_is_proven() -> bool {
    cfg!(unix)
}

pub fn run(argv: &[String]) -> Result<i32, HandBack> {
    let command = argv.first().map(String::as_str);
    if !is_ported(command) {
        return Err(HandBack);
    }
    let is_usage = !matches!(command, Some("enc" | "dec" | "status" | "diff" | "get" | "guard" | "keys" | "health" | "setup"));
    if !is_usage && !platform_is_proven() {
        return Err(HandBack);
    }
    let env = Env::startup()?;
    let cwd = std::env::current_dir().map_err(|_| HandBack)?.into_os_string().into_string().map_err(|_| HandBack)?;
    let mut dede = Dede::new(env, cwd);
    let code = match main(&mut dede, argv) {
        Ok(code) => code,
        Err(HandBack) if dede.out.is_live() => {
            // Unreachable by design: see `precheck`. The files this run wrote
            // are complete; say that it did not finish rather than start over.
            dede.log("dede: stopped at something this build does not handle; run it again with DOTENVDOTENC_NO_NATIVE=1");
            1
        }
        Err(HandBack) => return Err(HandBack),
    };
    dede.out.flush();
    Ok(code)
}

/// The exit code, as `main(argv)` of dede.ts returns it.
fn main(dede: &mut Dede, argv: &[String]) -> Result<i32, HandBack> {
    let command = argv.first().map(String::as_str);
    let raw = argv.get(1..).unwrap_or(&[]);
    let mut rest: Vec<String> = Vec::new();
    dede.keys_override = dede.env.get("DOTENV_KEYS_FILE").filter(|file| !file.is_empty());
    let mut i = 0;
    while i < raw.len() {
        let arg = raw[i].as_str();
        if arg == "-fk" || arg == "--env-keys-file" {
            let Some(path) = raw.get(i + 1) else {
                dede.log(&format!("dede: {arg} needs a path"));
                return Ok(4);
            };
            dede.keys_override = Some(path.clone());
            i += 1;
        } else if arg == "--key" {
            let name = raw.get(i + 1).map(String::as_str).unwrap_or("");
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                dede.log("dede: --key needs a NAME like TAKU (for DOTENV_PRIVATE_KEY_TAKU)");
                return Ok(4);
            }
            dede.key_choice = Some(name.to_string());
            i += 1;
        } else if let Some(path) = arg.strip_prefix("--env-keys-file=") {
            dede.keys_override = Some(path.to_string());
        } else {
            rest.push(arg.to_string());
        }
        i += 1;
    }
    // An empty path stays empty (and is then no file at all).
    if let Some(file) = dede.keys_override.clone().filter(|file| !file.is_empty()) {
        dede.keys_override = Some(dede.resolve(&file));
    }
    let has = |flag: &str| rest.iter().any(|arg| arg == flag);
    let force = has("--force");
    let yes = has("-y") || has("--yes");
    let all = has("--all");
    dede.quiet = has("--quiet");
    let args: Vec<String> = rest.iter().filter(|arg| !matches!(arg.as_str(), "--force" | "--all" | "--quiet" | "-y" | "--yes")).cloned().collect();

    let mut code = 0;
    let result: R<()> = (|| {
        match command {
            Some("enc") => {
                // With a terminal and without -y the TypeScript asks before
                // it commits. Asking is not ported.
                if !yes && std::io::stdin().is_terminal() {
                    return Err(Stop::HandBack);
                }
                let pairs = dede.pairs(&args, Mode::Enc)?;
                precheck(dede, &pairs)?;
                dede.out.go_live();
                each(dede, &pairs, &mut code, |dede, pair| dede.enc(pair, force))?;
                code = code.max(dede.commit_written(yes));
            }
            Some("dec") => {
                let pairs = dede.pairs(&args, Mode::Dec)?;
                precheck(dede, &pairs)?;
                dede.out.go_live();
                each(dede, &pairs, &mut code, |dede, pair| dede.dec(pair, force))?;
            }
            Some("status") => {
                let pairs = dede.pairs(&args, Mode::Any)?;
                let mut out_of_sync = false;
                each(dede, &pairs, &mut code, |dede, pair| {
                    if !dede.status(pair)? {
                        out_of_sync = true;
                    }
                    Ok(())
                })?;
                if out_of_sync {
                    code = code.max(1);
                }
                let top = dede.git_dir(&dede.cwd)?;
                for file in dede.unmanaged_env_files(&top)? {
                    let path = join(&top, &file);
                    if pairs.iter().any(|pair| pair.plain == path) {
                        continue;
                    }
                    dede.out.log(&format!("✗ {}: unmanaged plaintext env file (not committed, no .enc, not *.local): `dede enc` it and commit the .enc, or rename it to *.local", dede.rel(&path)));
                    code = code.max(1);
                }
            }
            Some("get") => {
                let Some(name) = args.first().filter(|name| !name.is_empty()) else {
                    return die("usage: dede get NAME [file|glob…]".into(), 4);
                };
                let pairs = dede.pairs(&args[1..], Mode::Dec)?;
                dede.get(name, &pairs, std::io::stdout().is_terminal())?;
            }
            Some("diff") => {
                let pairs = dede.pairs(&args, Mode::Any)?;
                let mut differs = false;
                each(dede, &pairs, &mut code, |dede, pair| {
                    if !dede.diff(pair)? {
                        differs = true;
                    }
                    Ok(())
                })?;
                if differs {
                    code = code.max(1);
                }
            }
            Some("guard") => dede.guard(all)?,
            Some("keys") => {
                if args.first().map(String::as_str) == Some("link") {
                    dede.keys_link(args.get(1).map(String::as_str))?;
                } else {
                    let pairs = dede.pairs(&args, Mode::Dec)?;
                    if !dede.keys_status(&pairs)? {
                        code = 1;
                    }
                }
            }
            None | Some("help" | "--help" | "-h") => dede.out.log(dede::USAGE),
            Some(_) => {
                dede.log(dede::USAGE);
                code = 4;
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(code),
        Err(Stop::Die(message, code)) => {
            let line = if message.starts_with("dede") { message } else { format!("dede: {message}") };
            dede.log(&line);
            Ok(code)
        }
        // Any other error ends the TypeScript in bun's report of an uncaught
        // exception, source excerpt and stack included.
        Err(Stop::Thrown(_)) | Err(Stop::HandBack) => Err(HandBack),
    }
}

/// Runs `step` for each pair. A failure fails that file only: a `DedeError`
/// with its message, anything else by its name, without the library's text.
fn each(dede: &mut Dede, pairs: &[Pair], code: &mut i32, mut step: impl FnMut(&mut Dede, &Pair) -> R<()>) -> R<()> {
    for pair in pairs {
        let (message, failure) = match step(dede, pair) {
            Ok(()) => continue,
            Err(Stop::Die(message, code)) => (message, code),
            Err(Stop::Thrown(name)) => (format!("{}: {name} (invalid key or file?)", dede.rel(&pair.enc)), 3),
            Err(Stop::HandBack) => return Err(Stop::HandBack),
        };
        dede.log(&format!("dede: {message}"));
        *code = (*code).max(failure);
    }
    Ok(())
}

/// Reads, without changing or printing anything, what `enc` or `dec` is
/// about to read for these pairs: both files, the keys, the key tree, and the
/// sync record. Whatever this port does not imitate (see `Stop::HandBack`)
/// shows here, while the invocation can still be handed back. Failures the
/// TypeScript reports are not this function's business; the real run reports
/// them.
fn precheck(dede: &mut Dede, pairs: &[Pair]) -> R<()> {
    let only_hand_back = |result: R<()>| match result {
        Err(Stop::HandBack) => Err(Stop::HandBack),
        _ => Ok(()),
    };
    for pair in pairs {
        only_hand_back(dede.view(pair, true).map(|_| ()))?;
        only_hand_back(dede.tree_for(crate::path::dirname(&pair.plain)).map(|_| ()))?;
        only_hand_back(dede.check_sync_record(pair))?;
    }
    Ok(())
}
