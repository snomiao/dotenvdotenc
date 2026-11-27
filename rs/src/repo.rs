//! What git will find, foreseen without asking git.
//!
//! `enc`, `dec` and `setup` change several files in turn, and the TypeScript
//! asks git where things are only on the way (`--git-path`, `config
//! core.hooksPath`). This port must not ask git anything the TypeScript does
//! not ask, in the order it asks, so before the first write it looks for
//! itself: at every place git could take the sync record from, and at the
//! hooks directory git will name. Where it cannot be sure what git will say,
//! the invocation is handed back.

use std::fs;
use std::io::ErrorKind;

use crate::env::{Env, HandBack};
use crate::js;
use crate::path::{dirname, join, resolve};
use crate::primitives::regex;

/// Where dede keeps its sync record, below the git directory.
const RECORD: &str = "dotenvdotenc/state.json";

/// Variables that move what git finds or reads (the repository, the work
/// tree, the configuration). Rare outside git's own hooks; not imitated.
const MOVING_VARIABLES: [&str; 8] = ["GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"];

fn moved(env: &Env) -> bool {
    MOVING_VARIABLES.iter().any(|name| env.get(name).is_some())
}

/// The git directory a `.git` file names (`gitdir: <path>`), if it is one.
fn gitfile_target(dot_git: &str, dir: &str) -> Option<String> {
    let text = js::utf8(&fs::read(dot_git).ok()?);
    let path = text.strip_prefix("gitdir: ")?.trim_end_matches(['\n', '\r']);
    (!path.is_empty()).then(|| resolve(dir, path))
}

/// Every sync record `git rev-parse --git-path dotenvdotenc/state.json`,
/// run in `start`, could name: at each directory from `start` up to the
/// root, along the path as written and along the real path (git walks the
/// real one), the record in a `.git` directory, in the directory a `.git`
/// file names, and in the directory itself where it looks like a git
/// directory (inside `.git`, or a bare repository). Git stops at the first
/// repository it accepts; this goes on, since it does not judge which one
/// git accepts (an empty `.git` is passed over by git, for one).
pub fn possible_records(start: &str, env: &Env) -> Result<Vec<String>, HandBack> {
    if moved(env) {
        return Err(HandBack);
    }
    let mut chains = vec![start.to_string()];
    if let Ok(real) = fs::canonicalize(start) {
        chains.push(real.into_os_string().into_string().map_err(|_| HandBack)?);
    }
    let mut found: Vec<String> = Vec::new();
    let mut add = |path: String| {
        if !found.contains(&path) {
            found.push(path);
        }
    };
    for mut dir in chains {
        loop {
            let dot_git = join(&dir, ".git");
            match fs::metadata(&dot_git) {
                Ok(meta) if meta.is_dir() => add(join(&dot_git, RECORD)),
                Ok(_) => {
                    if let Some(target) = gitfile_target(&dot_git, &dir) {
                        add(join(&target, RECORD));
                    }
                }
                Err(_) => {}
            }
            if fs::symlink_metadata(join(&dir, "HEAD")).is_ok() {
                add(join(&dir, RECORD));
            }
            let parent = dirname(&dir).to_string();
            if parent == dir {
                break;
            }
            dir = parent;
        }
    }
    Ok(found)
}

/// Where git keeps the hooks of the work tree `top` (as `git rev-parse
/// --show-toplevel` gave it), and whether `core.hooksPath` is set.
pub struct Hooks {
    /// What `git rev-parse --path-format=absolute --git-path hooks` prints.
    pub dir: String,
    /// Is `git config core.hooksPath` anything but empty?
    pub path_set: bool,
}

/// `git config core.hooksPath` and `git rev-parse --path-format=absolute
/// --git-path hooks` for the work tree `top`, read from git's configuration
/// files the way git reads them, for configurations written plainly: no
/// `include`, no continued lines, `hooksPath = <value>` without quotes,
/// escapes or comments, a value that is not `~user/…` or `%(prefix)/…` and
/// has no `..`, set in the user's or the repository's configuration.
/// Anything else is handed back, a system-wide setting included.
pub fn hooks(top: &str, env: &Env) -> Result<Hooks, HandBack> {
    if moved(env) {
        return Err(HandBack);
    }
    let dot_git = join(top, ".git");
    let git_dir = match fs::metadata(&dot_git) {
        Ok(meta) if meta.is_dir() => dot_git,
        Ok(_) => gitfile_target(&dot_git, top).ok_or(HandBack)?,
        Err(_) => return Err(HandBack),
    };
    let common_dir = match fs::read(join(&git_dir, "commondir")) {
        Ok(bytes) => resolve(&git_dir, js::utf8(&bytes).trim_end_matches(['\n', '\r'])),
        Err(err) if err.kind() == ErrorKind::NotFound => git_dir.clone(),
        Err(_) => return Err(HandBack),
    };
    let home = env.get("HOME").filter(|home| !home.is_empty()).ok_or(HandBack)?;
    let mut files: Vec<String> = Vec::new();
    if !no_system(env)? {
        files.extend(system_configs());
    }
    // Only the files git surely reads may set it: a system-wide file found at
    // one of the guessed places may be one this git does not read.
    let guessed = files.len();
    files.push(match env.get("XDG_CONFIG_HOME").filter(|xdg| !xdg.is_empty()) {
        Some(xdg) => join(&xdg, "git/config"),
        None => join(&home, ".config/git/config"),
    });
    files.push(join(&home, ".gitconfig"));
    let local = join(&common_dir, "config");
    files.push(local.clone());
    let mut value: Option<String> = None;
    for (index, file) in files.iter().enumerate() {
        let text = match fs::read(file) {
            Ok(bytes) => js::utf8(&bytes),
            Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => continue,
            Err(_) => return Err(HandBack),
        };
        // core.worktree moves the work tree; extensions.worktreeConfig
        // adds config.worktree.
        if *file == local && text.to_ascii_lowercase().contains("worktree") {
            return Err(HandBack);
        }
        if let Some(found) = hooks_path_in(&text)? {
            if index < guessed {
                return Err(HandBack);
            }
            value = Some(found);
        }
    }
    let Some(value) = value else {
        return Ok(Hooks { dir: join(&common_dir, "hooks"), path_set: false });
    };
    let expanded = if value == "~" || value.starts_with("~/") {
        format!("{home}{}", &value[1..])
    } else if value.starts_with('~') || value.starts_with("%(prefix)/") || value.split('/').any(|part| part == "..") {
        return Err(HandBack);
    } else {
        value
    };
    // Relative to the work tree, `.` and repeated or trailing slashes gone.
    Ok(Hooks { dir: resolve(top, &expanded), path_set: true })
}

/// GIT_CONFIG_NOSYSTEM as git reads a boolean.
fn no_system(env: &Env) -> Result<bool, HandBack> {
    match env.get("GIT_CONFIG_NOSYSTEM").map(|value| value.to_ascii_lowercase()).as_deref() {
        None | Some("" | "0" | "false" | "no" | "off") => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some(_) => Err(HandBack),
    }
}

/// The places a git's system-wide configuration is kept: /etc, beside the
/// git on PATH (`<prefix>/etc`, as Homebrew and Nix build it), and Apple's.
/// A git built to look elsewhere is not foreseen.
fn system_configs() -> Vec<String> {
    let mut out = vec!["/etc/gitconfig".to_string(), "/usr/local/etc/gitconfig".to_string(), "/opt/homebrew/etc/gitconfig".to_string()];
    for apple in ["/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig", "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig"] {
        out.push(apple.to_string());
    }
    if let Some(path) = std::env::var_os("PATH").and_then(|path| path.into_string().ok()) {
        if let Some(git) = path.split(':').filter(|dir| !dir.is_empty()).map(|dir| join(dir, "git")).find(|git| fs::metadata(git).is_ok_and(|meta| meta.is_file())) {
            let mut bins = vec![dirname(&git).to_string()];
            if let Some(real) = fs::canonicalize(&git).ok().and_then(|real| real.into_os_string().into_string().ok()) {
                bins.push(dirname(&real).to_string());
            }
            for bin in bins {
                out.push(resolve(&bin, "../etc/gitconfig"));
                out.push(resolve(&bin, "../share/git-core/gitconfig"));
            }
        }
    }
    out.dedup();
    out
}

/// The last `core.hooksPath` a configuration file sets, where the file is
/// plain enough to be sure of it.
fn hooks_path_in(text: &str) -> Result<Option<String>, HandBack> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let lower = text.to_ascii_lowercase();
    if lower.contains("include") {
        return Err(HandBack);
    }
    if !lower.contains("hookspath") {
        return Ok(None);
    }
    let header = regex(r#"^\[([A-Za-z0-9.-]+)([ \t]+"[^"\\]*")?\][ \t]*(?:[#;].*)?$"#, "");
    let assignment = regex(r#"^([A-Za-z][A-Za-z0-9-]*)[ \t]*=[ \t]*([^"\\#;]*)$"#, "");
    let mut in_core = false;
    let mut found = None;
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.ends_with('\\') {
            return Err(HandBack);
        }
        let line = line.trim_start_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mentioned = line.to_ascii_lowercase().contains("hookspath");
        if line.starts_with('[') {
            let Some(m) = header.find(line) else { return Err(HandBack) };
            if mentioned {
                return Err(HandBack);
            }
            let name = &line[m.group(1).expect("the name always takes part")];
            in_core = name.eq_ignore_ascii_case("core") && m.group(2).is_none();
            continue;
        }
        if !mentioned {
            continue;
        }
        let Some(m) = assignment.find(line) else { return Err(HandBack) };
        if !in_core || !line[m.group(1).expect("the key always takes part")].eq_ignore_ascii_case("hookspath") {
            continue;
        }
        let value = line[m.group(2).expect("the value always takes part")].trim_end_matches([' ', '\t']);
        if value.is_empty() {
            return Err(HandBack);
        }
        found = Some(value.to_string());
    }
    Ok(found)
}

/// What the file system will let this process do, asked without changing
/// anything.
#[cfg(unix)]
pub mod can {
    use std::ffi::CString;
    use std::fs;
    use std::io::ErrorKind;
    use std::os::unix::fs::MetadataExt;

    use crate::path::dirname;

    fn euid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// May a file be created in `dir` (it is a directory this process can
    /// write to and enter)?
    pub fn create_in(dir: &str) -> bool {
        let Ok(path) = CString::new(dir) else { return false };
        // SAFETY: `path` is a valid C string for the duration of the call.
        fs::metadata(dir).is_ok_and(|meta| meta.is_dir()) && unsafe { libc::access(path.as_ptr(), libc::W_OK | libc::X_OK) } == 0
    }

    /// May a file be renamed over `target` in `dir`? In a sticky directory
    /// only the owner of the file or of the directory may.
    pub fn replace(dir: &str, target: &str) -> bool {
        if !create_in(dir) {
            return false;
        }
        let me = euid();
        if me == 0 {
            return true;
        }
        let Ok(dir_meta) = fs::metadata(dir) else { return false };
        if dir_meta.mode() & 0o1000 == 0 || dir_meta.uid() == me {
            return true;
        }
        fs::symlink_metadata(target).map_or(true, |meta| meta.uid() == me)
    }

    /// Can this process create files in a directory it makes now (with the
    /// umask as it is)?
    pub fn fill_new_dir() -> bool {
        // SAFETY: umask only swaps the process's mask; it is put back at once.
        let mask = unsafe {
            let mask = libc::umask(0o022);
            libc::umask(mask);
            mask
        } as u32;
        euid() == 0 || (0o777 & !mask) & 0o300 == 0o300
    }

    /// What `mkdirSync(dir, { recursive: true })` would do: `Ok(false)` the
    /// directory is there, `Ok(true)` it would be made (and could be filled),
    /// `Err` it would throw.
    pub fn make_dir(dir: &str) -> Result<bool, ()> {
        match fs::metadata(dir) {
            Ok(meta) if meta.is_dir() => Ok(false),
            Err(err) if err.kind() == ErrorKind::NotFound && fs::symlink_metadata(dir).is_err() => {
                let parent = dirname(dir);
                if parent == dir {
                    return Err(());
                }
                let made = make_dir(parent)?;
                if (made && fill_new_dir()) || (!made && create_in(parent)) {
                    Ok(true)
                } else {
                    Err(())
                }
            }
            // A file, a link to nowhere, a path through a file, no access.
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::hooks_path_in;

    #[test]
    fn hooks_path_is_read_only_from_plain_files() {
        assert_eq!(hooks_path_in("[core]\n\tbare = false\n"), Ok(None));
        assert_eq!(hooks_path_in("[core]\n\thooksPath = .githooks\n"), Ok(Some(".githooks".into())));
        assert_eq!(hooks_path_in("[CORE]\nHOOKSPATH=a\n[core]\n  hookspath = ~/my hooks  \n"), Ok(Some("~/my hooks".into())));
        assert_eq!(hooks_path_in("[core \"x\"]\n\thooksPath = a\n"), Ok(None));
        assert_eq!(hooks_path_in("[alias]\n\thooksPath = a\n[alias]\n\tx = echo hookspath\n"), Ok(None));
        for odd in [
            "[core]\n\thooksPath = \"a b\"\n",
            "[core]\n\thooksPath = a # note\n",
            "[core]\n\thooksPath = a\\\nb\n",
            "[core] hooksPath = a\n",
            "[include]\n\tpath = other\n",
            "[includeIf \"gitdir:~/\"]\n\tpath = x\n[core]\n\thooksPath = a\n",
            "[core]\n\thooksPath\n",
            "[core]\n\thooksPath =\n",
            "[core\n\thooksPath = a\n",
            "[alias]\n\tx = \"hookspath\"\n",
        ] {
            assert!(hooks_path_in(odd).is_err(), "{odd:?}");
        }
    }
}
