//! `process.env` as the TypeScript sees it.
//!
//! The published `dede` starts with `#!/usr/bin/env bun`, and bun, before the
//! program's first line, loads `.env.development.local`, `.env.local`,
//! `.env.development` and `.env` of the current directory into the
//! environment (other names under NODE_ENV=production or test; variables
//! already set win, and among the files that order wins). Those are the very
//! files dede is about, so this is the common case, and it shows: a
//! `DOTENV_PRIVATE_KEY*` or `DOTENV_KEYS_FILE` in one of them is honoured,
//! and every variable in them is in the environment of each `git` dede
//! starts. (The project's own tests run with `--no-env-file` and do not see
//! it.)
//!
//! bun's reader has `$VAR` expansion, escapes and values over several lines.
//! Only the part of its syntax where a value is literally what stands in the
//! file is taken here (see `read_plain_dotenv`). A file that uses anything
//! else makes the whole invocation go back to the JavaScript, before anything
//! has been printed or changed.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::js;

/// "Not mine": the invocation has to be handed to the JavaScript. Only ever
/// acted on before the first output and the first change on disk.
#[derive(Debug, PartialEq)]
pub struct HandBack;

pub struct Env {
    /// Variables bun adds from `.env` files, on top of the real environment.
    added: Vec<(String, String)>,
}

/// The files bun loads from the current directory, strongest first.
fn dotenv_files(node_env: Option<&str>) -> &'static [&'static str] {
    match node_env {
        Some("production") => &[".env.production.local", ".env.local", ".env.production", ".env"],
        // No `.env.local` under test.
        Some("test") => &[".env.test.local", ".env.test", ".env"],
        _ => &[".env.development.local", ".env.local", ".env.development", ".env"],
    }
}

impl Env {
    /// The environment as the TypeScript sees it when it starts.
    pub fn startup() -> Result<Env, HandBack> {
        // These change what bun itself does (extra command-line options, or
        // an environment name that overrides NODE_ENV). Rare; not imitated.
        for name in ["BUN_ENV", "BUN_OPTIONS", "NODE_OPTIONS"] {
            if std::env::var_os(name).is_some() {
                return Err(HandBack);
            }
        }
        let node_env = match std::env::var_os("NODE_ENV") {
            Some(value) => Some(value.into_string().map_err(|_| HandBack)?),
            None => None,
        };
        // What dede reads from the environment has to be text.
        for (name, value) in std::env::vars_os() {
            let Some(name) = name.to_str() else { continue };
            if name.to_ascii_uppercase().starts_with("DOTENV_") && value.to_str().is_none() {
                return Err(HandBack);
            }
        }
        // Every file below is looked up in the current directory.
        std::env::current_dir().map_err(|_| HandBack)?;
        // bun reads bunfig.toml from the directory and from the user's
        // configuration; it can preload scripts and switch `.env` loading off.
        let home_name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let home = std::env::var_os(home_name).ok_or(HandBack)?;
        let mut bunfigs = vec![Path::new("bunfig.toml").to_path_buf(), Path::new(&home).join(".bunfig.toml")];
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            bunfigs.push(Path::new(&xdg).join(".bunfig.toml"));
        }
        for file in bunfigs {
            match fs::symlink_metadata(&file) {
                Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
                _ => return Err(HandBack),
            }
        }

        let mut env = Env { added: Vec::new() };
        for file in dotenv_files(node_env.as_deref()) {
            for (key, value) in read_plain_dotenv(file)? {
                if std::env::var_os(&key).is_none() && env.added.iter().all(|(k, _)| !same_name(k, &key)) {
                    env.added.push((key, value));
                }
            }
        }
        Ok(env)
    }

    /// `process.env[key]`
    pub fn get(&self, key: &str) -> Option<String> {
        if let Some((_, value)) = self.added.iter().find(|(k, _)| same_name(k, key)) {
            return Some(value.clone());
        }
        std::env::var_os(key).map(|value| value.to_string_lossy().into_owned())
    }

    /// The variables whose names start with `prefix`, for code that walks
    /// `process.env`.
    pub fn starting_with(&self, prefix: &str) -> Vec<(String, String)> {
        let starts = |name: &str| if cfg!(windows) { name.to_ascii_uppercase().starts_with(prefix) } else { name.starts_with(prefix) };
        let mut out: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.to_string_lossy().into_owned())))
            .filter(|(name, _)| starts(name))
            .collect();
        out.extend(self.added.iter().filter(|(name, _)| starts(name)).cloned());
        out
    }

    /// Gives a child process the variables added on top of the real environment.
    pub fn apply(&self, command: &mut std::process::Command) {
        for (key, value) in &self.added {
            command.env(key, value);
        }
    }
}

/// Environment variable names are case-insensitive on Windows.
fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Variables that would change how bun itself or the lookup of `git` behaves
/// if a `.env` file set them. NODE_ENV is not one of them: bun has chosen its
/// files by then, and dede does not read it.
fn changes_the_runtime(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    matches!(key.as_str(), "HOME" | "USERPROFILE" | "PATH" | "PATHEXT" | "XDG_CONFIG_HOME" | "TMPDIR" | "TEMP" | "TMP")
        || key.starts_with("BUN_")
        || (key.starts_with("NODE_") && key != "NODE_ENV")
}

/// Reads one of the files bun loads, if it is written in the subset of bun's
/// syntax where a value is simply the text that stands there:
///
/// - blank lines, and lines starting with `#`;
/// - `KEY=value`: KEY made of letters, digits and `_`, no space before `=`.
///   The value runs to the end of the line or to the first `#`, without the
///   spaces and tabs around it;
/// - `KEY="value"` and `KEY='value'`: the text between the quotes, kept as it
///   is (spaces, `#` and the other kinds of quote included). After the
///   closing quote only spaces and a `#` comment may follow.
///
/// A value must hold no `$`, no control character, and no quote character
/// that could end it or start another (none at all when it is not quoted);
/// a quoted one no backslash either. Those are where bun starts to interpret
/// (expansion, escapes, values over several lines). Lines end in LF or CRLF.
/// Anything else — `export`, indentation, a key with `.` or `-`, a line
/// without `=`, a BOM, the same key twice in a file — is `HandBack`.
///
/// Every rule here was read off bun 1.4.0 and is held by the parity cases
/// `bun env: …` (rs/parity.gen.mjs).
fn read_plain_dotenv(path: &str) -> Result<Vec<(String, String)>, HandBack> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(HandBack),
    };
    if !meta.is_file() {
        return Err(HandBack);
    }
    let bytes = fs::read(path).map_err(|_| HandBack)?;
    parse_plain_dotenv(std::str::from_utf8(&bytes).map_err(|_| HandBack)?)
}

const BLANKS: [char; 2] = [' ', '\t'];

/// True for text bun takes literally: no `$`, no control characters, no
/// exotic white space, and none of the quote characters in `quotes`.
fn literal(text: &str, quotes: &[char]) -> bool {
    text.chars().all(|c| !c.is_control() && c != '$' && !quotes.contains(&c) && (c == ' ' || !js::is_space(c)))
}

const ANY_QUOTE: [char; 3] = ['"', '\'', '`'];

/// The value bun gives to what follows `=` on a line.
fn plain_value(raw: &str) -> Result<&str, HandBack> {
    let raw = raw.trim_start_matches(BLANKS);
    let (value, rest, value_is_literal) = match raw.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let (inner, rest) = raw[1..].split_once(quote).ok_or(HandBack)?;
            (inner, rest.trim_start_matches(BLANKS), !inner.contains('\\') && literal(inner, &[quote]))
        }
        _ => {
            let (value, rest) = match raw.find('#') {
                Some(at) => (raw[..at].trim_end_matches(BLANKS), &raw[at..]),
                None => (raw.trim_end_matches(BLANKS), ""),
            };
            (value, rest, literal(value, &ANY_QUOTE))
        }
    };
    // `rest` is empty or a comment; a comment is ignored as long as it holds
    // nothing bun might read as the start of something else.
    let rest_is_comment = rest.is_empty() || (rest.starts_with('#') && literal(rest, &ANY_QUOTE) && !rest.contains('\\'));
    if value_is_literal && rest_is_comment {
        Ok(value)
    } else {
        Err(HandBack)
    }
}

fn parse_plain_dotenv(text: &str) -> Result<Vec<(String, String)>, HandBack> {
    let mut vars: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains('\r') {
            return Err(HandBack);
        }
        if line.trim_matches(BLANKS).is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, raw) = line.split_once('=').ok_or(HandBack)?;
        let key_is_plain = key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !key_is_plain || changes_the_runtime(key) || vars.iter().any(|(k, _)| same_name(k, key)) {
            return Err(HandBack);
        }
        vars.push((key.to_string(), plain_value(raw)?.to_string()));
    }
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Result<Vec<(String, String)>, HandBack> {
        parse_plain_dotenv(text)
    }

    fn pairs(list: &[(&str, &str)]) -> Result<Vec<(String, String)>, HandBack> {
        Ok(list.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    /// Each line and the value bun 1.4.0 gives it (recorded by running bun in
    /// a directory holding the file and printing process.env).
    #[test]
    fn plain_dotenv_lines_are_read() {
        assert_eq!(parsed(""), pairs(&[]));
        assert_eq!(parsed("A=1\nB=two words\n"), pairs(&[("A", "1"), ("B", "two words")]));
        assert_eq!(parsed("# it's a \"comment\" with $x\r\n\r\nA=1\r\nB= \t padded \t \r\nC="), pairs(&[("A", "1"), ("B", "padded"), ("C", "")]));
        assert_eq!(
            parsed("URL=https://user:pa.ss@host.example.com:8080/a/b.git?x=1&y=2\nWIN=C:\\Users\\me\nU=héllo→世界\nNODE_ENV=production"),
            pairs(&[("URL", "https://user:pa.ss@host.example.com:8080/a/b.git?x=1&y=2"), ("WIN", "C:\\Users\\me"), ("U", "héllo→世界"), ("NODE_ENV", "production")])
        );
        for (line, value) in [
            ("K=\"a b\"", "a b"),
            ("K=\" a \"", " a "),
            ("K=\"a\"   ", "a"),
            ("K=\"a\" # c", "a"),
            ("K='a b'", "a b"),
            ("K=''", ""),
            ("K=\"\"", ""),
            ("K=\"a#b\"", "a#b"),
            ("K='a # b'", "a # b"),
            ("K=\"a=b\"", "a=b"),
            ("K=\t\"a\"", "a"),
            ("K='a'#c", "a"),
            ("K=\"é→\"", "é→"),
            ("K='{\"a\":1}'", "{\"a\":1}"),
            ("K=\"it's\"", "it's"),
            ("K='a`b'", "a`b"),
            ("K=\"a`b\"", "a`b"),
            ("K=a # c", "a"),
            ("K=a#c", "a"),
            ("K= # c", ""),
            ("K=a b # c d", "a b"),
            ("K=a=b # c=d", "a=b"),
        ] {
            assert_eq!(parsed(line), pairs(&[("K", value)]), "{line:?}");
            assert_eq!(parsed(&format!("{line}\r\nL=1\r\n")), pairs(&[("K", value), ("L", "1")]), "{line:?} with CRLF");
        }
    }

    #[test]
    fn anything_bun_would_interpret_goes_back() {
        for text in [
            "A=$HOME/x",
            "A=cost$",
            "A=\"$B\"",
            "A='a$b'",
            "A=\"a\\nb\"",
            "A='a\\nb'",
            "A=\"unterminated",
            "A=\"two\nlines\"",
            "A=`backticks`",
            "A=\"a\"b",
            "A=it's",
            "A='it''s'",
            "A=\"a\tb\"",
            "A=1 # it's",
            "A=1 # $x",
            "A=a\tb",
            "A=a\u{a0}b",
            "export A=1",
            " A=1",
            "A =1",
            "A",
            "A.B=1",
            "1A=1",
            "A=1\nA=2",
            "A=1\rB=2",
            "\u{feff}A=1",
            "BUN_ENV=test",
            "PATH=/x",
            "HOME=/x",
            "NODE_OPTIONS=--x",
        ] {
            assert_eq!(parsed(text), Err(HandBack), "{text:?}");
        }
    }
}
