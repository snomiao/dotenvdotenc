//! dede.ts, function by function and in its order: names and keys, the file
//! format, git and the sync record, the key-level comparison, enc / dec /
//! status / get / diff, the guard, keys. `health` and `setup` have their own
//! files.
//!
//! Three ways a step can stop, as in the TypeScript:
//! - `Die`: a `DedeError`, a message and an exit code;
//! - `Thrown`: any other JavaScript error, of which only the name is ever
//!   shown (`…: TypeError (invalid key or file?)`), and which outside the
//!   per-file loop ends the TypeScript in a stack trace;
//! - `HandBack`: a situation this port does not imitate.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac};
use regress::Regex;
use sha2::{Digest, Sha256};

use crate::env::{Env, HandBack};
use crate::js::{self, Json, JsonError, Object};
use crate::out::Out;
use crate::path::{basename, dirname, join, relative, resolve};
use crate::primitives::{self, regex, CryptoError, Replacement, Values, PREFIX};

pub const USAGE: &str = "dede — sync gitignored .env* files with committed dotenvx-encrypted .env*.enc files

  dede enc [--force] [-y] [file|glob…] plaintext → .enc (default: every .env* here); then asks
                                    to commit the written .enc files (-y: commit without asking)
  dede dec [--force] [file|glob…]   .enc → plaintext   (default: every .env*.enc here)
  dede status [--quiet] [file|glob…] report sync state, exit 1 unless all in sync
  dede diff [file|glob…]            which keys differ between plaintext and .enc (names only)
  dede get NAME [file|glob…]        print one value from the .enc files (raw, never expanded);
                                    for piping: KEY=$(dede get KEY) cmd. It prints a secret, so pipe it
  dede guard [--all]                pre-commit: block staged plaintext env files, keys, unencrypted values
  dede setup                        add .gitignore rules and the pre-commit hook
  dede keys                         which key each .enc here needs, and whether it is held
  dede health [--all] [file|glob…]  rotation check against the rules in .dede.yaml: overdue (exit 1)
                                    and due-soon values, aged by git blame of their .enc line
  dede keys link <path>             make ./.env.keys a symlink to another checkout's .env.keys

  -fk, --env-keys-file <path>       use this keys file instead of ./.env.keys (also DOTENV_KEYS_FILE)
  --key <NAME>                      encrypt a new .enc with the existing DOTENV_PRIVATE_KEY_<NAME>
                                    (e.g. back up a keys file: dede enc .env.keys.myproj --key ME)

Private keys: DOTENV_PRIVATE_KEY_<SUFFIX> in the environment, else ./.env.keys (dotenvx convention),
else the key tree: any .env.keys.<name>.enc a held key opens adds the keys inside it, recursively.";

pub const TMP: &str = ".env.dede-tmp-";
const SKIP: [&str; 6] = [".env.keys", ".env.vault", ".env.me", ".env.example", ".env.sample", ".env.template"];
const BANNER: &str = "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/
#/            public-key encryption for .env files          /
#/       [how it works](https://dotenvx.com/encryption)     /
#/----------------------------------------------------------/";
const KEYS_BANNER: &str = "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/
#/ private decryption keys. DO NOT commit to source control /
#/     [how it works](https://dotenvx.com/encryption)       /
#/----------------------------------------------------------/";
const UNMANAGED_HINT: &str = "unmanaged plaintext env file (not committed, no .enc, not *.local): `dede enc` it and commit the .enc, or rename it to *.local";

/// Output of a `git` beyond this is cut off by bun's `spawnSync` (1 MiB, and
/// where exactly depends on how the pipe delivered it). Not imitated.
const GIT_OUTPUT_LIMIT: usize = 1_000_000;

/// A three-way merge works on both files at once; above this many UTF-16
/// code units together, what it builds could come near bun's limits (four
/// times this, the most `upsert` escapes it to, is still below
/// `primitives::PATTERN_LIMIT`), so such a pair is handed back.
const MERGE_TEXT_LIMIT: usize = 120_000;

#[derive(Debug)]
pub enum Stop {
    Die(String, i32),
    Thrown(&'static str),
    HandBack,
}

impl From<HandBack> for Stop {
    fn from(_: HandBack) -> Self {
        Stop::HandBack
    }
}

impl From<primitives::Fail> for Stop {
    fn from(fail: primitives::Fail) -> Self {
        match fail {
            primitives::Fail::Thrown(name) => Stop::Thrown(name),
            primitives::Fail::BeyondBun => Stop::HandBack,
        }
    }
}

impl From<CryptoError> for Stop {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::Thrown => Stop::Thrown("Error"),
            CryptoError::NotImitated => Stop::HandBack,
        }
    }
}

pub type R<T> = Result<T, Stop>;

/// `die(message, code)`
pub fn die<T>(message: String, code: i32) -> R<T> {
    Err(Stop::Die(message, code))
}

/// A file system call that throws in JavaScript.
fn thrown<T>(result: std::io::Result<T>) -> R<T> {
    result.map_err(|_| Stop::Thrown("Error"))
}

macro_rules! re {
    ($pattern:expr) => {
        re!($pattern, "")
    };
    ($pattern:expr, $flags:expr) => {{
        static CELL: OnceLock<Regex> = OnceLock::new();
        CELL.get_or_init(|| regex($pattern, $flags))
    }};
}

#[derive(Clone, Debug)]
pub struct Pair {
    pub plain: String, // absolute
    pub enc: String,   // absolute
    pub name: String,  // plaintext basename, e.g. .env.local
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Enc,
    Dec,
    Any,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Enc => "enc",
            Mode::Dec => "dec",
            Mode::Any => "any",
        }
    }
}

/// Key tree: see `tree_for`.
pub struct Tree {
    /// public key → private key
    pub ring: Object<String>,
    /// public key → where it was found, for `dede keys`
    pub from: Object<String>,
    /// DOTENV_PRIVATE_KEY_* name → private key, from the tree's files
    pub by_name: Object<String>,
}

/// Last-synced state of one pair, as far as this port takes it: every field
/// text, or absent.
#[derive(Clone)]
pub struct SyncState {
    plain: Option<String>,
    enc: Option<String>,
    salt: Option<String>,
    keys: Option<Object<String>>,
    notes: Option<String>,
}

#[derive(Default)]
pub struct View {
    p: Option<String>,    // plaintext file text
    e: Option<String>,    // .enc file text
    c: Option<String>,    // plaintext normalized through the dotenvx writer
    d: Option<String>,    // .enc decrypted into the same normalized form
    public: Option<String>,
    private: Option<String>,
    old: Option<(Values, Values)>, // (plain, cipher)
}

#[derive(PartialEq)]
enum Drift {
    EncChanged,
    PlainChanged,
    Both,
    Unknown,
    Neither,
}

struct Merge {
    text: Option<String>,
    took_local: Vec<String>,
    took_enc: Vec<String>,
    conflicts: Vec<String>,
}

pub struct Dede {
    pub env: Env,
    pub cwd: String,
    pub out: Out,
    pub keys_override: Option<String>,
    pub key_choice: Option<String>,
    pub written: Vec<String>,
    pub quiet: bool,
    trees: HashMap<String, Rc<Tree>>,
}

// ───────────────────────── names ─────────────────────────

/// dotenvx naming: .env → "", .env.local → "_LOCAL", .env.development.local → "_DEVELOPMENT_LOCAL"
pub fn suffix_of(name: &str) -> String {
    if name == ".env" {
        return String::new();
    }
    let rest: String = name.chars().skip(5).flat_map(char::to_uppercase).map(|c| if c.is_ascii_uppercase() || c.is_ascii_digit() { c } else { '_' }).collect();
    format!("_{rest}")
}

/// `/^\.env(\.[A-Za-z0-9_-]+)*$/`
pub fn matches_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".env") else { return false };
    rest.is_empty() || (rest.starts_with('.') && rest[1..].split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')))
}

pub fn is_env_name(name: &str) -> bool {
    matches_name(name) && !name.ends_with(".enc") && !SKIP.contains(&name) && !name.starts_with(TMP)
}

pub fn is_skipped(name: &str) -> bool {
    SKIP.contains(&name)
}

/// Keys files (.env.keys, .env.keys.<name>) may hold private keys.
fn is_keys_name(name: &str) -> bool {
    name == ".env.keys" || name.starts_with(".env.keys.")
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

// ───────────────────────── files ─────────────────────────

/// `existsSync(path)`
pub fn exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub fn is_symlink(path: &str) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// `readFileSync(path, "utf8")`
pub fn read_file(path: &str) -> R<String> {
    thrown(fs::read(path)).map(|bytes| js::utf8(&bytes))
}

/// `realpathSync(path)`
pub fn realpath(path: &str) -> R<String> {
    thrown(fs::canonicalize(path))?.into_os_string().into_string().map_err(|_| Stop::HandBack)
}

/// `readdirSync(path)`. A name that is not UTF-8 is none dede looks for.
pub fn readdir(path: &str) -> R<Vec<String>> {
    let mut names = Vec::new();
    for entry in thrown(fs::read_dir(path))? {
        names.push(thrown(entry)?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

/// The permission bits of a file that is not followed if it is a link.
#[cfg(unix)]
pub fn lstat_mode(path: &str) -> std::io::Result<(bool, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::symlink_metadata(path)?;
    Ok((meta.is_file(), meta.permissions().mode()))
}

#[cfg(not(unix))]
pub fn lstat_mode(path: &str) -> std::io::Result<(bool, u32)> {
    let meta = fs::symlink_metadata(path)?;
    Ok((meta.is_file(), 0o600))
}

#[cfg(unix)]
pub fn chmod(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub fn chmod(_path: &str, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("the system's random number generator");
    js::hex(&buffer)
}

pub fn sha(text: &str) -> String {
    js::hex(&Sha256::digest(js::lf(text).as_bytes()))
}

fn hmac(salt: &str, text: &str) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(salt.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(text.as_bytes());
    js::hex(&mac.finalize().into_bytes())[..24].to_string()
}

fn comments_of(text: &str) -> String {
    text.split('\n').filter(|line| js::trim_start(line).starts_with('#')).collect::<Vec<_>>().join("\n")
}

/// `xs.length > 6 ? first six + " +N" : all`
pub fn list(xs: &[String]) -> String {
    if xs.len() > 6 {
        format!("{} +{}", xs[..6].join(", "), xs.len() - 6)
    } else {
        xs.join(", ")
    }
}

fn keys_note(keys: &[String]) -> String {
    if keys.is_empty() {
        String::new()
    } else {
        format!(" ({})", list(keys))
    }
}

/// The names of both, each once, sorted as JavaScript sorts strings.
fn sorted_union(a: &Values, b: &Values) -> Vec<String> {
    let mut keys = a.keys();
    for key in b.keys() {
        if !a.has(&key) {
            keys.push(key);
        }
    }
    js::sort(&mut keys);
    keys
}

fn merged_note(merge: &Merge) -> String {
    let enc = keys_note(&merge.took_enc);
    let local = keys_note(&merge.took_local);
    format!("merged: from .enc{}, kept your edits{}", if enc.is_empty() { " (nothing)" } else { &enc }, if local.is_empty() { " (none)" } else { &local })
}

fn drift(state: &Option<SyncState>, p: &str, e: &str) -> Drift {
    let Some(state) = state else { return Drift::Unknown };
    let plain_changed = state.plain.as_deref() != Some(sha(p).as_str());
    let enc_changed = state.enc.as_deref() != Some(sha(e).as_str());
    match (plain_changed, enc_changed) {
        (true, true) => Drift::Both,
        (true, false) => Drift::PlainChanged,
        (false, true) => Drift::EncChanged,
        (false, false) => Drift::Neither,
    }
}

/// Keys whose value changed since the last sync (added, removed or edited).
fn changed_since(state: &Option<SyncState>, vals: &Values) -> Vec<String> {
    let Some(state) = state else { return Vec::new() };
    let (Some(keys), Some(salt)) = (&state.keys, state.salt.as_deref().filter(|salt| !salt.is_empty())) else { return Vec::new() };
    let mut names = keys.keys();
    for key in vals.keys() {
        if !keys.has(&key) {
            names.push(key);
        }
    }
    let mut changed: Vec<String> = names.into_iter().filter(|k| vals.get(k).map(|v| hmac(salt, &js::json_strings(v))).as_ref() != keys.get(k)).collect();
    js::sort(&mut changed);
    changed
}

/// The entry of one pair in the sync record, if it is of the shape dede
/// writes. Anything else in its place is not imitated.
fn state_entry(all: &Object<Json>, key: &str) -> R<Option<SyncState>> {
    let Some(entry) = all.get(key) else { return Ok(None) };
    let Json::Object(entry) = entry else { return Err(Stop::HandBack) };
    let text = |name: &str| match entry.get(name) {
        None => Ok(None),
        Some(Json::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Stop::HandBack),
    };
    let keys = match entry.get("keys") {
        None => None,
        Some(Json::Object(keys)) => {
            let mut out = Object::new();
            for (name, value) in keys.entries() {
                let Json::String(value) = value else { return Err(Stop::HandBack) };
                out.set(name, value.clone());
            }
            Some(out)
        }
        Some(_) => return Err(Stop::HandBack),
    };
    Ok(Some(SyncState { plain: text("plain")?, enc: text("enc")?, salt: text("salt")?, keys, notes: text("notes")? }))
}

impl Dede {
    pub fn new(env: Env, cwd: String, out: Out) -> Dede {
        Dede { env, cwd, out, keys_override: None, key_choice: None, written: Vec::new(), quiet: false, trees: HashMap::new() }
    }

    /// `console.error(message)`
    pub fn log(&mut self, message: &str) {
        self.out.error(message);
    }

    /// Display paths as git does, relative to the current directory.
    pub fn rel(&self, path: &str) -> String {
        let relative = relative(&self.cwd, &self.cwd, path);
        if relative.is_empty() {
            ".".to_string()
        } else {
            relative
        }
    }

    pub fn resolve(&self, path: &str) -> String {
        resolve(&self.cwd, path)
    }

    // ───────────────────────── git ─────────────────────────

    /// `spawnSync("git", args, { cwd, encoding: "utf8" })`: did it exit 0, and
    /// what it printed.
    pub fn git(&self, args: &[&str], cwd: &str) -> R<(bool, String)> {
        let mut command = Command::new("git");
        command.args(args).current_dir(cwd).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        self.env.apply(&mut command);
        match command.output() {
            Ok(output) => {
                if output.stdout.len() > GIT_OUTPUT_LIMIT || output.stderr.len() > GIT_OUTPUT_LIMIT {
                    return Err(Stop::HandBack);
                }
                Ok((output.status.code() == Some(0), js::utf8(&output.stdout)))
            }
            // No git, or no such directory: no exit status and no output.
            Err(_) => Ok((false, String::new())),
        }
    }

    pub fn git_dir(&self, cwd: &str) -> R<String> {
        let top = self.git(&["rev-parse", "--show-toplevel"], cwd)?.1;
        let top = js::trim(&top);
        if top.is_empty() {
            return die("not inside a git repository".into(), 1);
        }
        Ok(top.to_string())
    }

    pub fn is_ignored(&self, path: &str) -> R<bool> {
        Ok(self.git(&["check-ignore", "-q", "--", basename(path)], dirname(path))?.0)
    }

    fn is_tracked(&self, path: &str) -> R<bool> {
        Ok(self.git(&["ls-files", "--error-unmatch", "--", basename(path)], dirname(path))?.0)
    }

    // ───────────────────────── keys ─────────────────────────

    /// Keys come from the environment, then one keys file: ./.env.keys next to
    /// the env file, or an explicit -fk / DOTENV_KEYS_FILE.
    fn keys_file_for(&self, dir: &str) -> String {
        match &self.keys_override {
            Some(file) => file.clone(),
            None => join(dir, ".env.keys"),
        }
    }

    /// Key tree: a committed keys file `.env.keys.<name>.enc` (next to the env
    /// file, or next to the keys file a link points at) is opened in memory
    /// once a held key fits it, and its DOTENV_PRIVATE_KEY_* join the ring,
    /// repeatedly until nothing new opens. Nothing is written.
    pub fn tree_for(&mut self, dir: &str) -> R<Rc<Tree>> {
        let file = self.keys_file_for(dir);
        let cache_key = format!("{dir}\0{file}");
        if let Some(tree) = self.trees.get(&cache_key) {
            return Ok(tree.clone());
        }
        let variables = self.env.starting_with("DOTENV_P");
        let read = |path: &str| fs::read(path).ok().map(|bytes| js::utf8(&bytes));
        let env_ring = primitives::keyring(&[], &variables, read)?;
        let file_ring = if exists(&file) { primitives::keyring(&[&file], &[], read)? } else { Object::new() };
        let mut ring = primitives::keyring(&[&file], &variables, read)?;
        let link = if is_symlink(&file) { format!(" → {}", self.rel(&realpath(&file)?)) } else { String::new() };
        let held = |ring: &Object<String>, public: &str| ring.get(public).is_some_and(|private| !private.is_empty());
        let mut from: Object<String> = Object::new();
        for public in ring.keys() {
            let source = if held(&env_ring, &public) {
                "environment".to_string()
            } else if held(&file_ring, &public) {
                format!("{}{link}", self.rel(&file))
            } else {
                "keys".to_string()
            };
            from.set(&public, source);
        }
        let mut homes = vec![self.resolve(dir)];
        if exists(&file) {
            let home = dirname(&realpath(&file)?).to_string();
            if !homes.contains(&home) {
                homes.push(home);
            }
        }
        let mut nodes: Vec<String> = Vec::new();
        for home in &homes {
            let mut names: Vec<String> = readdir(home)?.into_iter().filter(|name| re!(r"^\.env\.keys\.[A-Za-z0-9_.-]+\.enc$").find(name).is_some()).collect();
            js::sort(&mut names);
            nodes.extend(names.iter().map(|name| join(home, name)));
        }
        let mut by_name: Object<String> = Object::new();
        let mut opened: Vec<String> = Vec::new();
        let mut grew = true;
        while grew {
            grew = false;
            for node in &nodes {
                if opened.contains(node) {
                    continue;
                }
                // try { … } catch { opened.add(node); continue; }
                let attempt = (|| -> R<Option<(Values, String)>> {
                    let text = js::lf(&read_file(node)?);
                    let (public, body, _) = self.split_enc(&text, node)?;
                    if !held(&ring, &public) {
                        return Ok(None); // maybe a later round opens it
                    }
                    let via = from.get(&public).cloned().unwrap_or_default();
                    let private = ring.get(&public).cloned().unwrap_or_default();
                    Ok(Some((self.decrypt_all(&body, &private, node)?.0, via)))
                })();
                let (plain, via) = match attempt {
                    Ok(Some(found)) => found,
                    Ok(None) => continue,
                    Err(Stop::HandBack) => return Err(Stop::HandBack),
                    Err(_) => {
                        opened.push(node.clone()); // malformed or undecryptable: not part of the tree
                        continue;
                    }
                };
                opened.push(node.clone());
                for (name, values) in plain.entries() {
                    if !name.starts_with("DOTENV_PRIVATE_KEY") {
                        continue;
                    }
                    let last = values.last().map(String::as_str).unwrap_or("");
                    for private in last.split(',').map(js::trim) {
                        if !is_hex64(private) {
                            continue;
                        }
                        if !by_name.has(name) {
                            by_name.set(name, private.to_string());
                        }
                        let public = primitives::derive(private)?;
                        if held(&ring, &public) {
                            continue;
                        }
                        ring.set(&public, private.to_string());
                        from.set(&public, format!("{} ← {via}", self.rel(node)));
                        grew = true;
                    }
                }
            }
        }
        let tree = Rc::new(Tree { ring, from, by_name });
        self.trees.insert(cache_key, tree.clone());
        Ok(tree)
    }

    /// The private key for `public`, or "" when it is not held.
    fn ring_for(&mut self, dir: &str, public: &str) -> R<String> {
        Ok(self.tree_for(dir)?.ring.get(public).cloned().unwrap_or_default())
    }

    fn private_key_for(&mut self, public: &str, pair: &Pair) -> R<String> {
        let private = self.ring_for(dirname(&pair.plain), public)?;
        if private.is_empty() {
            return die(
                format!(
                    "{}: no private key (set DOTENV_PRIVATE_KEY{}, add it to {} or to a .env.keys.<name>.enc a held key opens, or use -fk / `dede keys link`)",
                    self.rel(&pair.enc),
                    suffix_of(&pair.name),
                    self.rel(&self.keys_file_for(dirname(&pair.plain)))
                ),
                3,
            );
        }
        Ok(private)
    }

    /// A keys file inside a git work tree must be gitignored; one outside any repo is the user's business.
    fn assert_keys_file_safe(&mut self, path: &str) -> R<()> {
        let resolved = self.resolve(path);
        let in_repo = js::trim(&self.git(&["rev-parse", "--is-inside-work-tree"], dirname(&resolved))?.1) == "true";
        if in_repo && !self.is_ignored(path)? {
            return die(format!("{} is not gitignored; run `dede setup` first", self.rel(path)), 1);
        }
        Ok(())
    }

    fn key_by_name(&mut self, key_name: &str, dir: &str) -> R<String> {
        let keys_path = self.keys_file_for(dir);
        let from_file = if exists(&keys_path) { primitives::scan(&read_file(&keys_path)?)?.get(key_name).and_then(|values| values.last().cloned()) } else { None };
        let found = match self.env.get(key_name).filter(|value| !value.is_empty()).or(from_file.filter(|value| !value.is_empty())) {
            Some(found) => found,
            None => self.tree_for(dir)?.by_name.get(key_name).cloned().unwrap_or_default(),
        };
        Ok(js::trim(found.split(',').next().unwrap_or("")).to_string())
    }

    /// Existing key for a new .enc (env, the keys file or the key tree, by
    /// dotenvx name), else a fresh one saved to the keys file. Returns
    /// (public key, private key).
    fn obtain_key(&mut self, pair: &Pair) -> R<(String, String)> {
        let dir = dirname(&pair.plain).to_string();
        let keys_path = self.keys_file_for(&dir);
        if let Some(choice) = self.key_choice.clone() {
            let chosen = self.key_by_name(&format!("DOTENV_PRIVATE_KEY_{choice}"), &dir)?;
            if chosen.is_empty() {
                return die(format!("--key {choice}: DOTENV_PRIVATE_KEY_{choice} not found in the environment, {} or its key tree", self.rel(&keys_path)), 3);
            }
            return Ok((primitives::derive(&chosen)?, chosen));
        }
        let key_name = format!("DOTENV_PRIVATE_KEY{}", suffix_of(&pair.name));
        let existing = self.key_by_name(&key_name, &dir)?;
        if !existing.is_empty() {
            return Ok((primitives::derive(&existing)?, existing));
        }
        self.assert_keys_file_safe(&keys_path)?;
        let (public, private) = primitives::new_keypair();
        let previous = if exists(&keys_path) { read_file(&keys_path)? } else { format!("{KEYS_BANNER}\n") };
        // A linked .env.keys (dede keys link) is updated at its target, keeping the link.
        let target = if is_symlink(&keys_path) { realpath(&keys_path)? } else { keys_path.clone() };
        let text = format!("{previous}{}\n# {}\n{key_name}={private}\n", if previous.ends_with('\n') { "" } else { "\n" }, pair.name);
        self.write_atomic(&target, &text, 0o600)?;
        let message = format!("new key {key_name} saved to {} — back it up (password manager); teammates need it to decrypt", self.rel(&keys_path));
        self.log(&message);
        Ok((public, private))
    }

    // ───────────────────────── file format ─────────────────────────

    /// (public key, body, number of lines before the body)
    pub fn split_enc(&self, text: &str, file: &str) -> R<(String, String, usize)> {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut i = 0;
        while i < lines.len() && lines[i].starts_with("#/") {
            i += 1;
        }
        let header = re!(r#"^DOTENV_PUBLIC_KEY[A-Z0-9_]*="?(0[23][0-9a-f]{64})"?\r?$"#);
        let line = lines.get(i).copied().unwrap_or("");
        let Some(found) = header.find(line) else {
            return die(format!("{}: missing DOTENV_PUBLIC_KEY header", self.rel(file)), 4);
        };
        let public = line[found.group(1).expect("group 1 always takes part")].to_string();
        i += 1;
        if matches!(lines.get(i), Some(&"") | Some(&"\r")) {
            i += 1;
        }
        let body = if i < lines.len() { lines[i..].join("\n") } else { String::new() };
        Ok((public, body, i))
    }

    pub fn values(&self, text: &str, file: &str) -> R<Values> {
        let parsed = primitives::scan(text)?;
        let name = basename(file);
        let keys_file = is_keys_name(name.strip_suffix(".enc").unwrap_or(name));
        for key in parsed.keys() {
            if key.starts_with("DOTENV_PUBLIC_KEY") || (!keys_file && key.starts_with("DOTENV_PRIVATE_KEY")) {
                return die(format!("{}: {key} does not belong in an env file", self.rel(file)), 4);
            }
        }
        Ok(parsed)
    }

    fn rewrite(text: &str, vals: &Values) -> R<String> {
        let mut out = text.to_string();
        for (key, values) in vals.entries() {
            out = primitives::upsert(&out, key, Replacement::Each(values))?;
        }
        // upsert drops the final newline after an empty last value (`A=\n` → `A=`); keep the file's ending.
        if text.ends_with('\n') && !out.ends_with('\n') {
            out.push('\n');
        }
        Ok(out)
    }

    /// (plain, cipher)
    fn decrypt_all(&self, body: &str, private: &str, file: &str) -> R<(Values, Values)> {
        let cipher = self.values(body, file)?;
        let mut plain = Values::new();
        for (key, values) in cipher.entries() {
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                if value.is_empty() {
                    out.push(String::new());
                    continue;
                }
                if !value.starts_with(PREFIX) {
                    return die(format!("{}: {key} is not encrypted", self.rel(file)), 4);
                }
                match primitives::decrypt(private, value) {
                    Ok(plain) => out.push(plain),
                    Err(CryptoError::Thrown) => return die(format!("{}: cannot decrypt {key} (wrong key or corrupt value)", self.rel(file)), 3),
                    Err(CryptoError::NotImitated) => return Err(Stop::HandBack),
                }
            }
            plain.set(key, out);
        }
        Ok((plain, cipher))
    }

    /// Every committed line must be blank, a comment, or an assignment whose
    /// whole value is ciphertext. `offset`: lines before `body` in the file.
    pub fn assert_sealed(&self, body: &str, file: &str, offset: usize) -> R<()> {
        let hint = "quote the whole value (\"…\"), or put a space before a real comment";
        let key_pattern = re!(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=");
        let key_of = |line: &str| key_pattern.find(line).map(|found| line[found.group(1).expect("group 1 always takes part")].to_string());
        // An assignment in a committed file: the value is ciphertext (bare or quoted) or empty, then at most a spaced comment.
        let sealed = re!(
            r#"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(?:"(?:encrypted:[A-Za-z0-9+/=]+)?"|'(?:encrypted:[A-Za-z0-9+/=]+)?'|`(?:encrypted:[A-Za-z0-9+/=]+)?`|(?:encrypted:[A-Za-z0-9+/=]+)?)(?:\s+#.*|\s*)\r?$"#
        );
        // A commented-out assignment with a real-looking value, or a URL carrying userinfo, in a comment.
        let leaky = re!(r#"^\s*#\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*["'`]?\S{16,}|:\/\/[^/\s:@]+(?::[^@\s]*)?@"#);
        let lines: Vec<&str> = body.split('\n').collect();
        let is_comment = |line: &str| js::trim(line).is_empty() || js::trim_start(line).starts_with('#');
        for (i, line) in lines.iter().enumerate() {
            if is_comment(line) && !line.starts_with("#/") && leaky.find(&utf16_units(line)).is_some() {
                return die(
                    format!(
                        "{}: line {} is a comment holding a credential-like value (commented-out assignment or URL with userinfo); comments are committed in plaintext, so delete it",
                        self.rel(file),
                        i + 1 + offset
                    ),
                    4,
                );
            }
            if !is_comment(line) && key_of(line).is_none() {
                return die(format!("{}: line {} is not an assignment or comment and would be committed as plaintext", self.rel(file), i + 1 + offset), 4);
            }
        }
        for (key, values) in self.values(body, file)?.entries() {
            if values.iter().any(|value| !value.is_empty() && !value.starts_with(PREFIX)) {
                return die(format!("{}: {key} is not encrypted; {hint}", self.rel(file)), 4);
            }
        }
        for (i, line) in lines.iter().enumerate() {
            if !is_comment(line) && sealed.find(line).is_none() {
                return die(
                    format!(
                        "{}: line {} ({}) would commit part of its value as plaintext; {hint}",
                        self.rel(file),
                        i + 1 + offset,
                        key_of(line).unwrap_or_else(|| "undefined".to_string())
                    ),
                    4,
                );
            }
        }
        Ok(())
    }

    // ───────────────────────── sync record ─────────────────────────

    fn state_key(&self, pair: &Pair) -> R<String> {
        let top = self.git_dir(dirname(&pair.plain))?;
        Ok(relative(&self.cwd, &top, &pair.plain))
    }

    fn state_file(&self, pair: &Pair) -> R<String> {
        let path = self.git(&["rev-parse", "--path-format=absolute", "--git-path", "dotenvdotenc/state.json"], dirname(&pair.plain))?.1;
        let path = js::trim(&path);
        if path.is_empty() {
            return die("not inside a git repository".into(), 1);
        }
        Ok(path.to_string())
    }

    /// `JSON.parse` of the record, or `{}` when anything about that fails.
    fn load_state(&self, pair: &Pair) -> R<Object<Json>> {
        let text = match self.state_file(pair).and_then(|file| read_file(&file)) {
            Ok(text) => text,
            Err(Stop::HandBack) => return Err(Stop::HandBack),
            Err(_) => return Ok(Object::new()),
        };
        match js::parse_json(&text) {
            Ok(Json::Object(all)) => Ok(all),
            // A record that is not an object is not something dede wrote.
            Ok(_) | Err(JsonError::NotImitated) => Err(Stop::HandBack),
            Err(JsonError::Syntax) => Ok(Object::new()),
        }
    }

    /// `plain_text` is the plaintext that corresponds to `enc_text` (in sync).
    fn save_state(&mut self, pair: &Pair, plain_text: &str, enc_text: &str) -> R<()> {
        let file = self.state_file(pair)?;
        let mut all = self.load_state(pair)?;
        let key = self.state_key(pair)?;
        let current = state_entry(&all, &key)?;
        let (plain_hash, enc_hash) = (sha(plain_text), sha(enc_text));
        if let Some(current) = &current {
            if current.plain.as_ref() == Some(&plain_hash) && current.enc.as_ref() == Some(&enc_hash) && current.keys.is_some() {
                return Ok(());
            }
        }
        let salt = random_hex(16);
        let mut keys = Object::new();
        for (name, values) in self.values(plain_text, &pair.plain)?.entries() {
            keys.set(name, Json::String(hmac(&salt, &js::json_strings(values))));
        }
        let notes = hmac(&salt, &comments_of(&js::lf(plain_text)));
        let mut ordered = Object::new();
        ordered.set("plain", Json::String(plain_hash));
        ordered.set("enc", Json::String(enc_hash));
        ordered.set("salt", Json::String(salt));
        ordered.set("keys", Json::Object(keys));
        ordered.set("notes", Json::String(notes));
        all.set(&key, Json::Object(ordered));
        thrown(fs::create_dir_all(dirname(&file)))?;
        self.write_atomic(&file, &format!("{}\n", js::stringify(&Json::Object(all), "  ")), 0o600)
    }

    fn last_sync(&self, pair: &Pair) -> R<Option<SyncState>> {
        let all = self.load_state(pair)?;
        let key = self.state_key(pair)?;
        state_entry(&all, &key)
    }

    // ───────────────────────── key-level comparison (names only, never values) ─────────────────────────

    fn describe_diff(pair: &Pair, local: &Values, enc: &Values) -> String {
        let keys = sorted_union(local, enc);
        let differ: Vec<String> = keys.iter().filter(|k| local.has(k) && enc.has(k) && local.get(k) != enc.get(k)).cloned().collect();
        let only_local: Vec<String> = keys.iter().filter(|k| !enc.has(k)).cloned().collect();
        let only_enc: Vec<String> = keys.iter().filter(|k| !local.has(k)).cloned().collect();
        let mut parts = Vec::new();
        if !differ.is_empty() {
            parts.push(format!("different: {}", list(&differ)));
        }
        if !only_local.is_empty() {
            parts.push(format!("only in {}: {}", basename(&pair.plain), list(&only_local)));
        }
        if !only_enc.is_empty() {
            parts.push(format!("only in {}: {}", basename(&pair.enc), list(&only_enc)));
        }
        if parts.is_empty() {
            "same values, different comments/formatting".to_string()
        } else {
            parts.join(" · ")
        }
    }

    /// Three-way merge per key against the last sync. Each key takes the side
    /// that changed it; the same key changed on both sides, or comments
    /// changed on both sides, is a conflict.
    fn merge3(&self, pair: &Pair, p: &str, d: &str, state: &Option<SyncState>) -> R<Merge> {
        let mut merge = Merge { text: None, took_local: Vec::new(), took_enc: Vec::new(), conflicts: Vec::new() };
        let p = js::lf(p);
        let usable = state.as_ref().and_then(|state| Some((state, state.keys.as_ref()?, state.salt.as_deref().filter(|salt| !salt.is_empty())?)));
        let Some((state, state_keys, salt)) = usable else {
            merge.conflicts.push("(no per-key sync record; sync once with this dede version)".to_string());
            return Ok(merge);
        };
        let local = self.values(&p, &pair.plain)?;
        let enc = self.values(d, &pair.enc)?;
        let hash = |values: Option<&Vec<String>>| values.map(|values| hmac(salt, &js::json_strings(values)));
        for key in sorted_union(&local, &enc) {
            let local_hash = hash(local.get(&key));
            let enc_hash = hash(enc.get(&key));
            if local_hash == enc_hash {
                continue;
            }
            let recorded = state_keys.get(&key);
            if local_hash.as_ref() == recorded {
                merge.took_enc.push(key);
            } else if enc_hash.as_ref() == recorded {
                merge.took_local.push(key);
            } else {
                merge.conflicts.push(key);
            }
        }
        let local_notes = Some(hmac(salt, &comments_of(&p))) != state.notes;
        let enc_notes = Some(hmac(salt, &comments_of(d))) != state.notes;
        if local_notes && enc_notes && comments_of(&p) != comments_of(d) {
            merge.conflicts.push("(comments)".to_string());
        }
        if !merge.conflicts.is_empty() {
            return Ok(merge);
        }
        // Keep the text (comments, order) of the side whose comments changed; apply the other side's keys.
        let (base, apply, from) = if local_notes { (p.as_str(), merge.took_enc.clone(), &enc) } else { (d, merge.took_local.clone(), &local) };
        let mut text = base.to_string();
        for key in &apply {
            match from.get(key) {
                None => text = primitives::remove(&text, key),
                Some(values) => {
                    if self.values(&text, &pair.plain)?.has(key) {
                        text = primitives::upsert(&text, key, Replacement::Each(values))?;
                    } else if values.len() == 1 {
                        let start = if text.ends_with('\n') || text.is_empty() { text.clone() } else { format!("{text}\n") };
                        text = primitives::upsert(&start, key, Replacement::One(&values[0]))?;
                    } else {
                        merge.conflicts = vec![format!("{key} (repeated assignments)")];
                        return Ok(merge);
                    }
                }
            }
        }
        let merged = self.values(&text, &pair.plain)?;
        let mut want = if local_notes { local.clone() } else { enc.clone() };
        for key in &apply {
            match from.get(key) {
                Some(values) => want.set(key, values.clone()),
                None => want.delete(key),
            }
        }
        let mut names = merged.keys();
        for key in want.keys() {
            if !merged.has(&key) {
                names.push(key);
            }
        }
        for key in names {
            if merged.get(&key) != want.get(&key) {
                merge.conflicts = vec![format!("{key} (could not merge the text)")];
                return Ok(merge);
            }
        }
        merge.text = Some(text);
        Ok(merge)
    }

    /// The text of a file; `None` when there is none; a symlink is refused.
    pub fn read(&self, path: &str) -> R<Option<String>> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => die(format!("{} is a symlink; refusing", self.rel(path)), 4),
            Ok(_) => read_file(path).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// A temp file next to the target, written, synced, given its mode and
    /// renamed over the target.
    pub fn write_atomic(&mut self, path: &str, text: &str, mode: u32) -> R<()> {
        self.trees.clear(); // a new key or keys file may change the key tree
        if exists(path) && is_symlink(path) {
            return die(format!("{} is a symlink; refusing", self.rel(path)), 4);
        }
        let tmp = join(dirname(path), &format!("{TMP}{}-{}", std::process::id(), random_hex(4)));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = thrown(options.open(&tmp))?;
        let written = file.write_all(text.as_bytes()).and_then(|_| file.sync_all());
        drop(file);
        let result = written.and_then(|_| chmod(&tmp, mode)).and_then(|_| fs::rename(&tmp, path));
        if result.is_err() && !self.out.is_live() {
            // A first write that fails is handed back (the TypeScript ends in
            // an uncaught error there): the JavaScript then leaves its own
            // temp file, so this one goes.
            let _ = fs::remove_file(&tmp);
        }
        thrown(result)
    }

    /// Plaintext secrets are owner-only; fix a group/world-readable file
    /// instead of just warning.
    fn tighten(&mut self, path: &str) {
        if cfg!(windows) {
            return;
        }
        if let Ok((true, mode)) = lstat_mode(path) {
            if mode & 0o077 != 0 && chmod(path, 0o600).is_ok() {
                let message = format!("tightened {} to 0600", self.rel(path));
                self.log(&message);
            }
        }
    }

    fn preflight(&mut self, pair: &Pair) -> R<()> {
        if !self.is_ignored(&pair.plain)? {
            return die(format!("{} is not gitignored; run `dede setup` (or add `.env*` and `!.env*.enc` to .gitignore)", self.rel(&pair.plain)), 1);
        }
        if self.is_ignored(&pair.enc)? {
            let message = format!("warning: {} is gitignored and won't be committed; add `!.env*.enc` after your .env ignore rules (or run `dede setup`)", self.rel(&pair.enc));
            self.log(&message);
        }
        Ok(())
    }

    // ───────────────────────── sync ─────────────────────────

    pub fn view(&mut self, pair: &Pair, need_key: bool) -> R<View> {
        let mut view = View { p: self.read(&pair.plain)?, e: self.read(&pair.enc)?, ..View::default() };
        if let Some(p) = &view.p {
            view.c = Some(Self::rewrite(&js::lf(p), &self.values(p, &pair.plain)?)?);
        }
        if let Some(e) = &view.e {
            let (public, body, _) = self.split_enc(&js::lf(e), &pair.enc)?;
            view.public = Some(public.clone());
            if !need_key && self.ring_for(dirname(&pair.plain), &public)?.is_empty() {
                return Ok(view);
            }
            let private = self.private_key_for(&public, pair)?;
            let old = self.decrypt_all(&body, &private, &pair.enc)?;
            view.d = Some(Self::rewrite(&body, &old.0)?);
            view.private = Some(private);
            view.old = Some(old);
        }
        Ok(view)
    }

    fn build_enc(&self, pair: &Pair, public: &str, private: &str, raw: &str, c: &str, old: Option<&(Values, Values)>) -> R<String> {
        let p = js::lf(raw);
        let vals = self.values(&p, &pair.plain)?;
        let mut ciphertexts = Values::new();
        for (key, values) in vals.entries() {
            let mut out = Vec::with_capacity(values.len());
            for (i, value) in values.iter().enumerate() {
                // An unchanged value keeps its ciphertext, so its line in the .enc does not move.
                let kept = old.and_then(|(plain, cipher)| {
                    if plain.get(key).and_then(|values| values.get(i)) != Some(value) {
                        return None;
                    }
                    // `old.cipher[k][i]`: the same file gave both, so it is there.
                    cipher.get(key).and_then(|values| values.get(i)).filter(|cipher| !cipher.is_empty())
                });
                out.push(match kept {
                    Some(cipher) => cipher.clone(),
                    None => primitives::encrypt(public, value)?,
                });
            }
            ciphertexts.set(key, out);
        }
        let body = Self::rewrite(&p, &ciphertexts)?;
        self.assert_sealed(&body, &pair.enc, 0)?;
        if Self::rewrite(&body, &self.decrypt_all(&body, private, &pair.enc)?.0)? != c {
            return die(format!("{}: formatting does not survive encryption; quote the value with \"…\"", self.rel(&pair.plain)), 4);
        }
        Ok(format!("{BANNER}\nDOTENV_PUBLIC_KEY{}=\"{public}\"\n\n{body}", suffix_of(&pair.name)))
    }

    /// Reads what `enc` (`encrypting`) or `dec` is going to read for this
    /// pair, and foresees what it will make of it, without writing anything:
    /// whatever this port does not imitate has to show here, while the
    /// invocation can still be handed back. That includes text beyond bun's
    /// regular expressions (`primitives::QUOTED_SPAN_LIMIT`) in what the run
    /// will write and then read again: the .enc with its new ciphertexts, a
    /// merged file, the keys file a new key is appended to. `appended`: how
    /// much this run may append to a keys file, at most.
    pub fn foresee(&mut self, pair: &Pair, encrypting: bool, force: bool, appended: usize) -> R<()> {
        let view = self.view(pair, true)?;
        let plain_values = match &view.p {
            Some(p) => self.values(p, &pair.plain)?,
            None => Values::new(),
        };
        let enc_values = match &view.d {
            Some(d) => self.values(d, &pair.enc)?,
            None => Values::new(),
        };
        let fits = |text_len: usize| text_len <= primitives::QUOTED_SPAN_LIMIT;
        // What a fresh ciphertext of each value takes, quoted or not, and
        // the expression `upsert` then builds from it (a `+` is escaped).
        let mut ciphertext_total = 0;
        if encrypting {
            for values in [&plain_values, &enc_values] {
                for (name, values) in values.entries() {
                    for value in values {
                        let length = primitives::ciphertext_len(value);
                        ciphertext_total += length;
                        if !fits(length + 2) || primitives::upsert_pattern_len(name, 2 * length) > primitives::PATTERN_LIMIT {
                            return Err(Stop::HandBack);
                        }
                    }
                }
            }
        }
        // Both sides changed: the merged text is made of both files.
        if let (Some(p), Some(d), false) = (&view.p, &view.d, force) {
            if view.c.as_ref() != Some(d) {
                let both = primitives::utf16_len(p) + primitives::utf16_len(d);
                if both > MERGE_TEXT_LIMIT || (encrypting && !fits(both + ciphertext_total)) {
                    return Err(Stop::HandBack);
                }
            }
        }
        if !encrypting {
            return Ok(());
        }
        // The .enc as `build_enc` writes it, with each new ciphertext as long
        // as the real one will be (base64 holds no quote and no backslash).
        if let Some(p) = &view.p {
            let p = js::lf(p);
            let mut stand_ins = Values::new();
            for (name, values) in plain_values.entries() {
                let mut out = Vec::with_capacity(values.len());
                for (i, value) in values.iter().enumerate() {
                    let kept = view.old.as_ref().and_then(|(plain, cipher)| {
                        if plain.get(name).and_then(|values| values.get(i)) != Some(value) {
                            return None;
                        }
                        cipher.get(name).and_then(|values| values.get(i)).filter(|cipher| !cipher.is_empty())
                    });
                    out.push(match kept {
                        Some(cipher) => cipher.clone(),
                        None => format!("{PREFIX}{}", "A".repeat(primitives::ciphertext_len(value) - PREFIX.len())),
                    });
                }
                stand_ins.set(name, out);
            }
            let body = Self::rewrite(&p, &stand_ins)?;
            self.values(&body, &pair.enc)?;
        }
        // A new key is appended to the keys file, which is read again.
        let keys = self.keys_file_for(dirname(&pair.plain));
        if let Ok(bytes) = fs::read(&keys) {
            if primitives::longest_quoted_span(&js::utf8(&bytes), appended) > primitives::QUOTED_SPAN_LIMIT {
                return Err(Stop::HandBack);
            }
        }
        Ok(())
    }

    fn no_record<T>(&self, pair: &Pair, p: &str, d: &str) -> R<T> {
        let diff = Self::describe_diff(pair, &self.values(p, &pair.plain)?, &self.values(d, &pair.enc)?);
        die(
            format!(
                "{} and {} differ, and this checkout has never synced them — {diff}. Keep the .enc side: `dede dec --force`; keep the plaintext side: `dede enc --force`",
                self.rel(&pair.plain),
                self.rel(&pair.enc)
            ),
            2,
        )
    }

    fn merge_conflict<T>(&self, pair: &Pair, conflicts: &[String]) -> R<T> {
        let plain = self.rel(&pair.plain);
        die(format!("{plain}: both sides changed {} since the last sync; edit {plain} to the value you want, then `dede enc --force`", list(conflicts)), 2)
    }

    pub fn enc(&mut self, pair: &Pair, force: bool) -> R<()> {
        self.preflight(pair)?;
        self.tighten(&pair.plain);
        let view = self.view(pair, true)?;
        let Some(p) = view.p.clone() else {
            return die(format!("{} not found{}", self.rel(&pair.plain), if view.e.is_some() { "; run `dede dec`" } else { "" }), 1);
        };
        let c = view.c.clone().expect("set with the plaintext");
        let Some(e) = view.e.clone() else {
            let (public, private) = self.obtain_key(pair)?;
            let text = self.build_enc(pair, &public, &private, &p, &c, None)?;
            self.write_atomic(&pair.enc, &text, 0o644)?;
            self.save_state(pair, &p, &text)?;
            self.written.push(pair.enc.clone());
            let message = format!("created {}", self.rel(&pair.enc));
            self.log(&message);
            return Ok(());
        };
        let public = view.public.clone().expect("set with the .enc");
        let private = view.private.clone().expect("the key was needed");
        let d = view.d.clone().expect("the key was needed");
        if let Some(choice) = self.key_choice.clone() {
            let chosen = self.key_by_name(&format!("DOTENV_PRIVATE_KEY_{choice}"), dirname(&pair.plain))?;
            if !chosen.is_empty() && primitives::derive(&chosen)? != public {
                return die(format!("{} is encrypted with another key; --key only chooses the key for a new .enc", self.rel(&pair.enc)), 4);
            }
        }
        if c == d {
            self.save_state(pair, &p, &e)?;
            let message = format!("{}: in sync", self.rel(&pair.enc));
            self.log(&message);
            return Ok(());
        }
        let state = self.last_sync(pair)?;
        let drifted = drift(&state, &p, &e);
        let mut text = js::lf(&p);
        let mut note = format!("encrypted {} → {}", self.rel(&pair.plain), self.rel(&pair.enc));
        if !force {
            if drifted == Drift::Unknown {
                return self.no_record(pair, &p, &d);
            }
            if drifted == Drift::EncChanged {
                let changed = changed_since(&state, &self.values(&d, &pair.enc)?);
                return die(format!("{} changed since the last sync{} (pulled?); run `dede dec` first", self.rel(&pair.enc), keys_note(&changed)), 1);
            }
            if drifted == Drift::Both {
                let merge = self.merge3(pair, &p, &d, &state)?;
                if !merge.conflicts.is_empty() {
                    return self.merge_conflict(pair, &merge.conflicts);
                }
                text = merge.text.clone().expect("a merge without conflicts has a text");
                self.write_atomic(&pair.plain, &text, 0o600)?;
                note = format!("{}: {}; wrote both files", self.rel(&pair.enc), merged_note(&merge));
            }
        }
        let normalized = Self::rewrite(&text, &self.values(&text, &pair.plain)?)?;
        let built = self.build_enc(pair, &public, &private, &text, &normalized, view.old.as_ref())?;
        self.write_atomic(&pair.enc, &built, 0o644)?;
        self.save_state(pair, &text, &built)?;
        self.written.push(pair.enc.clone());
        self.log(&note);
        Ok(())
    }

    pub fn dec(&mut self, pair: &Pair, force: bool) -> R<()> {
        self.preflight(pair)?;
        let view = self.view(pair, true)?;
        let Some(e) = view.e.clone() else {
            return die(format!("{} not found{}", self.rel(&pair.enc), if view.p.is_some() { "; run `dede enc`" } else { "" }), 1);
        };
        let d = view.d.clone().expect("the key was needed");
        if let Some(p) = &view.p {
            if view.c.as_ref() == Some(&d) {
                self.save_state(pair, p, &e)?;
                let message = format!("{}: in sync", self.rel(&pair.plain));
                self.log(&message);
                return Ok(());
            }
            if !force {
                let state = self.last_sync(pair)?;
                let drifted = drift(&state, p, &e);
                if drifted == Drift::Unknown {
                    return self.no_record(pair, p, &d);
                }
                if drifted == Drift::PlainChanged {
                    let changed = changed_since(&state, &self.values(p, &pair.plain)?);
                    return die(
                        format!("{} has edits not yet encrypted{}; run `dede enc` (or `dede dec --force` to discard them)", self.rel(&pair.plain), keys_note(&changed)),
                        1,
                    );
                }
                if drifted == Drift::Both {
                    let merge = self.merge3(pair, p, &d, &state)?;
                    if !merge.conflicts.is_empty() {
                        return self.merge_conflict(pair, &merge.conflicts);
                    }
                    let text = merge.text.clone().expect("a merge without conflicts has a text");
                    self.write_atomic(&pair.plain, &text, 0o600)?;
                    self.save_state(pair, &d, &e)?; // synced with the new .enc; your kept edits still need `dede enc`
                    let message = format!("{}: {}{}", self.rel(&pair.plain), merged_note(&merge), if merge.took_local.is_empty() { "" } else { "; run `dede enc` to publish your edits" });
                    self.log(&message);
                    return Ok(());
                }
            }
        }
        self.write_atomic(&pair.plain, &d, 0o600)?;
        self.save_state(pair, &d, &e)?;
        let message = format!("decrypted {} → {}", self.rel(&pair.enc), self.rel(&pair.plain));
        self.log(&message);
        Ok(())
    }

    /// After `dede enc`: commit just the .enc files it wrote. -y commits
    /// without asking; without a terminal and without -y nothing is
    /// committed. (With a terminal and without -y the question is asked by
    /// the JavaScript: `enc` is handed back before it starts.)
    pub fn commit_written(&mut self, yes: bool) -> i32 {
        if self.written.is_empty() || !yes {
            return 0;
        }
        let names: Vec<String> = self.written.iter().map(|path| self.rel(path)).collect();
        let list = if names.len() > 3 { format!("{} +{}", names[..3].join(", "), names.len() - 3) } else { names.join(", ") };
        let cwd = dirname(&self.written[0]).to_string();
        self.out.flush();
        let run = |dede: &Dede, args: Vec<&str>, stdout: Stdio| {
            let mut command = Command::new("git");
            command.args(args).current_dir(&cwd).stdin(Stdio::null()).stdout(stdout).stderr(Stdio::inherit());
            dede.env.apply(&mut command);
            command.status().is_ok_and(|status| status.code() == Some(0))
        };
        let mut add = vec!["add", "--"];
        add.extend(self.written.iter().map(String::as_str));
        let message = format!("dede enc: {list}");
        let mut commit = vec!["commit", "-q", "-m", &message, "--"];
        commit.extend(self.written.iter().map(String::as_str));
        if !run(self, add, Stdio::null()) || !run(self, commit, Stdio::inherit()) {
            self.log("dede: commit failed; the .enc files are written, commit them yourself");
            return 1;
        }
        self.log(&format!("committed {list}"));
        0
    }

    pub fn status(&mut self, pair: &Pair) -> R<bool> {
        let view = self.view(pair, false)?;
        let quiet = self.quiet;
        let plain = self.rel(&pair.plain);
        let say = |dede: &mut Dede, text: &str, ok: bool| {
            if !ok || !quiet {
                dede.out.log(&format!("{} {plain}: {text}", if ok { "✓" } else { "✗" }));
            }
            ok
        };
        let Some(e) = &view.e else {
            return Ok(say(self, if view.p.is_none() { "missing" } else { "no .enc yet (run `dede enc`)" }, false));
        };
        let Some(p) = &view.p else { return Ok(say(self, "no plaintext (run `dede dec`)", false)) };
        let Some(d) = &view.d else { return Ok(say(self, "no private key; cannot compare", false)) };
        if view.c.as_ref() == Some(d) {
            return Ok(say(self, "in sync", true));
        }
        let state = self.last_sync(pair)?;
        let text = match drift(&state, p, e) {
            Drift::PlainChanged => format!("edited{} (run `dede enc`)", keys_note(&changed_since(&state, &self.values(p, &pair.plain)?))),
            Drift::EncChanged => format!(".enc changed{} (run `dede dec`)", keys_note(&changed_since(&state, &self.values(d, &pair.enc)?))),
            Drift::Both => {
                let merge = self.merge3(pair, p, d, &state)?;
                if merge.conflicts.is_empty() {
                    "both changed, mergeable (run `dede enc`)".to_string()
                } else {
                    format!("conflict: both changed {}", list(&merge.conflicts))
                }
            }
            Drift::Unknown | Drift::Neither => format!("differs, no sync record — {}", Self::describe_diff(pair, &self.values(p, &pair.plain)?, &self.values(d, &pair.enc)?)),
        };
        Ok(say(self, &text, false))
    }

    /// One value, decrypted straight from the .enc (no plaintext needed),
    /// written raw. The last assignment wins, as in dotenv.
    pub fn get(&mut self, name: &str, pairs: &[Pair], stdout_is_terminal: bool) -> R<()> {
        if re!(r"^[A-Za-z_][A-Za-z0-9_.-]*$").find(name).is_none() {
            return die("usage: dede get NAME [file|glob…]".into(), 4);
        }
        // `values(…)[name]` finds what every object inherits under such a
        // name, and the TypeScript ends in an uncaught TypeError.
        if js::is_object_member(name) {
            return Err(Stop::HandBack);
        }
        let mut found: Vec<(String, String)> = Vec::new(); // (file, value)
        for pair in pairs {
            let Some(e) = self.read(&pair.enc)? else { continue };
            let (public, body, _) = self.split_enc(&js::lf(&e), &pair.enc)?;
            let values = self.values(&body, &pair.enc)?;
            let Some(cipher) = values.get(name) else { continue };
            let ciphertext = cipher.last().expect("a name that was found has a value");
            let mut value = String::new();
            if !ciphertext.is_empty() {
                if !ciphertext.starts_with(PREFIX) {
                    return die(format!("{}: {name} is not encrypted", self.rel(&pair.enc)), 4);
                }
                let private = self.private_key_for(&public, pair)?;
                value = match primitives::decrypt(&private, ciphertext) {
                    Ok(value) => value,
                    Err(CryptoError::Thrown) => return die(format!("{}: cannot decrypt {name} (wrong key or corrupt value)", self.rel(&pair.enc)), 3),
                    Err(CryptoError::NotImitated) => return Err(Stop::HandBack),
                };
            }
            found.push((self.rel(&pair.enc), value));
        }
        if found.is_empty() {
            let places = if pairs.is_empty() { "any .env*.enc here".to_string() } else { pairs.iter().map(|pair| self.rel(&pair.enc)).collect::<Vec<_>>().join(", ") };
            return die(format!("{name} not found in {places}"), 1);
        }
        if found.iter().any(|(_, value)| value != &found[0].1) {
            let files: Vec<&str> = found.iter().map(|(file, _)| file.as_str()).collect();
            return die(format!("{name} has different values in {}; name the file: dede get {name} <file>", files.join(", ")), 2);
        }
        self.out.write(&format!("{}{}", found[0].1, if stdout_is_terminal { "\n" } else { "" }));
        Ok(())
    }

    pub fn diff(&mut self, pair: &Pair) -> R<bool> {
        let view = self.view(pair, false)?;
        let plain = self.rel(&pair.plain);
        let say = |dede: &mut Dede, text: &str, ok: bool| {
            dede.out.log(&format!("{} {plain}: {text}", if ok { "✓" } else { "✗" }));
            ok
        };
        let (Some(p), Some(_)) = (&view.p, &view.e) else {
            return Ok(say(self, if view.e.is_none() { "no .enc" } else { "no plaintext" }, false));
        };
        let Some(d) = &view.d else { return Ok(say(self, "no private key; cannot compare", false)) };
        if view.c.as_ref() == Some(d) {
            return Ok(say(self, "no differences", true));
        }
        let text = Self::describe_diff(pair, &self.values(p, &pair.plain)?, &self.values(d, &pair.enc)?);
        Ok(say(self, &text, false))
    }

    // ───────────────────────── guard ─────────────────────────

    /// Staged paths, and whether each is new to git (added, renamed/copied
    /// in, or changed type). With --all: every tracked path, none of them new.
    fn guard_list(&self, top: &str, all: bool) -> R<Vec<(String, bool)>> {
        if all {
            return Ok(self.git(&["ls-files", "-z"], top)?.1.split('\0').filter(|path| !path.is_empty()).map(|path| (path.to_string(), false)).collect());
        }
        let output = self.git(&["diff", "--cached", "--name-status", "-z", "--diff-filter=d"], top)?.1;
        let parts: Vec<&str> = output.split('\0').collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < parts.len() && !parts[i].is_empty() {
            let status = parts[i].chars().next().expect("not empty");
            i += 1;
            if status == 'R' || status == 'C' {
                i += 1; // skip the old path
            }
            // git always names a path after a status.
            let path = parts.get(i).ok_or(Stop::HandBack)?;
            i += 1;
            out.push((path.to_string(), "ARCT".contains(status)));
        }
        Ok(out)
    }

    /// Untracked and ignored files of the work tree, each once, ignored
    /// directories collapsed (so node_modules is not walked).
    fn untracked(&self, top: &str) -> R<Vec<String>> {
        let others = self.git(&["ls-files", "--others", "--exclude-standard", "-z"], top)?.1;
        let ignored = self.git(&["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"], top)?.1;
        let node_modules = re!(r"(^|\/)node_modules\/");
        let mut out: Vec<String> = Vec::new();
        for path in others.split('\0').chain(ignored.split('\0')) {
            if !path.is_empty() && !path.ends_with('/') && node_modules.find(path).is_none() && !out.iter().any(|seen| seen == path) {
                out.push(path.to_string());
            }
        }
        Ok(out)
    }

    /// Untracked plaintext env files that nobody manages: not *.local, not
    /// committed, and without an .enc twin.
    pub fn unmanaged_env_files(&self, top: &str) -> R<Vec<String>> {
        Ok(self
            .untracked(top)?
            .into_iter()
            .filter(|path| {
                let name = basename(path);
                is_env_name(name) && !name.ends_with(".local") && !exists(&format!("{}.enc", join(top, path)))
            })
            .collect())
    }

    /// Plaintext files with an .enc twin whose edits have not been encrypted
    /// yet. Uses the sync record, so no key is needed; without a record it
    /// decrypts when the key is held.
    fn unencrypted_edits(&mut self, top: &str) -> R<Vec<String>> {
        let mut bad = Vec::new();
        for file in self.untracked(top)? {
            let name = basename(&file).to_string();
            let plain = join(top, &file);
            if !is_env_name(&name) || !exists(&format!("{plain}.enc")) || is_symlink(&plain) {
                continue;
            }
            let pair = Pair { plain: plain.clone(), enc: format!("{plain}.enc"), name: name.clone() };
            // Both were just seen; a file that is gone again is not imitated.
            let p = self.read(&plain)?.ok_or(Stop::HandBack)?;
            self.read(&pair.enc)?.ok_or(Stop::HandBack)?;
            let state = self.last_sync(&pair)?;
            if state.is_some() {
                if Some(sha(&p)) != state.as_ref().and_then(|state| state.plain.clone()) {
                    let changed = changed_since(&state, &self.values(&p, &plain)?);
                    bad.push(format!("{file}: edits not encrypted yet{}; run `dede enc` and commit {name}.enc", keys_note(&changed)));
                }
                continue;
            }
            let view = self.view(&pair, false)?;
            if let Some(d) = &view.d {
                if view.c.as_ref() != Some(d) {
                    let diff = Self::describe_diff(&pair, &self.values(&p, &plain)?, &self.values(d, &pair.enc)?);
                    bad.push(format!("{file}: differs from {name}.enc and has never been synced here ({diff}); see `dede diff`"));
                }
            }
        }
        Ok(bad)
    }

    pub fn guard(&mut self, all: bool) -> R<()> {
        let top = self.git_dir(&self.cwd)?;
        let mut bad: Vec<String> = Vec::new();
        for file in self.unmanaged_env_files(&top)? {
            bad.push(format!("{file}: {UNMANAGED_HINT}"));
        }
        bad.extend(self.unencrypted_edits(&top)?);
        let private_key = re!(r#"DOTENV_PRIVATE_KEY[A-Z0-9_]*["']?\s*[=:]\s*["']?[0-9a-fA-F]{64}"#);
        for (file, added) in self.guard_list(&top, all)? {
            let name = basename(&file);
            let (blob_ok, blob) = self.git(&["cat-file", "blob", &format!(":{file}")], &top)?;
            if name == ".env.keys" || name.starts_with(TMP) {
                bad.push(format!("{file}: private keys / temp file must never be committed"));
            } else if name.ends_with(".enc") && is_env_name(&name[..name.len() - 4]) {
                let path = join(&top, &file);
                let sealed = self.split_enc(&blob, &path).and_then(|(_, body, offset)| self.assert_sealed(&body, &path, offset));
                match sealed {
                    Ok(()) => {}
                    Err(Stop::Die(message, _)) => bad.push(message),
                    Err(Stop::Thrown(_)) => bad.push(format!("{file}: unreadable")),
                    Err(Stop::HandBack) => return Err(Stop::HandBack),
                }
            } else if added && matches_name(name) && !is_skipped(name) {
                // Already-tracked plaintext env files are public config on purpose; only new ones are blocked.
                bad.push(format!("{file}: new plaintext env file; commit {name}.enc instead (dede enc), or --no-verify if it is public config"));
            }
            if blob_ok && private_key.find(&blob).is_some() {
                bad.push(format!("{file}: contains a DOTENV_PRIVATE_KEY"));
            }
        }
        if !bad.is_empty() {
            return die(format!("dede guard: blocked\n  {}\n  (unstage with `git restore --staged <file>`)", bad.join("\n  ")), 1);
        }
        Ok(())
    }

    // ───────────────────────── keys ─────────────────────────

    /// Prints public-key prefixes and file names only, never a private key.
    pub fn keys_status(&mut self, pairs: &[Pair]) -> R<bool> {
        let mut ok = true;
        for pair in pairs {
            let Some(e) = self.read(&pair.enc)? else { continue };
            let (public, _, _) = self.split_enc(&e, &pair.enc)?;
            let from = self.tree_for(dirname(&pair.plain))?.from.get(&public).cloned();
            if from.is_none() {
                ok = false;
            }
            let line = format!(
                "{} {}  {}…  {}",
                if from.is_some() { "✓" } else { "✗" },
                self.rel(&pair.enc),
                &public[..10],
                from.unwrap_or_else(|| format!("missing (DOTENV_PRIVATE_KEY{})", suffix_of(&pair.name)))
            );
            self.out.log(&line);
        }
        Ok(ok)
    }

    pub fn keys_link(&mut self, target: Option<&str>) -> R<()> {
        let Some(target) = target.filter(|target| !target.is_empty()) else {
            return die("usage: dede keys link <path/to/.env.keys>".into(), 4);
        };
        let link = join(&self.cwd, ".env.keys");
        let absolute = self.resolve(target);
        if !fs::metadata(&absolute).is_ok_and(|meta| meta.is_file()) {
            return die(format!("{target}: no such keys file"), 4);
        }
        let link_real = if exists(&link) { realpath(&link)? } else { String::new() };
        if realpath(&absolute)? == link_real {
            self.log(&format!(".env.keys already points to {target}"));
            return Ok(());
        }
        if exists(&link) || is_symlink(&link) {
            return die(".env.keys already exists here; move it away first".into(), 1);
        }
        self.assert_keys_file_safe(&link)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = thrown(fs::metadata(&absolute))?.permissions().mode();
            if mode & 0o077 != 0 {
                self.log(&format!("warning: {target} is readable by other users; chmod 600 it"));
            }
            // The one change this command makes, after which it prints to
            // standard error. If it fails, nothing has been printed yet and
            // nothing has changed.
            if !self.out.colour_is_known() {
                return Err(Stop::HandBack);
            }
            thrown(std::os::unix::fs::symlink(target, &link))?;
            self.log(&format!("linked .env.keys → {target}"));
            Ok(())
        }
        #[cfg(not(unix))]
        Err(Stop::HandBack)
    }

    /// Looks at the sync record of this pair's repository without asking git
    /// for its place: is it something this port reads and writes back the
    /// way the TypeScript does? Every record git could take is looked at
    /// (`repo::possible_records`), and every entry in it, since which one
    /// the run will use is git's answer. A record that is not there is no
    /// concern; one that is not JSON is `{}` to both.
    pub fn check_sync_record(&self, pair: &Pair) -> R<()> {
        for record in crate::repo::possible_records(dirname(&pair.plain), &self.env)? {
            let Ok(bytes) = fs::read(&record) else { continue };
            match js::parse_json(&js::utf8(&bytes)) {
                Ok(Json::Object(all)) => {
                    for key in all.keys() {
                        state_entry(&all, &key)?;
                    }
                }
                Ok(_) | Err(JsonError::NotImitated) => return Err(Stop::HandBack),
                Err(JsonError::Syntax) => {}
            }
        }
        Ok(())
    }

    // ───────────────────────── args ─────────────────────────

    /// The pairs the arguments name; `None` in place of a pair list never
    /// happens: a glob is handed back.
    pub fn pairs(&mut self, args: &[String], mode: Mode) -> R<Vec<Pair>> {
        let cwd = self.cwd.clone();
        let mut found: Vec<(String, bool)> = Vec::new();
        // Sorted: readdir order is the filesystem's; output and new keys should not depend on it.
        if args.is_empty() {
            let mut names = readdir(&cwd)?;
            js::sort(&mut names);
            found.extend(names.iter().map(|name| (join(&cwd, name), false)));
        }
        for arg in args {
            // `Bun.Glob` does the matching in the TypeScript; not ported.
            if arg.contains(['*', '?', '[', '{']) {
                return Err(Stop::HandBack);
            }
            found.push((self.resolve(arg), true));
        }
        let mut out: Vec<Pair> = Vec::new();
        for (path, explicit) in found {
            let plain = path.strip_suffix(".enc").unwrap_or(&path).to_string();
            let name = basename(&plain).to_string();
            if !is_env_name(&name) {
                if explicit && !name.starts_with(".env") {
                    return die(format!("{}: not a .env file", self.rel(&path)), 4);
                }
                continue;
            }
            if !explicit && is_symlink(&plain) {
                let message = format!("skipping {}: symlink (dede only syncs regular files)", self.rel(&plain));
                self.log(&message);
                continue;
            }
            if exists(&plain) && self.is_tracked(&plain)? {
                let message = format!("skipping {}: committed in plaintext, so treated as public config (if it holds secrets: git rm --cached it and rotate them)", self.rel(&plain));
                self.log(&message);
                continue;
            }
            let pair = Pair { enc: format!("{plain}.enc"), plain, name };
            let wanted = match mode {
                Mode::Enc => exists(&pair.plain),
                Mode::Dec => exists(&pair.enc),
                Mode::Any => exists(&pair.plain) || exists(&pair.enc),
            };
            if !wanted && !explicit {
                continue;
            }
            match out.iter().position(|seen| seen.plain == pair.plain) {
                Some(at) if explicit => out[at] = pair,
                Some(_) => {}
                None => out.push(pair),
            }
        }
        if out.is_empty() && (!args.is_empty() || mode != Mode::Any) {
            self.log(&format!("dede {}: no matching env files", mode.name()));
        }
        Ok(out)
    }
}

/// The text with every character outside the Basic Multilingual Plane
/// replaced by two private-use characters: what a JavaScript regular
/// expression without the `u` flag sees, for one that only counts them.
fn utf16_units(text: &str) -> std::borrow::Cow<'_, str> {
    if text.chars().all(|c| (c as u32) < 0x10000) {
        return text.into();
    }
    text.chars().map(|c| if (c as u32) < 0x10000 { c.to_string() } else { "\u{e000}\u{e000}".to_string() }).collect::<String>().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(suffix_of(".env"), "");
        assert_eq!(suffix_of(".env.local"), "_LOCAL");
        assert_eq!(suffix_of(".env.development.local"), "_DEVELOPMENT_LOCAL");
        assert_eq!(suffix_of(".env.keys.my-proj"), "_KEYS_MY_PROJ");
        for name in [".env", ".env.local", ".env.a-b_c.D9", ".env.keys.x"] {
            assert!(is_env_name(name), "{name}");
        }
        for name in [".env.", ".envx", "env", ".env..a", ".env.a b", ".env.enc", ".env.local.enc", ".env.keys", ".env.example", ".env.dede-tmp-1-ab", ".env.é", ".env.local\n", ""] {
            assert!(!is_env_name(name), "{name:?}");
        }
        assert!(matches_name(".env.keys") && matches_name(".env.enc") && !matches_name(".env/"));
    }

    #[test]
    fn hashes() {
        // sha256("a\n"), and HMAC-SHA256("k", "v") cut to 24 hex digits, as node:crypto gives them.
        assert_eq!(sha("a\r\n"), "87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7");
        assert_eq!(hmac("k", "v"), "c5d4be1992d50d3b41f9a212");
        assert_eq!(comments_of("A=1\n# x\n  # y\nB=2 # z"), "# x\n  # y");
    }
}
