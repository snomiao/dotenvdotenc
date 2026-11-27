//! The seven functions of @dotenvx/primitives 3.0.3 that dede uses: `scan`,
//! `upsert`, `remove`, `keypair`, `encrypt`, `decrypt` and the reading half of
//! `keyringSync`. Each follows the package's own steps (dist/index.cjs),
//! including its regular expressions, which run on an ECMAScript engine here.
//!
//! The format is dotenvx's: a value is encrypted for a secp256k1 public key
//! with ECIES as eciesjs does it (an ephemeral key, ECDH, HKDF-SHA256 over
//! both uncompressed points, AES-256-GCM with a 16-byte nonce) and written as
//! `encrypted:` plus the base64 of `ephemeral key ‖ nonce ‖ tag ‖ ciphertext`.

use std::sync::OnceLock;

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::AesGcm;
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{PublicKey, SecretKey};
use regress::Regex;
use sha2::Sha256;

use crate::js::{self, Object};

pub const PREFIX: &str = "encrypted:";

/// What went wrong in the library, as far as dede can tell it apart: only the
/// name of the JavaScript error ever reaches a user (`TypeError`, `Error`).
#[derive(Debug, PartialEq)]
pub struct Thrown(pub &'static str);

/// A JavaScript regular expression. The patterns here are the package's and
/// the TypeScript's own, so failing to compile one is a bug in this file.
pub fn regex(pattern: &str, flags: &str) -> Regex {
    Regex::with_flags(pattern, flags).unwrap_or_else(|err| panic!("regular expression {pattern:?}: {err}"))
}

/// `values` for each name, in the order of the file: `parsed` of `scan()`.
pub type Values = Object<Vec<String>>;

#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub expand_double_quoted_newlines: bool,
    pub convert_windows_newlines: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { expand_double_quoted_newlines: true, convert_windows_newlines: true }
    }
}

/// `scan(source).parsed`
pub fn scan(source: &str) -> Result<Values, Thrown> {
    scan_with(source, ScanOptions::default())
}

/// `scan(source, options).parsed`: every assignment, repeated names kept in
/// order, nothing expanded or decrypted.
pub fn scan_with(source: &str, options: ScanOptions) -> Result<Values, Thrown> {
    static LINE: OnceLock<Regex> = OnceLock::new();
    static NEWLINES: OnceLock<Regex> = OnceLock::new();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    let line = LINE.get_or_init(|| {
        regex(
            r#"(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#(.*))?(?:$|$)"#,
            "m",
        )
    });
    let quoted = QUOTED.get_or_init(|| regex(r#"^(['"`])([\s\S]*)\1$"#, "m"));
    let converted;
    let text = if options.convert_windows_newlines {
        let newlines = NEWLINES.get_or_init(|| regex(r"\r\n?", ""));
        converted = replace_all(newlines, source, |_, _| "\n".to_string());
        converted.as_str()
    } else {
        source
    };

    let mut parsed = Values::new();
    for found in line.find_iter(text) {
        let name = &text[found.group(1).expect("the name group always takes part")];
        // `parsed[name] = parsed[name] || []; parsed[name].push(value)`: for a
        // name every object has (`constructor`, `toString`, …) what is found
        // there is no array, and `push` fails.
        if js::is_object_member(name) {
            return Err(Thrown("TypeError"));
        }
        let raw = found.group(2).map(|range| &text[range]).unwrap_or("");
        let trimmed = js::trim(raw);
        let quote = trimmed.chars().next().filter(|c| matches!(c, '\'' | '"' | '`'));
        let mut value = replace_all(quoted, trimmed, |found, text| text[found.group(2).expect("group 2 always takes part")].to_string());
        match quote {
            Some('\'') => value = value.replace("\\'", "'"),
            Some('"') if options.expand_double_quoted_newlines => {
                value = value.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
            }
            _ => {}
        }
        match parsed.get_mut(name) {
            Some(values) => values.push(value),
            None => parsed.set(name, vec![value]),
        }
    }
    Ok(parsed)
}

/// `text.replace(regex /g, f)`
fn replace_all(regex: &Regex, text: &str, replacement: impl Fn(&regress::Match, &str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for found in regex.find_iter(text) {
        out.push_str(&text[last..found.start()]);
        out.push_str(&replacement(&found, text));
        last = found.end();
    }
    out.push_str(&text[last..]);
    out
}

/// The new value of an `upsert`: one for every assignment of the name, or
/// one each.
pub enum Replacement<'a> {
    One(&'a str),
    Each(&'a [String]),
}

/// `upsert(source, name, value)`: replaces the value of every assignment of
/// `name`, keeping quotes, `export` and indentation, or appends
/// `name="value"`.
pub fn upsert(source: &str, name: &str, value: Replacement) -> Result<String, Thrown> {
    let parsed = scan_with(source, ScanOptions { expand_double_quoted_newlines: false, convert_windows_newlines: false })?;
    let Some(old) = parsed.get(name) else {
        // `${name}="${value}"`: an array is written as JavaScript joins it.
        let value = match value {
            Replacement::One(value) => value.to_string(),
            Replacement::Each(values) => values.join(","),
        };
        let line = format!("{name}=\"{value}\"");
        return Ok(if source.is_empty() || source.ends_with('\n') { format!("{source}{line}\n") } else { format!("{source}\n{line}") });
    };
    let marker = |i: usize| format!("\0DOTENVX_UPSERT_{i}\0");
    let mut text = source.to_string();
    for (i, old_value) in old.iter().enumerate() {
        text = replace_assignment(&text, name, old_value, &marker(i));
    }
    let count = match value {
        Replacement::One(_) => old.len(),
        Replacement::Each(values) => values.len(),
    };
    for i in 0..count {
        let new = match value {
            Replacement::One(value) => value,
            Replacement::Each(values) => values[i].as_str(),
        };
        text = text.replace(&marker(i), new);
    }
    Ok(text)
}

/// What the package escapes before putting text into a regular expression.
fn escape_regex(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '|' | '\\' | '{' | '}' | '(' | ')' | '[' | ']' | '^' | '$' | '+' | '*' | '?' | '.' => {
                out.push('\\');
                out.push(c);
            }
            '-' => out.push_str("\\x2d"),
            c => out.push(c),
        }
    }
    out
}

/// Replaces the first assignment of `name` whose value is `old` by
/// `name=<quote><marker><quote>`.
fn replace_assignment(text: &str, name: &str, old: &str, marker: &str) -> String {
    let name_pattern = escape_regex(name);
    let old_pattern = escape_regex(old);
    let end = if old_pattern.is_empty() { "$" } else { "" };
    let assignment = regex(&format!("^(\\s*)?(export\\s+)?{name_pattern}\\s*=\\s*([\"'`]?){old_pattern}\\3{end}"), "m");
    let Some(found) = assignment.find(text) else { return text.to_string() };
    let group = |i: usize| found.group(i).map(|range| &text[range]).unwrap_or("");
    let (indent, export, quote) = (group(1), group(2), group(3));
    let mut line = format!("{name}={quote}{marker}{quote}");
    if old_pattern.is_empty() && quote.is_empty() {
        // An empty value followed by blank lines: the match swallowed them.
        let blank = regex(&format!("{name_pattern}\\s*=\\s*\n\n"), "m");
        if let Some(blank) = blank.find(text) {
            let newlines = text[blank.range()].matches('\n').count() - 1;
            line.push_str(&"\n".repeat(newlines));
        }
    }
    format!("{}{indent}{export}{line}{}", &text[..found.start()], &text[found.end()..])
}

/// `remove(source, name)`: the source without the assignments of `name`,
/// values over several lines included.
pub fn remove(source: &str, name: &str) -> String {
    struct Assignment<'a> {
        name: &'a str,
        raw: &'a str,
    }
    fn assignment(line: &str) -> Option<Assignment<'_>> {
        let mut text = js::trim_start(line);
        if let Some(rest) = text.strip_prefix("export ") {
            text = js::trim_start(rest);
        }
        let equals = text.find('=');
        let colon = text.find(": ");
        let at = match (equals, colon) {
            (None, colon) => colon?,
            (Some(equals), Some(colon)) if colon < equals => colon,
            (Some(equals), _) => equals,
        };
        let name = js::trim(&text[..at]);
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
            return None;
        }
        let skip = if text[at..].starts_with(": ") { 2 } else { 1 };
        Some(Assignment { name, raw: &text[at + skip..] })
    }
    /// Does the text hold the quote twice, not counting escaped ones?
    fn closed(text: &str, quote: char) -> bool {
        let mut escaped = false;
        let mut count = 0;
        for c in text.chars() {
            if c == quote && !escaped {
                count += 1;
            }
            escaped = c == '\\' && !escaped;
        }
        count >= 2
    }

    let newline = if source.contains("\r\n") { "\r\n" } else { "\n" };
    let normal = source.replace("\r\n", "\n").replace('\r', "\n");
    let ends_with_newline = normal.ends_with('\n');
    let mut lines: Vec<&str> = normal.split('\n').collect();
    if ends_with_newline {
        lines.pop();
    }
    let mut kept: Vec<&str> = Vec::new();
    let mut at = 0;
    let mut removed = false;
    while at < lines.len() {
        let line = lines[at];
        let Some(found) = assignment(line).filter(|found| found.name == name) else {
            kept.push(line);
            at += 1;
            continue;
        };
        removed = true;
        let start = js::trim_start(found.raw);
        let quote = start.chars().next().filter(|c| matches!(c, '\'' | '"' | '`'));
        if let Some(quote) = quote {
            if !closed(start, quote) {
                let mut raw = found.raw.to_string();
                at += 1;
                while at < lines.len() {
                    raw.push('\n');
                    raw.push_str(lines[at]);
                    if closed(js::trim_start(&raw), quote) {
                        break;
                    }
                    at += 1;
                }
            }
        }
        at += 1;
    }
    if !removed {
        return source.to_string();
    }
    let mut out = kept.join("\n");
    if ends_with_newline && !out.is_empty() {
        out.push('\n');
    }
    if newline == "\r\n" {
        out = out.replace('\n', "\r\n");
    }
    out
}

// ───────────────────────────── keys ─────────────────────────────

/// The secret a private key text stands for: `Buffer.from(text, "hex")`,
/// then eciesjs's check (32 bytes, between 1 and the group order).
/// `Ok(None)` is an invalid key; `Err(())` is text that is not imitated.
fn secret_key(text: &str) -> Result<Option<SecretKey>, ()> {
    let bytes = js::hex_bytes(text).ok_or(())?;
    if bytes.len() != 32 {
        return Ok(None);
    }
    Ok(SecretKey::from_slice(&bytes).ok())
}

fn public_hex(key: &PublicKey) -> String {
    js::hex(key.to_sec1_point(true).as_bytes())
}

/// The result of an operation on a key or a value.
#[derive(Debug, PartialEq)]
pub enum CryptoError {
    /// The library throws an `Error`.
    Thrown,
    /// The input is of a kind whose handling by bun is not imitated (a key or
    /// ciphertext with other than ASCII characters in it).
    NotImitated,
}

/// `keypair(privateKey).publicKey`: the compressed public key, in hex.
pub fn derive(private_key: &str) -> Result<String, CryptoError> {
    match secret_key(private_key) {
        Ok(Some(secret)) => Ok(public_hex(&secret.public_key())),
        Ok(None) => Err(CryptoError::Thrown),
        Err(()) => Err(CryptoError::NotImitated),
    }
}

fn random_secret() -> SecretKey {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("the system's random number generator");
        let secret = SecretKey::from_slice(&bytes);
        bytes.fill(0);
        if let Ok(secret) = secret {
            return secret;
        }
    }
}

/// `keypair()`: a new key, as (public key, private key), both in hex.
pub fn new_keypair() -> (String, String) {
    let secret = random_secret();
    (public_hex(&secret.public_key()), js::hex(&secret.to_bytes()))
}

/// The AES key both sides derive: HKDF-SHA256 over the ephemeral public key
/// and the shared point, both uncompressed.
fn shared_key(ephemeral: &PublicKey, other: &PublicKey, secret: &SecretKey) -> [u8; 32] {
    let point = (other.to_projective() * *secret.to_nonzero_scalar()).to_affine();
    let mut material = Vec::with_capacity(130);
    material.extend_from_slice(ephemeral.to_sec1_point(false).as_bytes());
    material.extend_from_slice(point.to_sec1_point(false).as_bytes());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &material).expand(&[], &mut key).expect("32 bytes is a valid length");
    material.fill(0);
    key
}

type Cipher = AesGcm<Aes256, U16>;

/// `encrypt(publicKey, value)`
pub fn encrypt(public_key: &str, value: &str) -> Result<String, CryptoError> {
    // A public key reaches this only from `derive` or from an .enc header,
    // both 66 lower-case hex digits.
    let bytes = js::hex_bytes(public_key).filter(|bytes| bytes.len() == 33 && public_key.len() == 66).ok_or(CryptoError::NotImitated)?;
    let recipient = PublicKey::from_sec1_bytes(&bytes).map_err(|_| CryptoError::Thrown)?;
    let ephemeral = random_secret();
    let ephemeral_public = ephemeral.public_key();
    let mut key = shared_key(&ephemeral_public, &recipient, &ephemeral);
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("the system's random number generator");
    let cipher = Cipher::new_from_slice(&key).expect("a 32-byte key");
    key.fill(0);
    // The cipher gives ciphertext ‖ tag; the format has the tag first.
    let sealed = cipher.encrypt((&nonce).into(), value.as_bytes()).map_err(|_| CryptoError::Thrown)?;
    let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
    let mut out = Vec::with_capacity(65 + 32 + ciphertext.len());
    out.extend_from_slice(ephemeral_public.to_sec1_point(false).as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(format!("{PREFIX}{}", js::base64(&out)))
}

/// `decrypt(privateKey, value)` for a value that starts with `encrypted:`.
pub fn decrypt(private_key: &str, value: &str) -> Result<String, CryptoError> {
    let encoded = value.strip_prefix(PREFIX).ok_or(CryptoError::NotImitated)?;
    if private_key.is_empty() {
        return Err(CryptoError::Thrown);
    }
    let secret = secret_key(private_key).map_err(|()| CryptoError::NotImitated)?;
    let data = js::base64_bytes(encoded).ok_or(CryptoError::NotImitated)?;
    let secret = secret.ok_or(CryptoError::Thrown)?;
    // 65 bytes of uncompressed public key, 16 of nonce, 16 of tag.
    if data.len() < 65 + 32 || data[0] != 4 {
        return Err(CryptoError::Thrown);
    }
    let ephemeral = PublicKey::from_sec1_bytes(&data[..65]).map_err(|_| CryptoError::Thrown)?;
    let mut key = shared_key(&ephemeral, &ephemeral, &secret);
    let cipher = Cipher::new_from_slice(&key).expect("a 32-byte key");
    key.fill(0);
    let (nonce, rest) = data[65..].split_at(16);
    let (tag, ciphertext) = rest.split_at(16);
    let mut sealed = Vec::with_capacity(rest.len());
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    let nonce: [u8; 16] = nonce.try_into().expect("16 bytes");
    let plain = cipher.decrypt((&nonce).into(), sealed.as_slice()).map_err(|_| CryptoError::Thrown)?;
    // `Buffer.from(bytes).toString("utf8")`
    Ok(js::utf8(&plain))
}

/// `keyringSync({ fk: files, processEnv: variables })`: public key → private
/// key. A public key named by a `DOTENV_PUBLIC_KEY*` variable is in the ring
/// with an empty private key until one is found for it.
///
/// `read` gives a file's text, or `None` where `readFileSync` throws.
pub fn keyring(files: &[&str], variables: &[(String, String)], read: impl Fn(&str) -> Option<String>) -> Result<Object<String>, CryptoError> {
    let mut candidates: Vec<String> = Vec::new();
    for file in files {
        // Anything that goes wrong with a keys file means "no keys in it".
        let Some(text) = read(file) else { continue };
        let Ok(parsed) = scan(&text) else { continue };
        for (name, values) in parsed.entries() {
            if name.starts_with("DOTENV_PRIVATE_KEY") {
                for value in values {
                    candidates.extend(value.split(',').map(String::from));
                }
            }
        }
    }
    let mut ring: Object<String> = Object::new();
    for (name, value) in variables {
        if name.starts_with("DOTENV_PUBLIC_KEY") && !ring.has(value) && !js::is_object_member(value) {
            ring.set(value, String::new());
        }
        if name.starts_with("DOTENV_PRIVATE_KEY") {
            candidates.push(value.clone());
        }
    }
    for candidate in candidates {
        match derive(&candidate) {
            Ok(public) => ring.set(&public, candidate),
            Err(CryptoError::Thrown) => {}
            Err(CryptoError::NotImitated) => return Err(CryptoError::NotImitated),
        }
    }
    Ok(ring)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{parse_json, Json};

    fn text(value: &Json) -> &str {
        match value {
            Json::String(s) => s,
            other => panic!("not text: {other:?}"),
        }
    }

    fn list(value: &Json) -> &[Json] {
        match value {
            Json::Array(items) => items,
            other => panic!("not a list: {other:?}"),
        }
    }

    fn object(value: &Json) -> &Object<Json> {
        match value {
            Json::Object(object) => object,
            other => panic!("not an object: {other:?}"),
        }
    }

    fn vectors() -> Object<Json> {
        object(&parse_json(include_str!("testdata/primitives.json")).unwrap()).clone()
    }

    /// The text of a `scan` result the way rs/vectors.gen.mjs records it:
    /// `JSON.stringify(parsed)`, or the name of the error thrown.
    fn scanned(result: Result<Values, Thrown>) -> String {
        match result {
            Ok(parsed) => {
                let mut out = Object::new();
                for (name, values) in parsed.entries() {
                    out.set(name, Json::Array(values.iter().map(|v| Json::String(v.clone())).collect()));
                }
                js::stringify(&Json::Object(out), "")
            }
            Err(Thrown(name)) => format!("throws {name}"),
        }
    }

    /// Sources and what @dotenvx/primitives 3.0.3 makes of them under bun,
    /// recorded by rs/vectors.gen.mjs.
    #[test]
    fn scan_upsert_and_remove_follow_the_package() {
        let vectors = vectors();
        let sources = list(vectors.get("sources").unwrap());
        assert!(sources.len() > 250, "the recorded sources are missing");
        for case in sources {
            let case = object(case);
            let source = text(case.get("source").unwrap());
            assert_eq!(scanned(scan(source)), text(case.get("scan").unwrap()), "scan({source:?})");
            let raw = ScanOptions { expand_double_quoted_newlines: false, convert_windows_newlines: false };
            assert_eq!(scanned(scan_with(source, raw)), text(case.get("scanRaw").unwrap()), "scan({source:?}, raw)");
            for step in list(case.get("upsert").unwrap()) {
                let step = object(step);
                let name = text(step.get("name").unwrap());
                let expected = text(step.get("result").unwrap());
                let got = match step.get("value").unwrap() {
                    Json::String(value) => upsert(source, name, Replacement::One(value)),
                    values => {
                        let values: Vec<String> = list(values).iter().map(|v| text(v).to_string()).collect();
                        upsert(source, name, Replacement::Each(&values))
                    }
                };
                let got = got.unwrap_or_else(|Thrown(name)| format!("throws {name}"));
                assert_eq!(got, expected, "upsert({source:?}, {name:?}, {:?})", step.get("value"));
            }
            for step in list(case.get("remove").unwrap()) {
                let step = object(step);
                let name = text(step.get("name").unwrap());
                assert_eq!(remove(source, name), text(step.get("result").unwrap()), "remove({source:?}, {name:?})");
            }
        }
    }

    /// Keys and ciphertexts made by @dotenvx/primitives; every key here was
    /// made for this file and protects nothing.
    #[test]
    fn keys_and_ciphertexts_follow_the_package() {
        let vectors = vectors();
        for case in list(vectors.get("derive").unwrap()) {
            let case = object(case);
            let private = text(case.get("privateKey").unwrap());
            let expected = text(case.get("result").unwrap());
            let got = match derive(private) {
                Ok(public) => public,
                Err(CryptoError::Thrown) => "throws".to_string(),
                Err(CryptoError::NotImitated) => "not imitated".to_string(),
            };
            assert_eq!(got, expected, "derive({private:?})");
        }
        let cases = list(vectors.get("decrypt").unwrap());
        assert!(cases.len() > 20);
        for case in cases {
            let case = object(case);
            let private = text(case.get("privateKey").unwrap());
            let value = text(case.get("value").unwrap());
            let expected = text(case.get("result").unwrap());
            let got = match decrypt(private, value) {
                Ok(plain) => format!("ok {plain}"),
                Err(CryptoError::Thrown) => "throws".to_string(),
                Err(CryptoError::NotImitated) => "not imitated".to_string(),
            };
            assert_eq!(got, expected, "decrypt({private:?}, {value:?})");
        }
    }

    #[test]
    fn what_is_encrypted_here_decrypts_here() {
        let (public, private) = new_keypair();
        assert_eq!(derive(&private).as_deref(), Ok(public.as_str()));
        for value in ["", "x", "two words", "a\nb", "é→世界😀", &"long ".repeat(1000)] {
            let sealed = encrypt(&public, value).unwrap();
            assert!(sealed.starts_with(PREFIX));
            assert_ne!(sealed, encrypt(&public, value).unwrap(), "encryption is randomized");
            assert_eq!(decrypt(&private, &sealed).as_deref(), Ok(value));
            let (_, other) = new_keypair();
            assert_eq!(decrypt(&other, &sealed), Err(CryptoError::Thrown));
        }
    }
}
