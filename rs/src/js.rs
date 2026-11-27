//! The JavaScript rules the TypeScript relies on without saying so, spelled
//! out: what `trim` removes, how strings sort, the order of an object's keys,
//! how `JSON.parse` and `JSON.stringify` read and write, how bytes become
//! text.

use std::cmp::Ordering;
use std::collections::HashMap;

/// What `String.prototype.trim` removes and `\s` matches: ECMAScript
/// WhiteSpace and LineTerminator. Not the same set as `char::is_whitespace`
/// (JavaScript includes U+FEFF and leaves out U+0085).
pub fn is_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `s.trim()`
pub fn trim(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.trimStart()`
pub fn trim_start(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

/// `buffer.toString("utf8")` and `readFileSync(path, "utf8")`: invalid
/// sequences become U+FFFD, one per maximal invalid subpart, and a leading
/// BOM is kept.
pub fn utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `text.replace(/\r\n/g, "\n")`
pub fn lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// The order of `Array.prototype.sort()` without a comparator: by UTF-16
/// code units.
pub fn cmp_utf16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `[...xs].sort()`
pub fn sort(xs: &mut [String]) {
    xs.sort_by(|a, b| cmp_utf16(a, b));
}

/// Names every object answers to through `Object.prototype`. A dotenv scanner
/// that collects values with `parsed[name] = parsed[name] || []` finds the
/// inherited member there and fails with a TypeError.
pub fn is_object_member(name: &str) -> bool {
    matches!(
        name,
        "constructor"
            | "toString"
            | "toLocaleString"
            | "valueOf"
            | "hasOwnProperty"
            | "isPrototypeOf"
            | "propertyIsEnumerable"
            | "__proto__"
            | "__defineGetter__"
            | "__defineSetter__"
            | "__lookupGetter__"
            | "__lookupSetter__"
    )
}

/// The number a key stands for if JavaScript treats it as an array index
/// ("0", "7", "4294967294"; not "07", not "-1").
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    key.parse::<u64>().ok().filter(|n| *n <= 4_294_967_294).map(|n| n as u32)
}

/// A JavaScript object used as a map from strings: keys that are array
/// indices come first, in numeric order, then the others in the order they
/// were first set. Setting an existing key keeps its place.
#[derive(Clone, Debug, PartialEq)]
pub struct Object<V> {
    entries: Vec<Option<(String, V)>>,
    index: HashMap<String, usize>,
}

impl<V> Default for Object<V> {
    fn default() -> Self {
        Object { entries: Vec::new(), index: HashMap::new() }
    }
}

impl<V> Object<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&V> {
        self.index.get(key).and_then(|at| self.entries[*at].as_ref()).map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        let at = *self.index.get(key)?;
        self.entries[at].as_mut().map(|(_, v)| v)
    }

    pub fn has(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// `object[key] = value`
    pub fn set(&mut self, key: &str, value: V) {
        match self.index.get(key) {
            Some(at) => self.entries[*at] = Some((key.to_string(), value)),
            None => {
                self.index.insert(key.to_string(), self.entries.len());
                self.entries.push(Some((key.to_string(), value)));
            }
        }
    }

    /// `delete object[key]`
    pub fn delete(&mut self, key: &str) {
        if let Some(at) = self.index.remove(key) {
            self.entries[at] = None;
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// `Object.entries(object)`, in JavaScript's order.
    pub fn entries(&self) -> Vec<(&str, &V)> {
        let mut indices: Vec<(u32, &str, &V)> = Vec::new();
        let mut names: Vec<(&str, &V)> = Vec::new();
        for (key, value) in self.entries.iter().flatten() {
            match array_index(key) {
                Some(n) => indices.push((n, key, value)),
                None => names.push((key, value)),
            }
        }
        indices.sort_by_key(|(n, _, _)| *n);
        indices.into_iter().map(|(_, k, v)| (k, v)).chain(names).collect()
    }

    /// `Object.keys(object)`
    pub fn keys(&self) -> Vec<String> {
        self.entries().into_iter().map(|(k, _)| k.to_string()).collect()
    }
}

/// A JSON value as `JSON.parse` gives it, for files the TypeScript reads,
/// changes and writes back whole (the sync record, package.json).
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Kept as written. Only integers `JSON.stringify` writes back unchanged
    /// are accepted; see `parse_json`.
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Object<Json>),
}

/// Why a text is not taken as JSON.
#[derive(Debug, PartialEq)]
pub enum JsonError {
    /// `JSON.parse` throws a SyntaxError.
    Syntax,
    /// Valid JSON that this reader does not reproduce the way JavaScript
    /// would write it back (a number other than a plain integer, a lone
    /// surrogate, nesting deeper than any real file).
    NotImitated,
}

/// `JSON.parse(text)`
pub fn parse_json(text: &str) -> Result<Json, JsonError> {
    let mut parser = JsonParser { bytes: text.as_bytes(), text, at: 0, depth: 0 };
    parser.blank();
    let value = parser.value()?;
    parser.blank();
    if parser.at != parser.bytes.len() {
        return Err(JsonError::Syntax);
    }
    Ok(value)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
    depth: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn word(&mut self, word: &str, value: Json) -> Result<Json, JsonError> {
        if self.bytes[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(JsonError::Syntax)
        }
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        match self.peek() {
            Some(b'n') => self.word("null", Json::Null),
            Some(b't') => self.word("true", Json::Bool(true)),
            Some(b'f') => self.word("false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(JsonError::Syntax),
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let digits = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        let int = &self.text[digits..self.at];
        if int.is_empty() || (int.len() > 1 && int.starts_with('0')) {
            return Err(JsonError::Syntax);
        }
        let mut plain = true;
        if self.peek() == Some(b'.') {
            plain = false;
            self.at += 1;
            let from = self.at;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == from {
                return Err(JsonError::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            plain = false;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let from = self.at;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
            if self.at == from {
                return Err(JsonError::Syntax);
            }
        }
        let raw = &self.text[start..self.at];
        // An integer below 2^53 is written back digit for digit; "-0" is not.
        if !plain || int.len() > 15 || raw == "-0" {
            return Err(JsonError::NotImitated);
        }
        Ok(Json::Number(raw.to_string()))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while !matches!(self.peek(), None | Some(b'"' | b'\\' | 0..=0x1f)) {
                self.at += 1;
            }
            out.push_str(&self.text[start..self.at]);
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let escape = self.peek().ok_or(JsonError::Syntax)?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            let code = if (0xd800..0xdc00).contains(&unit) {
                                // A pair of escapes is one character; a lone
                                // half has no place in a Rust string.
                                if !self.bytes[self.at..].starts_with(b"\\u") {
                                    return Err(JsonError::NotImitated);
                                }
                                self.at += 2;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err(JsonError::NotImitated);
                                }
                                0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                unit
                            };
                            out.push(char::from_u32(code).ok_or(JsonError::NotImitated)?);
                        }
                        _ => return Err(JsonError::Syntax),
                    }
                }
                _ => return Err(JsonError::Syntax),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self.bytes.get(self.at..self.at + 4).ok_or(JsonError::Syntax)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(JsonError::Syntax);
        }
        self.at += 4;
        Ok(u32::from_str_radix(std::str::from_utf8(digits).unwrap(), 16).unwrap())
    }

    fn nested(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > 200 {
            return Err(JsonError::NotImitated);
        }
        Ok(())
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.nested()?;
        self.at += 1;
        let mut items = Vec::new();
        self.blank();
        if self.peek() == Some(b']') {
            self.at += 1;
        } else {
            loop {
                self.blank();
                items.push(self.value()?);
                self.blank();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b']') => {
                        self.at += 1;
                        break;
                    }
                    _ => return Err(JsonError::Syntax),
                }
            }
        }
        self.depth -= 1;
        Ok(Json::Array(items))
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.nested()?;
        self.at += 1;
        let mut object = Object::new();
        self.blank();
        if self.peek() == Some(b'}') {
            self.at += 1;
        } else {
            loop {
                self.blank();
                if self.peek() != Some(b'"') {
                    return Err(JsonError::Syntax);
                }
                let key = self.string()?;
                self.blank();
                if self.peek() != Some(b':') {
                    return Err(JsonError::Syntax);
                }
                self.at += 1;
                self.blank();
                let value = self.value()?;
                object.set(&key, value);
                self.blank();
                match self.peek() {
                    Some(b',') => self.at += 1,
                    Some(b'}') => {
                        self.at += 1;
                        break;
                    }
                    _ => return Err(JsonError::Syntax),
                }
            }
        }
        self.depth -= 1;
        Ok(Json::Object(object))
    }
}

/// `JSON.stringify(text)` for a string.
pub fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `JSON.stringify(values)` for an array of strings.
pub fn json_strings(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|v| json_string(v)).collect();
    format!("[{}]", items.join(","))
}

/// `JSON.stringify(value, null, indent)`, `indent` being a string of at most
/// ten characters.
pub fn stringify(value: &Json, indent: &str) -> String {
    let mut out = String::new();
    write_json(value, indent, 0, &mut out);
    out
}

fn write_json(value: &Json, indent: &str, level: usize, out: &mut String) {
    let line = |out: &mut String, level: usize| {
        if !indent.is_empty() {
            out.push('\n');
            for _ in 0..level {
                out.push_str(indent);
            }
        }
    };
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => out.push_str(n),
        Json::String(s) => out.push_str(&json_string(s)),
        Json::Array(items) => {
            if items.is_empty() {
                return out.push_str("[]");
            }
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                line(out, level + 1);
                write_json(item, indent, level + 1, out);
            }
            line(out, level);
            out.push(']');
        }
        Json::Object(object) => {
            if object.len() == 0 {
                return out.push_str("{}");
            }
            out.push('{');
            for (i, (key, item)) in object.entries().into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                line(out, level + 1);
                out.push_str(&json_string(key));
                out.push(':');
                if !indent.is_empty() {
                    out.push(' ');
                }
                write_json(item, indent, level + 1, out);
            }
            line(out, level);
            out.push('}');
        }
    }
}

/// `Buffer.from(text, "hex")` as bun does it for ASCII text: pairs of hex
/// digits up to the first pair that is not one; a single digit left over is
/// dropped. `None` for text with other than ASCII in it (bun then looks at
/// the low byte of each UTF-16 unit, which is not imitated).
pub fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() {
        return None;
    }
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => out.push(high << 4 | low),
            _ => break,
        }
    }
    Some(out)
}

/// `bytes.toString("hex")`
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `Buffer.from(text, "base64")` as bun does it for ASCII text: both
/// alphabets, anything else skipped, the end at the first `=`, and a single
/// character left over dropped. `None` for text with other than ASCII in it.
pub fn base64_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 3);
    let mut bits = 0u32;
    let mut have = 0;
    for b in text.bytes() {
        let six = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        bits = bits << 6 | u32::from(six);
        have += 1;
        if have == 4 {
            out.extend_from_slice(&[(bits >> 16) as u8, (bits >> 8) as u8, bits as u8]);
            bits = 0;
            have = 0;
        }
    }
    match have {
        2 => out.push((bits >> 4) as u8),
        3 => out.extend_from_slice(&[(bits >> 10) as u8, (bits >> 2) as u8]),
        _ => {}
    }
    Some(out)
}

/// `bytes.toString("base64")`
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = u32::from(chunk[0]) << 16 | u32::from(*chunk.get(1).unwrap_or(&0)) << 8 | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_follows_javascript_not_unicode() {
        assert_eq!(trim("\u{feff} \t\r\n a b \u{a0}\u{3000}\u{2028}"), "a b");
        assert_eq!(trim("\u{85}a\u{85}"), "\u{85}a\u{85}");
        assert_eq!(trim_start(" \u{feff}a "), "a ");
    }

    /// Bytes and what bun 1.4.0 makes of them with `readFileSync(path,
    /// "utf8")` (recorded, re-encoded and printed as hex).
    #[test]
    fn utf8_replaces_invalid_bytes_the_way_bun_does() {
        let bytes: &[u8] = &[
            0xef, 0xbb, 0xbf, 0x41, 0xff, 0x42, 0xc3, 0x28, 0xe2, 0x82, 0x43, 0xf0, 0x9f, 0x92, 0x44, 0xed, 0xa0, 0x80,
            0x45, 0xf8, 0x88, 0x80, 0x80, 0x80, 0x46, 0xc0, 0xaf, 0x47, 0xe0, 0x80, 0xaf, 0x48, 0xf4, 0x90, 0x80, 0x80,
            0x49, 0xe2, 0x82,
        ];
        let expected = "efbbbf41efbfbd42efbfbd28efbfbd43efbfbd44efbfbdefbfbdefbfbd45efbfbdefbfbdefbfbdefbfbdefbfbd46efbfbdefbfbd47efbfbdefbfbdefbfbd48efbfbdefbfbdefbfbdefbfbd49efbfbd";
        assert_eq!(hex(utf8(bytes).as_bytes()), expected);
    }

    /// `Buffer.from(s, "hex")` and `Buffer.from(s, "base64")` recorded from
    /// bun 1.4.0.
    #[test]
    fn hex_and_base64_are_as_forgiving_as_bun() {
        for (text, bytes) in [("abc", "ab"), ("ab zz", "ab"), ("zzab", ""), ("ABcd", "abcd"), ("ab,cd", "ab"), (" ab", ""), ("a", ""), ("", ""), ("0x11", ""), ("ab\ncd", "ab")] {
            assert_eq!(hex(&hex_bytes(text).unwrap()), bytes, "hex {text:?}");
        }
        assert_eq!(hex_bytes("ab\u{ff43}d"), None);
        for (text, bytes) in [
            ("QUJD", "414243"),
            ("QUJD\n", "414243"),
            ("QU JD", "414243"),
            ("QUI=", "4142"),
            ("QUI", "4142"),
            ("QQ==", "41"),
            ("QQ", "41"),
            ("Q", ""),
            ("QUJD=", "414243"),
            ("QUJD==", "414243"),
            ("QU-_", "414fbf"),
            ("QU+/", "414fbf"),
            ("QU!JD", "414243"),
            ("QUJD=QUJD", "414243"),
            ("=QUJD", ""),
            ("QUI=QUJD", "4142"),
            ("QUJ", "4142"),
            ("QUJDR", "414243"),
        ] {
            assert_eq!(hex(&base64_bytes(text).unwrap()), bytes, "base64 {text:?}");
        }
        assert_eq!(base64(b"A"), "QQ==");
        assert_eq!(base64(b"AB"), "QUI=");
        assert_eq!(base64(b"ABC"), "QUJD");
        assert_eq!(base64(&[0x41, 0x4f, 0xbf]), "QU+/");
    }

    /// `JSON.stringify({b:1, 2:1, a:1, 1:1, "01":1, "-1":1, "4294967295":1,
    /// "4294967294":1, "1.5":1})` in bun.
    #[test]
    fn object_keys_come_in_javascript_order() {
        let mut object = Object::new();
        for key in ["b", "2", "a", "1", "01", "-1", "4294967295", "4294967294", "1.5"] {
            object.set(key, Json::Number("1".into()));
        }
        assert_eq!(stringify(&Json::Object(object.clone()), ""), r#"{"1":1,"2":1,"4294967294":1,"b":1,"a":1,"01":1,"-1":1,"4294967295":1,"1.5":1}"#);
        object.set("b", Json::Null);
        object.delete("a");
        object.set("a", Json::Bool(true));
        assert_eq!(object.keys(), ["1", "2", "4294967294", "b", "01", "-1", "4294967295", "1.5", "a"]);
    }

    #[test]
    fn json_round_trip() {
        let text = "{\n  \"a\": {\n    \"plain\": \"x\\ny\\u0001\\\"\",\n    \"n\": [\n      1,\n      -20,\n      true,\n      null,\n      [],\n      {}\n    ]\n  },\n  \"é\": \"\u{2028}\"\n}";
        let value = parse_json(text).unwrap();
        assert_eq!(stringify(&value, "  "), text);
        assert_eq!(parse_json(" [1 , \"\\ud83d\\ude00\\/\"] ").map(|v| stringify(&v, "")), Ok("[1,\"😀/\"]".to_string()));
        // The last of two equal keys wins, in the place of the first.
        assert_eq!(parse_json(r#"{"a":1,"b":2,"a":3}"#).map(|v| stringify(&v, "")), Ok(r#"{"a":3,"b":2}"#.to_string()));
        for bad in ["", "{", "[1,]", "{\"a\":1,}", "01", "1.", "'a'", "\"\t\"", "\u{feff}{}", "{} x", "nul", "\"\\x\"", "{a:1}", "-"] {
            assert_eq!(parse_json(bad), Err(JsonError::Syntax), "{bad:?}");
        }
        for odd in ["1.5", "1e3", "-0", "\"\\ud800\"", "12345678901234567890"] {
            assert_eq!(parse_json(odd), Err(JsonError::NotImitated), "{odd:?}");
        }
    }

    #[test]
    fn sort_is_by_utf16_units() {
        let mut names: Vec<String> = [".env.b", ".env", ".env.B", ".env_a", ".env-a", ".env.1", ".env.a.enc", ".env.a", "\u{1f600}", "\u{ff5e}"].map(String::from).to_vec();
        sort(&mut names);
        assert_eq!(names, [".env", ".env-a", ".env.1", ".env.B", ".env.a", ".env.a.enc", ".env.b", ".env_a", "\u{1f600}", "\u{ff5e}"]);
    }
}
