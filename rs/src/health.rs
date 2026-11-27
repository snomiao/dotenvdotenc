//! `dede health`: the rotation check against the rules in `.dede.yaml`.
//!
//! The TypeScript reads the file with `Bun.YAML.parse` and matches names with
//! `Bun.Glob`. Neither is ported whole. What is read here is the shape the
//! README shows, and in it only what bun certainly reads as text:
//!
//! ```yaml
//! # comment
//! rotate:
//!   - keys: TAILSCALE_AUTHKEY        # a plain word
//!     expires: 2027-01-26            # a date
//!     note: "admin console → Keys"   # quoted, without escapes
//!   - keys: ["*_TOKEN*", '*_SECRET']  # a list on one line
//!     every: 90d
//!     warn: 14d
//! ```
//!
//! and globs made of names, `*` and `?`. Anything else in the file — another
//! top-level key, a `{…}` mapping, a value over several lines, an escape in
//! quotes, a number that is not a plain integer, `true`, `null`, an empty
//! value, a tab, a file bun's parser rejects — sends the invocation back to
//! the JavaScript, as does a glob with `[`, `{`, `!`, `\` or `**`. `health`
//! only reads, so that is always possible.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::dede::{die, exists, read_file, Dede, Pair, Stop, R};
use crate::js::{self, Object};
use crate::path::{basename, dirname, join};
use crate::primitives::regex;

const DAY: i64 = 86_400_000;
const CONFIG: &str = ".dede.yaml";

/// A value of the file: text, or a whole number bun reads as a number and
/// prints back the same way.
#[derive(Clone, Debug, PartialEq)]
enum Scalar {
    Text(String),
    Number(String),
}

impl Scalar {
    /// `String(value)`
    fn text(&self) -> &str {
        match self {
            Scalar::Text(text) | Scalar::Number(text) => text,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    One(Scalar),
    List(Vec<Scalar>),
}

/// One rule as written: its fields in order.
type RawRule = Vec<(String, Value)>;

struct Rule {
    keys: Vec<String>,
    files: Vec<String>,
    every: Option<i64>,   // days
    expires: Option<i64>, // epoch ms
    warn: i64,            // days
    note: Option<String>,
}

/// What `Bun.YAML.parse` makes of the file, as far as this reader goes.
#[derive(Debug, PartialEq)]
enum Document {
    /// No `rotate` at all (an empty file, comments only).
    NoRules,
    /// `rotate:` with nothing under it: null, which is no list.
    Null,
    Rules(Vec<RawRule>),
}

fn hand_back<T>() -> Result<T, Stop> {
    Err(Stop::HandBack)
}

/// Text that stands for itself when written without quotes.
fn plain_scalar(text: &str) -> Result<Scalar, Stop> {
    let first = text.chars().next().ok_or(Stop::HandBack)?;
    let allowed = |c: char| c.is_alphanumeric() || matches!(c, ' ' | '_' | '.' | '-' | '/' | '(' | ')' | '+' | '=' | '@' | ',' | '→');
    if !(first.is_alphanumeric() || matches!(first, '_' | '.' | '/')) || !text.chars().all(allowed) || text.ends_with(' ') {
        return hand_back();
    }
    if ["true", "false", "null"].iter().any(|word| text.eq_ignore_ascii_case(word)) {
        return hand_back();
    }
    if first == '.' {
        let second = text[1..].chars().next();
        if second.is_none_or(|c| c.is_ascii_digit()) || [".inf", ".nan"].iter().any(|word| text.eq_ignore_ascii_case(word)) {
            return hand_back();
        }
    }
    if first.is_ascii_digit() {
        let digits = text.bytes().take_while(u8::is_ascii_digit).count();
        let rest = &text[digits..];
        let is_duration = matches!(rest.trim_start_matches(' '), "d" | "w" | "m" | "y");
        let is_date = text.len() == 10 && text.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() });
        let is_integer = rest.is_empty() && digits <= 15 && (digits == 1 || !text.starts_with('0'));
        if is_integer {
            return Ok(Scalar::Number(text.to_string()));
        }
        if !is_duration && !is_date {
            return hand_back();
        }
    } else if first.is_numeric() {
        return hand_back();
    }
    Ok(Scalar::Text(text.to_string()))
}

/// A quoted scalar at the start of `text`: its content and what follows.
fn quoted_scalar(text: &str) -> Result<(Scalar, &str), Stop> {
    let quote = text.chars().next().ok_or(Stop::HandBack)?;
    let (inner, rest) = text[1..].split_once(quote).ok_or(Stop::HandBack)?;
    // No escapes: `\` in double quotes, `''` in single quotes. And nothing
    // that only a YAML parser knows how to fold.
    if inner.contains('\\') || rest.starts_with(quote) || inner.chars().any(|c| c.is_control()) {
        return hand_back();
    }
    Ok((Scalar::Text(inner.to_string()), rest))
}

/// After a value: nothing, or a comment set off by a space.
fn only_comment(rest: &str) -> Result<(), Stop> {
    let trimmed = rest.trim_start_matches(' ');
    if trimmed.is_empty() || (trimmed.starts_with('#') && trimmed.len() < rest.len()) {
        Ok(())
    } else {
        hand_back()
    }
}

fn value(text: &str) -> Result<Value, Stop> {
    let text = text.trim_start_matches(' ');
    match text.chars().next() {
        None => hand_back(),
        Some('"' | '\'') => {
            let (scalar, rest) = quoted_scalar(text)?;
            only_comment(rest)?;
            Ok(Value::One(scalar))
        }
        Some('[') => {
            let mut items = Vec::new();
            let mut rest = text[1..].trim_start_matches(' ');
            if let Some(after) = rest.strip_prefix(']') {
                only_comment(after)?;
                return Ok(Value::List(items));
            }
            loop {
                let (scalar, after) = match rest.chars().next() {
                    Some('"' | '\'') => quoted_scalar(rest)?,
                    _ => {
                        let end = rest.find([',', ']']).ok_or(Stop::HandBack)?;
                        let word = rest[..end].trim_end_matches(' ');
                        // In a list a plain scalar is a single word.
                        if word.contains(' ') {
                            return hand_back();
                        }
                        (plain_scalar(word)?, &rest[end..])
                    }
                };
                items.push(scalar);
                let after = after.trim_start_matches(' ');
                if let Some(after) = after.strip_prefix(']') {
                    only_comment(after)?;
                    return Ok(Value::List(items));
                }
                rest = after.strip_prefix(',').ok_or(Stop::HandBack)?.trim_start_matches(' ');
            }
        }
        Some(_) => {
            let content = match text.find(" #") {
                Some(at) => &text[..at],
                None => text,
            };
            Ok(Value::One(plain_scalar(content.trim_end_matches(' '))?))
        }
    }
}

/// `name: value` → (name, value text)
fn field(text: &str) -> Result<(&str, &str), Stop> {
    let (name, rest) = text.split_once(':').ok_or(Stop::HandBack)?;
    let is_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !is_name || !rest.starts_with(' ') {
        return hand_back();
    }
    Ok((name, rest))
}

fn parse_document(text: &str) -> Result<Document, Stop> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.chars().any(|c| c.is_control()) {
            return hand_back(); // a tab, a lone carriage return
        }
        let content = line.trim_start_matches(' ');
        if !content.is_empty() && !content.starts_with('#') {
            lines.push(line);
        }
    }
    let Some((first, items)) = lines.split_first() else { return Ok(Document::NoRules) };
    let after = first.strip_prefix("rotate:").ok_or(Stop::HandBack)?;
    if after.trim_start_matches(' ').starts_with('[') {
        if !items.is_empty() {
            return hand_back();
        }
        return match value(after)? {
            Value::List(list) if list.is_empty() => Ok(Document::Rules(Vec::new())),
            _ => hand_back(),
        };
    }
    only_comment(after)?;
    if items.is_empty() {
        return Ok(Document::Null);
    }
    let indent = items[0].len() - items[0].trim_start_matches(' ').len();
    let mut rules: Vec<RawRule> = Vec::new();
    for line in items {
        let spaces = line.len() - line.trim_start_matches(' ').len();
        let content = &line[spaces..];
        let content = if spaces == indent && content.starts_with("- ") && !content[2..].starts_with(' ') {
            rules.push(Vec::new());
            &content[2..]
        } else if spaces == indent + 2 && !rules.is_empty() {
            content
        } else {
            return hand_back();
        };
        let (name, rest) = field(content)?;
        let rule = rules.last_mut().ok_or(Stop::HandBack)?;
        // A name given twice: bun keeps the last; where it then stands in the
        // order of the fields is not imitated.
        if rule.iter().any(|(seen, _)| seen == name) {
            return hand_back();
        }
        rule.push((name.to_string(), value(rest)?));
    }
    Ok(Document::Rules(rules))
}

/// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `new Date(ms).toISOString().slice(0, 10)` for years 0 to 9999.
fn format_date(ms: i64) -> Option<String> {
    let z = ms.div_euclid(DAY) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (0..=9999).contains(&year).then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// `Date.parse("YYYY-MM-DD")`: midnight UTC; a day up to 31 in any month
/// (the 31st of April is the 1st of May); `None` is NaN.
fn parse_date(text: &str) -> Option<i64> {
    let number = |range: std::ops::Range<usize>| text[range].parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((days_from_civil(year, month, 1) + day - 1) * DAY)
}

/// `new Bun.Glob(pattern).match(name)` for a pattern of literal characters,
/// `*` and `?`, and a name without `/`.
fn glob_match(pattern: &str, name: &str) -> Result<bool, Stop> {
    let literal = |c: char| c.is_alphanumeric() || matches!(c, '_' | '.' | '-');
    if pattern.contains("**") || !pattern.chars().all(|c| literal(c) || c == '*' || c == '?') || name.contains('/') {
        return hand_back();
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    // The usual two-pointer match with one remembered `*`.
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return Ok(false);
        }
    }
    Ok(pattern[p..].iter().all(|c| *c == '*'))
}

impl Dede {
    /// `days(value, where)`: Nd, Nw, Nm (months of 30 days), Ny.
    fn days(&self, value: &Scalar, place: &str) -> R<i64> {
        let text = js::trim(value.text());
        let digits = text.bytes().take_while(u8::is_ascii_digit).count();
        let unit = text[digits..].trim_start_matches(js::is_space);
        let factor = match unit {
            "d" => 1,
            "w" => 7,
            "m" => 30,
            "y" => 365,
            _ => 0,
        };
        if digits == 0 || factor == 0 {
            return die(format!("{place}: \"{}\" is not a duration like 90d, 12w, 6m or 1y", value.text()), 4);
        }
        // Beyond this JavaScript's arithmetic and number formatting take over.
        if digits > 6 {
            return hand_back();
        }
        Ok(text[..digits].parse::<i64>().expect("up to six digits") * factor)
    }

    /// The rules of `.dede.yaml` at the repository root; `None` without the file.
    fn load_rules(&self, top: &str) -> R<Option<Vec<Rule>>> {
        let file = join(top, CONFIG);
        if !exists(&file) {
            return Ok(None);
        }
        // A file that cannot be read ends the TypeScript in an uncaught error.
        let text = read_file(&file).map_err(|_| Stop::HandBack)?;
        let raw = match parse_document(&text)? {
            Document::NoRules => return Ok(Some(Vec::new())),
            Document::Null => return die(format!("{}: rotate must be a list of rules", self.rel(&file)), 4),
            Document::Rules(raw) => raw,
        };
        let mut rules = Vec::with_capacity(raw.len());
        for (i, fields) in raw.iter().enumerate() {
            let place = format!("{}: rotate[{i}]", self.rel(&file));
            for (name, _) in fields {
                if !matches!(name.as_str(), "keys" | "files" | "every" | "expires" | "warn" | "note") {
                    return die(format!("{place}: unknown field {name}"), 4);
                }
            }
            let get = |name: &str| fields.iter().find(|(field, _)| field == name).map(|(_, value)| value);
            let one = |name: &str| match get(name) {
                None => Ok(None),
                Some(Value::One(scalar)) => Ok(Some(scalar)),
                // A list where one value belongs is turned into text by JavaScript's rules.
                Some(Value::List(_)) => hand_back(),
            };
            let list = |name: &str| match get(name) {
                None => vec!["*".to_string()],
                Some(Value::One(scalar)) => vec![scalar.text().to_string()],
                Some(Value::List(items)) => items.iter().map(|scalar| scalar.text().to_string()).collect(),
            };
            let expires = match one("expires")? {
                None => None,
                Some(Scalar::Text(text)) if text.len() == 10 && text.bytes().enumerate().all(|(i, b)| if i == 4 || i == 7 { b == b'-' } else { b.is_ascii_digit() }) => match parse_date(text) {
                    Some(ms) => Some(ms),
                    None => return die(format!("{place}: expires \"{text}\" is not a date (YYYY-MM-DD)"), 4),
                },
                // Any other text is for `Date.parse`, in the time zone of the machine.
                Some(_) => return hand_back(),
            };
            let every = match one("every")? {
                None => None,
                Some(Scalar::Text(text)) if text == "never" => None,
                Some(scalar) => Some(self.days(scalar, &place)?),
            };
            let warn = match one("warn")? {
                None => 30,
                Some(scalar) => self.days(scalar, &place)?,
            };
            let note = one("note")?.map(|scalar| scalar.text().to_string());
            rules.push(Rule { keys: list("keys"), files: list("files"), every, expires, warn, note });
        }
        Ok(Some(rules))
    }

    /// When each line of a committed file last changed (epoch ms);
    /// uncommitted lines count as now. `None` when git cannot say.
    fn line_dates(&self, file: &str) -> R<Option<Vec<i64>>> {
        let (ok, output) = self.git(&["blame", "--line-porcelain", "-M", "-C", "--", basename(file)], dirname(file))?;
        if !ok {
            return Ok(None);
        }
        let mut dates = Vec::new();
        let mut time: i64 = 0;
        for line in output.split('\n') {
            if let Some(seconds) = line.strip_prefix("author-time ") {
                // `Number(text) * 1000`; git writes whole seconds.
                time = seconds.parse::<i64>().map_err(|_| Stop::HandBack)?.checked_mul(1000).ok_or(Stop::HandBack)?;
            } else if line.starts_with('\t') {
                dates.push(time);
            }
        }
        Ok(Some(dates))
    }

    pub fn health(&mut self, pairs: &[Pair], all: bool) -> R<bool> {
        let top = self.git_dir(&self.cwd)?;
        let Some(rules) = self.load_rules(&top)? else {
            return die(format!("no {CONFIG} at the repo root; add rotation rules there (see README: Rotation)"), 4);
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| Stop::HandBack)?.as_millis() as i64;
        let key_pattern = {
            static CELL: std::sync::OnceLock<regress::Regex> = std::sync::OnceLock::new();
            CELL.get_or_init(|| regex(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=", ""))
        };
        let (mut overdue, mut soon, mut ok, mut exempt, mut unruled) = (0, 0, 0, 0, 0);
        for pair in pairs {
            let Some(e) = self.read(&pair.enc)? else { continue };
            let text = js::lf(&e);
            let dates = self.line_dates(&pair.enc)?;
            let mut at: Object<usize> = Object::new();
            for (i, line) in text.split('\n').enumerate() {
                let Some(found) = key_pattern.find(line) else { continue };
                let key = &line[found.group(1).expect("group 1 always takes part")];
                if key.starts_with("DOTENV_PUBLIC_KEY") {
                    continue;
                }
                // Assigning to this name on a JavaScript object sets nothing.
                if key == "__proto__" {
                    return hand_back();
                }
                at.set(key, i); // last assignment wins, as in dotenv
            }
            for (key, line) in at.entries() {
                let mut rule = None;
                for candidate in &rules {
                    let mut key_fits = false;
                    for glob in &candidate.keys {
                        if glob_match(glob, key)? {
                            key_fits = true;
                            break;
                        }
                    }
                    if !key_fits {
                        continue;
                    }
                    let mut file_fits = false;
                    for glob in &candidate.files {
                        if glob_match(glob, &pair.name)? {
                            file_fits = true;
                            break;
                        }
                    }
                    if file_fits {
                        rule = Some(candidate);
                        break;
                    }
                }
                let Some(rule) = rule else {
                    unruled += 1;
                    continue;
                };
                if rule.every.is_none() && rule.expires.is_none() {
                    exempt += 1;
                    continue;
                }
                let changed = dates.as_ref().and_then(|dates| dates.get(*line).copied()).unwrap_or(now);
                let due_by = match (rule.every.map(|days| changed + days * DAY), rule.expires) {
                    (Some(a), Some(b)) => a.min(b),
                    (Some(a), None) => a,
                    (None, Some(b)) => b,
                    (None, None) => unreachable!("exempt rules were counted above"),
                };
                let left = (due_by - now).div_euclid(DAY);
                let mut why = vec![if dates.is_some() { format!("changed {}", format_date(changed).ok_or(Stop::HandBack)?) } else { "not committed".to_string() }];
                // `rule.every && …`, `rule.expires && …`: a zero is left out.
                if let Some(days) = rule.every.filter(|days| *days != 0) {
                    why.push(format!("every {days}d"));
                }
                if let Some(expires) = rule.expires.filter(|ms| *ms != 0) {
                    why.push(format!("expires {}", format_date(expires).ok_or(Stop::HandBack)?));
                }
                let note = rule.note.as_deref().filter(|note| !note.is_empty()).map(|note| format!(" — {note}")).unwrap_or_default();
                let tail = format!("{}{note}", why.join(", "));
                let enc = self.rel(&pair.enc);
                if left < 0 {
                    overdue += 1;
                    self.out.log(&format!("✗ {enc}  {key}  overdue {}d ({tail})", -left));
                } else if left <= rule.warn {
                    soon += 1;
                    self.out.log(&format!("! {enc}  {key}  due in {left}d ({tail})"));
                } else {
                    ok += 1;
                    if all {
                        self.out.log(&format!("✓ {enc}  {key}  due in {left}d ({tail})"));
                    }
                }
            }
        }
        self.log(&format!("dede health: {overdue} overdue, {soon} due soon, {ok} ok, {exempt} exempt (every: never), {unruled} without a rule"));
        Ok(overdue == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Value {
        Value::One(Scalar::Text(s.to_string()))
    }

    fn rule(fields: &[(&str, Value)]) -> RawRule {
        fields.iter().map(|(name, value)| (name.to_string(), value.clone())).collect()
    }

    fn parsed(source: &str) -> Option<Document> {
        parse_document(source).ok()
    }

    /// Sources and what `Bun.YAML.parse` (bun 1.4.0) makes of them.
    #[test]
    fn reads_what_bun_reads_as_text() {
        assert_eq!(parsed(""), Some(Document::NoRules));
        assert_eq!(parsed("# only a comment\n"), Some(Document::NoRules));
        assert_eq!(parsed("rotate:\n"), Some(Document::Null));
        assert_eq!(parsed("rotate: []\n"), Some(Document::Rules(vec![])));
        assert_eq!(parsed("\u{feff}rotate: []\n"), Some(Document::Rules(vec![])));
        assert_eq!(parsed("rotate:\n- keys: A\n"), Some(Document::Rules(vec![rule(&[("keys", text("A"))])])));
        assert_eq!(parsed("rotate:\n- keys: A\n  every: 1d\n- keys: B\n"), Some(Document::Rules(vec![rule(&[("keys", text("A")), ("every", text("1d"))]), rule(&[("keys", text("B"))])])));
        assert_eq!(
            parsed("rotate:\n  - keys: A # c\n    every: 90d # c2\n    warn: 14d\n    note: admin console keys # where\n"),
            Some(Document::Rules(vec![rule(&[("keys", text("A")), ("every", text("90d")), ("warn", text("14d")), ("note", text("admin console keys"))])]))
        );
        assert_eq!(
            parsed("rotate:\n  - keys: [\"*_A\", '*_B', C]\n    files: .env.prod\n    every: never\n"),
            Some(Document::Rules(vec![rule(&[
                ("keys", Value::List(vec![Scalar::Text("*_A".into()), Scalar::Text("*_B".into()), Scalar::Text("C".into())])),
                ("files", text(".env.prod")),
                ("every", text("never")),
            ])]))
        );
        assert_eq!(parsed("rotate:\r\n  - keys: A\r\n"), Some(Document::Rules(vec![rule(&[("keys", text("A"))])])));
        assert_eq!(parsed("rotate:  # rules\n  - keys:   A   \n\n  - keys: B\n# end\n"), Some(Document::Rules(vec![rule(&[("keys", text("A"))]), rule(&[("keys", text("B"))])])));
        assert_eq!(parsed("rotate:\n  - keys: [ A , \"B\" ] # c\n    files: []\n"), Some(Document::Rules(vec![rule(&[("keys", Value::List(vec![Scalar::Text("A".into()), Scalar::Text("B".into())])), ("files", Value::List(vec![]))])])));
        assert_eq!(
            parsed("rotate:\n  - expires: 2027-01-26\n    every: 90\n    keys: on\n    files: \"\"\n    note: 'a # b'\n"),
            Some(Document::Rules(vec![rule(&[("expires", text("2027-01-26")), ("every", Value::One(Scalar::Number("90".into()))), ("keys", text("on")), ("files", text("")), ("note", text("a # b"))])]))
        );
        assert_eq!(parsed("rotate:\n  - note: a/b (c) = d+e @f\n    keys: A,B\n"), Some(Document::Rules(vec![rule(&[("note", text("a/b (c) = d+e @f")), ("keys", text("A,B"))])])));
        assert_eq!(parsed("rotate:\n  - keys: é\n    note: admin → keys\n"), Some(Document::Rules(vec![rule(&[("keys", text("é")), ("note", text("admin → keys"))])])));
    }

    /// What bun reads as something other than the text that stands there, or
    /// rejects, or what this reader does not try.
    #[test]
    fn the_rest_goes_back() {
        for source in [
            "rotate: 5\n",
            "other: 1\n",
            "rotate:\n  - keys: A\nother: 1\n",
            "rotate:\n  - keys: TRUE\n",
            "rotate:\n  - files: null\n",
            "rotate:\n  - keys: ~\n",
            "rotate:\n  - warn: 1.5\n",
            "rotate:\n  - note: 0x10\n",
            "rotate:\n  - files: 1e3\n",
            "rotate:\n  - files: .5\n",
            "rotate:\n  - files: 007\n",
            "rotate:\n  - keys: -5\n",
            "rotate:\n  - every: 1_000d\n",
            "rotate:\n  - note: 12:30\n",
            "rotate:\n  - note: a#b\n",
            "rotate:\n  -   keys: A\n",
            "rotate:\n  - keys: A\n    keys: B\n",
            "rotate:\n  -\n",
            "rotate:\n  - foo\n",
            "rotate:\n  - keys: a b\n    note: x: y\n",
            "rotate:\n  - note: it's fine\n",
            "rotate:\n  - note: \"a\\tb\"\n",
            "rotate:\n  - note: 'it''s'\n",
            "---\nrotate: []\n",
            "rotate:\n\t- keys: A\n",
            "rotate:\n  - keys: \"A\" # c\n    note: 'x'# not comment?\n",
            "rotate:\n  - {keys: A}\n",
            "rotate:\n  - keys: A\n      every: 90d\n",
            "rotate:\n  - keys: A\n   every: 90d\n",
            "rotate:\n  - keys:\n    note: x\n",
            "rotate:\n  - keys: *_TOKEN\n",
            "rotate:\n  - note: |\n      text\n",
            "rotate:\n  - keys: [A, [B]]\n",
            "rotate:\n  - keys: [A\n",
            "rotate:\n  - keys: A\nrotate:\n  - keys: B\n",
        ] {
            assert_eq!(parsed(source), None, "{source:?}");
        }
    }

    /// `new Bun.Glob(pattern).match(name)` recorded from bun 1.4.0: each
    /// pattern with the names it matches among `NAMES`.
    #[test]
    fn globs_follow_bun() {
        const NAMES: [&str; 19] = ["", "A", "AB", "ABC", "A.B", "AxB", "A-B", "A_TOKEN", "X_TOKEN_Y", "_TOKEN", ".env", ".env.local", ".env.prod.local", "a", "ab", "aXbY", "xaybz", "é", "😀"];
        let recorded: [(&str, &[&str]); 16] = [
            ("*", &NAMES),
            ("?", &["A", "a", "é", "😀"]),
            ("A*", &["A", "AB", "ABC", "A.B", "AxB", "A-B", "A_TOKEN"]),
            ("*A", &["A"]),
            ("*_TOKEN*", &["A_TOKEN", "X_TOKEN_Y", "_TOKEN"]),
            ("A?C", &["ABC"]),
            ("A.B", &["A.B"]),
            ("A-B", &["A-B"]),
            (".env*", &[".env", ".env.local", ".env.prod.local"]),
            (".env.*", &[".env.local", ".env.prod.local"]),
            ("*.local", &[".env.local", ".env.prod.local"]),
            ("", &[""]),
            ("a", &["a"]),
            ("*a*b*", &["ab", "aXbY", "xaybz"]),
            ("??", &["AB", "ab"]),
            (".env", &[".env"]),
        ];
        for (pattern, expected) in recorded {
            let matched: Vec<&str> = NAMES.iter().copied().filter(|name| glob_match(pattern, name).unwrap()).collect();
            assert_eq!(matched, expected, "{pattern:?}");
        }
        for pattern in ["**", "A**", "[AB]", "{A,B}", "!A", "A\\*", "a/b", "A B"] {
            assert!(glob_match(pattern, "A").is_err(), "{pattern:?}");
        }
    }

    /// `Date.parse` and `toISOString` recorded from bun 1.4.0.
    #[test]
    fn dates_follow_javascript() {
        for (text, ms) in [
            ("2027-01-26", Some(1_800_921_600_000)),
            ("2027-02-29", Some(1_803_859_200_000)),
            ("2028-02-29", Some(1_835_395_200_000)),
            ("2027-02-30", Some(1_803_945_600_000)),
            ("2027-04-31", Some(1_809_129_600_000)),
            ("2027-13-01", None),
            ("2027-00-10", None),
            ("2027-01-00", None),
            ("2027-01-32", None),
            ("0000-01-01", Some(-62_167_219_200_000)),
            ("9999-12-31", Some(253_402_214_400_000)),
            ("1970-01-01", Some(0)),
            ("1969-12-31", Some(-86_400_000)),
        ] {
            assert_eq!(parse_date(text), ms, "{text}");
        }
        assert_eq!(format_date(0).as_deref(), Some("1970-01-01"));
        assert_eq!(format_date(1_800_921_600_000).as_deref(), Some("2027-01-26"));
        assert_eq!(format_date(1_800_921_600_000 + DAY - 1).as_deref(), Some("2027-01-26"));
        assert_eq!(format_date(-1).as_deref(), Some("1969-12-31"));
        assert_eq!(format_date(-62_167_219_200_000).as_deref(), Some("0000-01-01"));
        assert_eq!(format_date(253_402_214_400_000).as_deref(), Some("9999-12-31"));
        assert_eq!(format_date(253_402_214_400_000 + DAY), None);
    }
}
