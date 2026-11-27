//! `node:path` for POSIX paths, as text: the TypeScript builds every path it
//! prints with these, so they are reproduced rather than left to the system
//! (which resolves `..` through symlinks; node does not look at the disk).

/// Resolves `.` and `..` segments and repeated slashes, without a leading or
/// trailing slash in the result.
fn normalize_segments(path: &str, allow_above_root: bool) -> String {
    let mut out: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|last| *last != "..") {
                    out.pop();
                } else if allow_above_root {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out.join("/")
}

/// `path.resolve(cwd, path)`; `cwd` is absolute.
pub fn resolve(cwd: &str, path: &str) -> String {
    let joined = if path.starts_with('/') { path.to_string() } else { format!("{cwd}/{path}") };
    format!("/{}", normalize_segments(&joined, false))
}

/// `path.normalize(path)`
fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let mut out = normalize_segments(path, !absolute);
    if out.is_empty() {
        if absolute {
            return "/".to_string();
        }
        return if trailing { "./".to_string() } else { ".".to_string() };
    }
    if trailing {
        out.push('/');
    }
    if absolute {
        format!("/{out}")
    } else {
        out
    }
}

/// `path.join(a, b)`
pub fn join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => ".".to_string(),
        (true, false) => normalize(b),
        (false, true) => normalize(a),
        (false, false) => normalize(&format!("{a}/{b}")),
    }
}

/// `path.relative(from, to)`; `cwd` is what a relative `from` or `to` (the
/// empty path included) is resolved against.
pub fn relative(cwd: &str, from: &str, to: &str) -> String {
    let from = resolve(cwd, from);
    let to = resolve(cwd, to);
    if from == to {
        return String::new();
    }
    let from_parts: Vec<&str> = from.split('/').filter(|s| !s.is_empty()).collect();
    let to_parts: Vec<&str> = to.split('/').filter(|s| !s.is_empty()).collect();
    let common = from_parts.iter().zip(&to_parts).take_while(|(a, b)| a == b).count();
    let mut out: Vec<&str> = vec![".."; from_parts.len() - common];
    out.extend(&to_parts[common..]);
    out.join("/")
}

/// `path.basename(path)`
pub fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(at) => &trimmed[at + 1..],
        None => trimmed,
    }
}

/// `path.dirname(path)`, node's own steps: the text before the last slash
/// that follows a name, whatever else is in it.
pub fn dirname(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let bytes = path.as_bytes();
    let has_root = bytes[0] == b'/';
    let mut end = None;
    let mut matched_slash = true;
    for i in (1..bytes.len()).rev() {
        if bytes[i] == b'/' {
            if !matched_slash {
                end = Some(i);
                break;
            }
        } else {
            matched_slash = false;
        }
    }
    match end {
        None if has_root => "/",
        None => ".",
        Some(1) if has_root => "//",
        Some(end) => &path[..end],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{parse_json, Json};

    fn rows(table: &Json) -> Vec<Vec<String>> {
        let Json::Array(rows) = table else { panic!("not a table") };
        rows.iter()
            .map(|row| {
                let Json::Array(cells) = row else { panic!("not a row") };
                cells.iter().map(|cell| if let Json::String(s) = cell { s.clone() } else { panic!("not text") }).collect()
            })
            .collect()
    }

    /// Inputs and results recorded from bun's `node:path` by
    /// rs/vectors.gen.mjs, with /tmp as the current directory.
    #[test]
    fn follows_node() {
        let Json::Object(vectors) = parse_json(include_str!("testdata/path.json")).unwrap() else { panic!() };
        for row in rows(vectors.get("dirname").unwrap()) {
            assert_eq!(dirname(&row[0]), row[1], "dirname({:?})", row[0]);
        }
        for row in rows(vectors.get("basename").unwrap()) {
            assert_eq!(basename(&row[0]), row[1], "basename({:?})", row[0]);
        }
        for row in rows(vectors.get("resolve").unwrap()) {
            assert_eq!(resolve(&row[0], &row[1]), row[2], "resolve({:?}, {:?})", row[0], row[1]);
        }
        for row in rows(vectors.get("join").unwrap()) {
            assert_eq!(join(&row[0], &row[1]), row[2], "join({:?}, {:?})", row[0], row[1]);
        }
        for row in rows(vectors.get("relative").unwrap()) {
            assert_eq!(relative("/tmp", &row[0], &row[1]), row[2], "relative({:?}, {:?})", row[0], row[1]);
        }
    }
}
