//! `dede setup`: the .gitignore rules and the hooks (a plain git hook, husky
//! in a JavaScript project without a hook manager, or a snippet to paste for
//! lefthook).
//!
//! It changes several files in turn, so everything this port does not
//! imitate has to show before the first of them: `precheck` looks at
//! package.json (which the TypeScript rewrites through `JSON.parse` and
//! `JSON.stringify`) and at the lefthook file, and `foresee_setup` at every file
//! and directory the run will read, make or replace, in the hooks directory
//! git will name (`repo::hooks`: a real path, links resolved the way git
//! resolves them, so that `/.husky/_` is stripped from it where the
//! TypeScript strips it from git's answer). Where one of them would make the
//! TypeScript end in an uncaught error after its first write (core.hooksPath
//! naming a file, a hook that is a directory or cannot be read, a hooks
//! directory that cannot be written, .husky a file), the invocation is
//! handed back before anything is written.

use std::fs;
use std::process::{Command, Stdio};

use crate::dede::{die, exists, is_symlink, lstat_mode, read_file, Dede, Stop, R};
use crate::js::{self, Json, Object};
use crate::path::join;
use crate::primitives::regex;

const IGNORE_BLOCK: &str = "# dede(dotenvdotenc): plaintext env files and private keys stay local; only .enc is committed\n.env*\n!.env*.enc\n";
const HOOK_MARK: &str = "dede guard";
const HOOK_CMD: &str = "{ if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede guard; else dede guard; fi; } || exit 1";
// After a pull or branch switch: say which files need `dede dec` (never blocks).
const NOTICE_MARK: &str = "dede status --quiet";
const NOTICE_CMD: &str = "{ if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede status --quiet; else dede status --quiet; fi; } || true";
const LEFTHOOK_FILES: [&str; 4] = ["lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml"];

/// `!value` in JavaScript, for what `JSON.parse` can give.
fn falsy(value: Option<&Json>) -> bool {
    match value {
        None | Some(Json::Null) | Some(Json::Bool(false)) => true,
        Some(Json::String(text)) => text.is_empty(),
        Some(Json::Number(number)) => number == "0",
        Some(_) => false,
    }
}

/// package.json with husky added, as the TypeScript's `setupHusky` rewrites
/// it; `HandBack` for a file whose handling there is not imitated.
fn with_husky(raw: &str) -> R<String> {
    let mut package = match js::parse_json(raw) {
        Ok(Json::Object(package)) => package,
        // Not JSON: the TypeScript ends in an uncaught SyntaxError. Not an
        // object, or a number this port would not write back the same.
        _ => return Err(Stop::HandBack),
    };
    let indent_pattern = regex(r#"^\{\r?\n([ \t]+)""#, "");
    let indent: String = match indent_pattern.find(raw) {
        // `JSON.stringify` uses at most ten characters of it.
        Some(found) => raw[found.group(1).expect("group 1 always takes part")].chars().take(10).collect(),
        None => "  ".to_string(),
    };
    // pkg.scripts ??= {}
    if matches!(package.get("scripts"), None | Some(Json::Null)) {
        package.set("scripts", Json::Object(Object::new()));
    }
    let Some(Json::Object(scripts)) = package.get_mut("scripts") else { return Err(Stop::HandBack) };
    let prepare = scripts.get("prepare").cloned();
    if falsy(prepare.as_ref()) {
        scripts.set("prepare", Json::String("husky".to_string()));
    } else {
        let Some(Json::String(prepare)) = prepare else { return Err(Stop::HandBack) };
        if regex(r"\bhusky\b", "").find(&prepare).is_none() {
            scripts.set("prepare", Json::String(format!("husky && {prepare}")));
        }
    }
    // `pkg.devDependencies?.husky`, `pkg.dependencies?.husky`
    let mut has_husky = false;
    for name in ["devDependencies", "dependencies"] {
        match package.get(name) {
            None | Some(Json::Null) => {}
            Some(Json::Object(dependencies)) => has_husky = has_husky || !falsy(dependencies.get("husky")),
            Some(_) => return Err(Stop::HandBack),
        }
    }
    if !has_husky {
        // { ...pkg.devDependencies, husky: "^9.1.7" }
        let mut dependencies = match package.get("devDependencies") {
            Some(Json::Object(dependencies)) => dependencies.clone(),
            _ => Object::new(),
        };
        dependencies.set("husky", Json::String("^9.1.7".to_string()));
        package.set("devDependencies", Json::Object(dependencies));
    }
    Ok(format!("{}\n", js::stringify(&Json::Object(package), &indent)))
}

impl Dede {
    /// Is there anything about this repository that `setup` would meet after
    /// it has started to write, and that this port does not imitate?
    fn setup_precheck(&self, top: &str) -> R<()> {
        for name in LEFTHOOK_FILES {
            let path = join(top, name);
            if exists(&path) {
                // Only the first one found is read. One that cannot be read
                // ends the TypeScript in an uncaught error.
                return read_file(&path).map(|_| ()).map_err(|_| Stop::HandBack);
            }
        }
        let package = join(top, "package.json");
        if exists(&package) {
            // Read by the TypeScript only when husky gets set up; checked
            // here whenever it exists, which is before git has been asked
            // whether that is the case.
            let raw = read_file(&package).map_err(|_| Stop::HandBack)?;
            with_husky(&raw)?;
        }
        Ok(())
    }

    /// Every file and directory the rest of `setup` will read, make or
    /// replace, looked at without changing anything: `HandBack` where the
    /// TypeScript would end in an uncaught error after a first write. It
    /// follows the run step by step and stops where the run stops with a
    /// refusal of dede's own.
    fn foresee_setup(&self, top: &str, writes_gitignore: bool) -> R<()> {
        use crate::repo::can;
        let gitignore = join(top, ".gitignore");
        if writes_gitignore {
            if is_symlink(&gitignore) {
                return Ok(()); // refused: "is a symlink"
            }
            if !can::replace(top, &gitignore) {
                return Err(Stop::HandBack);
            }
        }
        if LEFTHOOK_FILES.iter().any(|name| exists(&join(top, name))) {
            return Ok(()); // only read, and that was looked at already
        }
        let hooks = crate::repo::hooks(top, &self.env)?;
        let package = join(top, "package.json");
        let husky_dir = join(top, ".husky");
        if !hooks.path_set && !exists(&husky_dir) && exists(&package) {
            if is_symlink(&package) {
                return Ok(()); // refused: "is a symlink"
            }
            // package.json replaced; .husky made (a link to nowhere cannot
            // be) and filled.
            if !can::replace(top, &package) || is_symlink(&husky_dir) || !can::fill_new_dir() {
                return Err(Stop::HandBack);
            }
            return Ok(());
        }
        let dir = if !hooks.path_set && exists(&husky_dir) { husky_dir } else { crate::repo::husky_dir_of(&hooks.dir) };
        let mut made = false;
        for (name, mark) in [("pre-commit", HOOK_MARK), ("post-merge", NOTICE_MARK), ("post-checkout", NOTICE_MARK)] {
            let hook = join(&dir, name);
            let previous = match fs::symlink_metadata(&hook) {
                Ok(meta) if meta.file_type().is_symlink() => return Ok(()), // refused: "is a symlink"
                Ok(_) => Some(read_file(&hook).map_err(|_| Stop::HandBack)?),
                Err(_) => None,
            };
            if previous.as_ref().is_some_and(|text| text.contains(mark)) {
                continue;
            }
            if previous.as_ref().is_some_and(|text| text.starts_with("#!") && regex(r"^#!.*\b(sh|bash|zsh|dash)\b", "").find(text).is_none()) {
                return Ok(()); // refused: "is not a shell script"
            }
            made |= can::make_dir(&dir).map_err(|()| Stop::HandBack)?;
            let writable = if made { can::fill_new_dir() } else { can::create_in(&dir) };
            if !writable || (previous.is_some() && !can::replace(&dir, &hook)) {
                return Err(Stop::HandBack);
            }
        }
        Ok(())
    }

    pub fn setup(&mut self) -> R<()> {
        // It prints to standard error whatever happens.
        if !self.out.colour_is_known() {
            return Err(Stop::HandBack);
        }
        let top = self.git_dir(&self.cwd)?;
        self.setup_precheck(&top)?;
        let gitignore = join(&top, ".gitignore");
        let probe = |dede: &Dede, name: &str| dede.git(&["check-ignore", "-q", "--no-index", "--", name], &top).map(|(ok, _)| ok);
        let ok = |dede: &Dede| -> R<bool> { Ok(probe(dede, ".env.local")? && probe(dede, ".env.keys")? && probe(dede, ".env")? && !probe(dede, ".env.local.enc")? && !probe(dede, ".env.enc")?) };
        let ignored = ok(self)?;
        self.foresee_setup(&top, !ignored)?;
        if !ignored {
            let previous = self.read(&gitignore)?.unwrap_or_default();
            let text = format!(
                "{previous}{}{}{IGNORE_BLOCK}",
                if previous.is_empty() || previous.ends_with('\n') { "" } else { "\n" },
                if previous.is_empty() { "" } else { "\n" }
            );
            // Once a file has changed nothing is handed back any more. (A
            // first write that fails still is: the TypeScript ends in an
            // uncaught error there, and nothing has been printed or changed.)
            self.write_atomic(&gitignore, &text, 0o644)?;
            self.out.go_live()?;
            if !ok(self)? {
                return die(".gitignore still does not ignore .env* while keeping .env*.enc; check for conflicting rules (`git check-ignore -v .env.local.enc`)".into(), 1);
            }
            self.log("updated .gitignore: .env* ignored, .env*.enc committed");
        } else {
            self.log(".gitignore: ok");
        }

        if let Some(lefthook) = LEFTHOOK_FILES.iter().find(|name| exists(&join(&top, name))) {
            let text = read_file(&join(&top, lefthook))?;
            if text.contains(HOOK_MARK) {
                self.log(&format!("{lefthook}: dede guard already configured"));
                return Ok(());
            }
            self.log(&format!(
                "{lefthook} found; add this, then run `lefthook install`:\n\npre-commit:\n  commands:\n    dede-guard:\n      run: {HOOK_CMD}\npost-merge:\n  commands:\n    dede-status:\n      run: {NOTICE_CMD}\npost-checkout:\n  commands:\n    dede-status:\n      run: {NOTICE_CMD}\n"
            ));
            return Ok(());
        }
        // A JS repo with no hook manager yet gets husky (v9) as the default.
        let package = join(&top, "package.json");
        let hooks_path_set = !js::trim(&self.git(&["config", "core.hooksPath"], &top)?.1).is_empty();
        let husky_dir = join(&top, ".husky");
        if !hooks_path_set && !exists(&husky_dir) && exists(&package) {
            return self.setup_husky(&top, &package);
        }
        // --git-path honours core.hooksPath (incl. `~`); husky v9 points it at .husky/_ and runs .husky/<hook>.
        // A .husky/ dir whose `husky` has not run yet (no core.hooksPath) is still where the hook belongs.
        let dir = if !hooks_path_set && exists(&husky_dir) {
            husky_dir
        } else {
            crate::repo::husky_dir_of(&self.git(&["rev-parse", "--path-format=absolute", "--git-path", "hooks"], &top)?.1)
        };
        if dir.is_empty() {
            return die("cannot locate the git hooks directory".into(), 1);
        }
        self.install_hook(&dir, "pre-commit", HOOK_CMD, HOOK_MARK, "runs dede guard before each commit", false)?;
        for hook in ["post-merge", "post-checkout"] {
            self.install_hook(&dir, hook, NOTICE_CMD, NOTICE_MARK, "reports env files to decrypt after a pull or checkout", true)?;
        }
        Ok(())
    }

    fn install_hook(&mut self, dir: &str, name: &str, command: &str, mark: &str, what: &str, quiet_if_present: bool) -> R<()> {
        let hook = join(dir, name);
        let previous = self.read(&hook)?;
        if previous.as_ref().is_some_and(|text| text.contains(mark)) {
            if !quiet_if_present {
                self.log(&format!("{}: dede guard already installed", self.rel(&hook)));
            }
            return Ok(());
        }
        let has_shebang = previous.as_ref().is_some_and(|text| text.starts_with("#!"));
        if has_shebang && regex(r"^#!.*\b(sh|bash|zsh|dash)\b", "").find(previous.as_deref().unwrap_or("")).is_none() {
            return die(format!("{} is not a shell script; add `{command}` to it yourself", self.rel(&hook)), 1);
        }
        fs::create_dir_all(dir).map_err(|_| Stop::Thrown("Error"))?;
        // First thing after the shebang, so a later `exec`/`exit` in an existing hook cannot skip it.
        let (body, mode) = match &previous {
            None => (format!("#!/bin/sh\n{command}\n"), 0o755),
            Some(text) => {
                let body = if has_shebang {
                    match text.find('\n') {
                        None => format!("{text}\n{command}\n"),
                        Some(newline) => format!("{}{command}\n{}", &text[..=newline], &text[newline + 1..]),
                    }
                } else {
                    format!("{command}\n{text}")
                };
                (body, lstat_mode(&hook).map_err(|_| Stop::Thrown("Error"))?.1 & 0o777)
            }
        };
        self.write_atomic(&hook, &body, mode)?;
        self.out.go_live()?;
        self.log(&format!("{} {}: {what}", if previous.is_none() { "created" } else { "updated" }, self.rel(&hook)));
        Ok(())
    }

    fn setup_husky(&mut self, top: &str, package: &str) -> R<()> {
        let raw = read_file(package)?;
        let text = with_husky(&raw)?;
        let mode = lstat_mode(package).map_err(|_| Stop::Thrown("Error"))?.1 & 0o777;
        self.write_atomic(package, &text, mode)?;
        self.out.go_live()?;
        let husky_dir = join(top, ".husky");
        fs::create_dir_all(&husky_dir).map_err(|_| Stop::Thrown("Error"))?;
        self.write_atomic(&join(&husky_dir, "pre-commit"), &format!("{HOOK_CMD}\n"), 0o644)?;
        for hook in ["post-merge", "post-checkout"] {
            let path = join(&husky_dir, hook);
            if !exists(&path) {
                self.write_atomic(&path, &format!("{NOTICE_CMD}\n"), 0o644)?;
            }
        }
        let husky = join(&join(top, "node_modules/.bin"), "husky");
        if exists(&husky) {
            let mut command = Command::new(&husky);
            command.current_dir(top).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            self.env.apply(&mut command);
            if command.status().is_ok_and(|status| status.code() == Some(0)) {
                self.log("set up husky: .husky/pre-commit runs dede guard before each commit");
                return Ok(());
            }
        }
        self.log("set up husky in package.json and .husky/pre-commit; run `bun install` (or npm/pnpm install) to activate it");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// package.json before and after `setupHusky` of dede.ts (recorded by
    /// running its lines under bun).
    #[test]
    fn package_json_gets_husky_the_way_the_typescript_adds_it() {
        let cases = [
            ("{}", "{\n  \"scripts\": {\n    \"prepare\": \"husky\"\n  },\n  \"devDependencies\": {\n    \"husky\": \"^9.1.7\"\n  }\n}\n"),
            (
                "{\n    \"name\": \"x\",\n    \"scripts\": {\n        \"prepare\": \"build\",\n        \"test\": \"t\"\n    },\n    \"devDependencies\": {\n        \"a\": \"1\"\n    }\n}\n",
                "{\n    \"name\": \"x\",\n    \"scripts\": {\n        \"prepare\": \"husky && build\",\n        \"test\": \"t\"\n    },\n    \"devDependencies\": {\n        \"a\": \"1\",\n        \"husky\": \"^9.1.7\"\n    }\n}\n",
            ),
            (
                "{\n\t\"scripts\": {\"prepare\": \"husky install\"},\n\t\"dependencies\": {\"husky\": \"8\"}\n}",
                "{\n\t\"scripts\": {\n\t\t\"prepare\": \"husky install\"\n\t},\n\t\"dependencies\": {\n\t\t\"husky\": \"8\"\n\t}\n}\n",
            ),
            (
                "{\n             \"a\": null, \"scripts\": null, \"devDependencies\": null, \"n\": 3, \"t\": [true, false, {}, []]\n}",
                "{\n          \"a\": null,\n          \"scripts\": {\n                    \"prepare\": \"husky\"\n          },\n          \"devDependencies\": {\n                    \"husky\": \"^9.1.7\"\n          },\n          \"n\": 3,\n          \"t\": [\n                    true,\n                    false,\n                    {},\n                    []\n          ]\n}\n",
            ),
            (
                "{\"scripts\":{\"prepare\":\"\"},\"devDependencies\":{\"husky\":\"\",\"z\":\"1\"},\"2\":\"two\",\"1\":\"one\"}",
                "{\n  \"1\": \"one\",\n  \"2\": \"two\",\n  \"scripts\": {\n    \"prepare\": \"husky\"\n  },\n  \"devDependencies\": {\n    \"husky\": \"^9.1.7\",\n    \"z\": \"1\"\n  }\n}\n",
            ),
        ];
        for (before, after) in cases {
            assert_eq!(with_husky(before).ok().as_deref(), Some(after), "{before:?}");
        }
        for odd in ["[]", "{", "{\"scripts\": \"x\"}", "{\"scripts\": {\"prepare\": 1}}", "{\"devDependencies\": []}", "{\"version\": 1.5}", "null"] {
            assert!(with_husky(odd).is_err(), "{odd:?}");
        }
    }
}
