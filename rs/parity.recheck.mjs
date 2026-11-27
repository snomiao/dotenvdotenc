// The cases of a second independent check of the port (Rust against
// TypeScript), written against the repaired port at 2c2a075, kept as they
// were written, with the marks of what the port now hands back brought up to
// date (each such change is said where it is). rs/parity.gen.mjs adds them to
// rs/parity.json, after the first verifier's; run them from there. At
// 2c2a075 nine of the setup cases below differed (the 'stopped at …' line
// through symbolic links in the hooks path).
//
// Keys are throwaway digits repeated 64 times, written by a shell line when a
// case runs. Fixed ciphertexts (made once with @dotenvx/primitives for those
// throwaway keys) are kept in rs/parity.recheck.fixtures.json; `node
// rs/parity.gen.mjs --seal` makes the ones it lacks.
import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { encrypt, derive, scan, upsert } = createRequire(import.meta.url)("@dotenvx/primitives");
const flags = new Set(process.argv.slice(2));
const pub = (digit) => derive(String(digit).repeat(64));
const key = (digit) => `$(printf %064d 0 | tr 0 ${digit})`;
const keysFile = (map, file = ".env.keys") =>
  `{ ${Object.entries(map)
    .map(([suffix, digit]) => `printf 'DOTENV_PRIVATE_KEY${suffix}=%s\\n' "${key(digit)}"`)
    .join("; ")}; } > ${file}`;

const FIXTURES_PATH = path.join(HERE, "parity.recheck.fixtures.json");
const fixtures = JSON.parse(fs.readFileSync(FIXTURES_PATH, "utf8"));
export let sealedNew = 0;
function seal(digit, value, variant = "", fits = () => true) {
  const id = `${digit}|${variant}|${value.length > 200 ? createHash("sha256").update(value).digest("hex") : value}`;
  if (!fixtures[id]) {
    if (!flags.has("--seal")) throw new Error(`no ciphertext recorded for ${JSON.stringify(id.slice(0, 80))}: run with --seal`);
    sealedNew++;
    let made;
    do made = encrypt(pub(digit), value);
    while (!fits(made));
    fixtures[id] = made;
  }
  return fixtures[id];
}
const BANNER = [
  "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/",
  "#/            public-key encryption for .env files          /",
  "#/       [how it works](https://dotenvx.com/encryption)     /",
  "#/----------------------------------------------------------/",
].join("\n");
const suffixOf = (name) => (name === ".env" ? "" : "_" + name.slice(5).toUpperCase().replace(/[^A-Z0-9]/g, "_"));
const lf = (text) => text.replace(/\r\n/g, "\n");
function encBody(digit, plain, variant = "") {
  const text = lf(plain);
  let out = text;
  for (const [k, vs] of Object.entries(scan(text).parsed)) out = upsert(out, k, vs.map((v, i) => seal(digit, v, `${variant}${k}#${i}`)));
  return text.endsWith("\n") && !out.endsWith("\n") ? `${out}\n` : out;
}
const header = (name, digit) => `${BANNER}\nDOTENV_PUBLIC_KEY${suffixOf(name)}="${pub(digit)}"\n\n`;
const encFile = (name, digit, plain, variant = "") => `${header(name, digit)}${encBody(digit, plain, variant)}`;
const sha = (text) => createHash("sha256").update(lf(text)).digest("hex");
const hmac = (salt, text) => createHmac("sha256", salt).update(text).digest("hex").slice(0, 24);
const commentsOf = (text) => text.split("\n").filter((l) => l.trimStart().startsWith("#")).join("\n");
const SALT = "000102030405060708090a0b0c0d0e0f";
function stateText(entries) {
  const all = {};
  for (const [file, [plain, enc]] of Object.entries(entries)) {
    all[file] = { plain: sha(plain), enc: sha(enc), salt: SALT };
    all[file].keys = Object.fromEntries(Object.entries(scan(plain).parsed).map(([k, v]) => [k, hmac(SALT, JSON.stringify(v))]));
    all[file].notes = hmac(SALT, commentsOf(lf(plain)));
  }
  return JSON.stringify(all, null, 2) + "\n";
}

const IGNORE = ".env*\n!.env*.enc\n";
const INIT = "git init -q -b main";
const IDENT = "git config --global user.name Parity && git config --global user.email parity@example.com";
const PROBE = "node <REPO>/rs/parity/probe.mjs";
const GIT_LOG = "cat <HOME>/git.log 2>&1";
const LS = "ls -A | grep -v '^\\.git$' | while read -r f; do stat -c '%a %F %n' \"$f\"; done";
const FIND = "find . -path ./.git/objects -prune -o -path '*/.git/objects' -prune -o -name '*.sample' -prune -o -print | sort | while read -r f; do stat -c '%a %F %n' \"$f\"; done";

export const cases = [];
function add(name, args, o = {}) {
  const repo = o.repo === undefined ? IGNORE : o.repo;
  const files = Object.fromEntries(Object.entries({ ...(repo === false || repo === "" ? {} : { ".gitignore": repo }), ...(o.files || {}) }).filter(([, t]) => t !== undefined));
  const setup = [...(repo === false ? [] : [INIT]), ...(o.setup || [])];
  const env = { ...(o.env || {}) };
  const c = { name: `recheck2: ${name}`, args };
  if (o.stdin !== undefined) c.stdin = o.stdin;
  if (Object.keys(env).length) c.env = env;
  if (Object.keys(files).length) c.files = files;
  if (setup.length) c.setup = setup;
  c.after = [...(o.after || [LS]), ...(o.back || o.nolog ? [] : [GIT_LOG])];
  if (o.back) c.handback = o.back;
  if (o.timeout) c.timeout = o.timeout;
  if (cases.some((x) => x.name === c.name)) throw new Error("dup " + name);
  cases.push(c);
}

// ═════════ A. setup: the hooks directory git names, through symbolic links ═════════
// git prints `--path-format=absolute --git-path hooks` as a real path; the
// TypeScript's /\/\.husky\/_\/?$/ applies to that. The pre-read resolves
// core.hooksPath without following links.
const UNCAUGHT = "the TypeScript updates .gitignore and then ends in an uncaught error";
const hooksIn = (dir) => `for h in pre-commit post-merge post-checkout; do if [ -e ${dir}/$h ]; then stat -c '--- %a %F %n' ${dir}/$h; [ -f ${dir}/$h ] && cat ${dir}/$h; fi; done; true`;
const setup = (name, o = {}) => add(`setup: ${name}`, ["setup"], { repo: "", ...o, after: ["cat .gitignore 2>&1", ...(o.after || []), FIND] });

setup(".husky a link to real, core.hooksPath .husky/_, real/_/pre-commit a directory", {
  setup: ["mkdir -p real/_/pre-commit", "ln -s real .husky", "git config core.hooksPath .husky/_"], back: UNCAUGHT });
setup("core.hooksPath .husky/_, .husky/_ a link to ../hk, hk/pre-commit a directory", {
  setup: ["mkdir -p .husky hk/pre-commit", "ln -s ../hk .husky/_", "git config core.hooksPath .husky/_"], back: UNCAUGHT });
setup("core.hooksPath hooks, hooks a link to .husky/_, .husky/pre-commit a directory", {
  setup: ["mkdir -p .husky/_ .husky/pre-commit", "ln -s .husky/_ hooks", "git config core.hooksPath hooks"], back: UNCAUGHT });
setup("core.hooksPath .husky/_, .husky/_ a link to a regular file", {
  setup: ["mkdir -p .husky", "echo x > hfile", "ln -s ../hfile .husky/_", "git config core.hooksPath .husky/_"], back: UNCAUGHT });
setup("core.hooksPath absolute through a link to .husky, .husky/pre-commit a directory", {
  setup: ["mkdir -p .husky/_ .husky/pre-commit", "ln -s .husky alias", "git config core.hooksPath \"$PWD/alias/_\""], back: UNCAUGHT });
setup("the rules are there; core.hooksPath .husky/_ a link to ../hk, hk/post-merge a directory", {
  repo: IGNORE, setup: ["mkdir -p .husky hk/post-merge", "ln -s ../hk .husky/_", "git config core.hooksPath .husky/_"], after: [hooksIn("hk")],
  back: "the TypeScript writes hk/pre-commit and then ends in an uncaught error" });
setup("core.hooksPath in the user's .gitconfig through a link to a .husky/_ whose .husky/pre-commit is a directory", {
  setup: ["mkdir -p .husky/_ .husky/pre-commit", "ln -s \"$PWD/.husky/_\" \"$HOME/hk\"", "git config --global core.hooksPath '~/hk'"], back: UNCAUGHT });
setup("control: .husky a link to real, core.hooksPath .husky/_, all fine", {
  setup: ["mkdir -p real/_", "ln -s real .husky", "git config core.hooksPath .husky/_"], after: [hooksIn("real/_"), hooksIn("real")] });
setup("control: core.hooksPath hooks, a link to .husky/_, all fine", {
  setup: ["mkdir -p .husky/_", "ln -s .husky/_ hooks", "git config core.hooksPath hooks"], after: [hooksIn(".husky"), hooksIn(".husky/_")] });
setup("control: core.hooksPath .husky/_ a link to ../hk, all fine", {
  setup: ["mkdir -p .husky hk", "ln -s ../hk .husky/_", "git config core.hooksPath .husky/_"], after: [hooksIn("hk"), hooksIn(".husky")] });
// (Marked handback at 2c2a075, as more than needed: the pre-read now names
// h2/_ as git does, and the binary answers.)
setup(".husky a link to h2 without _, h2/pre-commit a directory (git names h2/_)", {
  setup: ["mkdir -p h2/pre-commit", "ln -s h2 .husky", "git config core.hooksPath .husky/_"], after: [hooksIn("h2/_")] });
setup(".husky a link to a directory, no core.hooksPath, its pre-commit a directory", {
  setup: ["mkdir -p real/pre-commit", "ln -s real .husky"], back: UNCAUGHT });
setup(".git/hooks a link to a directory whose pre-commit is a directory", {
  setup: ["mkdir -p elsewhere/pre-commit", "rm -rf .git/hooks", "ln -s ../elsewhere .git/hooks"], back: UNCAUGHT });
// (Likewise: the pre-read names the link's target, as git does.)
setup(".git/hooks a link to nowhere", {
  setup: ["rm -rf .git/hooks", "ln -s ../nowhere-hooks .git/hooks"], after: [hooksIn("nowhere-hooks")] });
setup("relative core.hooksPath with ./ and a trailing slash", {
  setup: ["git config core.hooksPath ./githooks/"], after: [hooksIn("githooks")] });
setup("relative core.hooksPath with a doubled slash, .husky//_", {
  setup: ["mkdir -p .husky/_", "git config core.hooksPath .husky//_"], after: [hooksIn(".husky")] });
setup("core.hooksPath set twice, the later one a link into .husky/_", {
  setup: ["mkdir -p .husky/_ .husky/pre-commit first", "ln -s .husky/_ second", "git config core.hooksPath first", "git config --add core.hooksPath second"], back: UNCAUGHT });

// ═════════ B. worktrees and submodules ═════════
const MAIN = `git init -q -b main main && cd main && ${IDENT} && printf '.env*\\n!.env*.enc\\n' > .gitignore && git add .gitignore && git commit -q -m init && cd ..`;
const MAIN_NORULES = `git init -q -b main main && cd main && ${IDENT} && echo x > README && git add README && git commit -q -m init && cd ..`;
add("setup: in a linked worktree, the main repository's pre-commit hook a directory", ["setup"], {
  repo: false, setup: [MAIN_NORULES, "git -C main worktree add -q ../wt", "mkdir -p main/.git/hooks/pre-commit"], env: { X_CD: "wt" },
  after: ["cat wt/.gitignore 2>&1", "ls -A main/.git/hooks | grep -v sample"], back: UNCAUGHT });
add("setup: in a linked worktree, relative core.hooksPath, its pre-commit a directory", ["setup"], {
  repo: false, setup: [MAIN_NORULES, "git -C main worktree add -q ../wt", "git -C main config core.hooksPath .githooks", "mkdir -p wt/.githooks/pre-commit"], env: { X_CD: "wt" },
  after: ["cat wt/.gitignore 2>&1", "ls -A wt/.githooks"], back: UNCAUGHT });
add("setup: in a linked worktree, relative core.hooksPath, made in the worktree", ["setup"], {
  repo: false, setup: [MAIN_NORULES, "git -C main worktree add -q ../wt", "git -C main config core.hooksPath .githooks"], env: { X_CD: "wt" },
  after: ["cat wt/.gitignore 2>&1", hooksIn("wt/.githooks"), "ls -A main"] });
add("setup: in a linked worktree, relative core.hooksPath .husky/_ where the worktree's .husky is a link", ["setup"], {
  repo: false, setup: [MAIN_NORULES, "git -C main worktree add -q ../wt", "git -C main config core.hooksPath .husky/_", "mkdir -p wt/real/_/pre-commit", "ln -s real wt/.husky"], env: { X_CD: "wt" },
  after: ["cat wt/.gitignore 2>&1"], back: UNCAUGHT });
const SUB = `git init -q -b main subsrc && (cd subsrc && ${IDENT} && echo s > s && git add s && git commit -q -m s) && git init -q -b main top && cd top && ${IDENT} && git -c protocol.file.allow=always submodule add -q ../subsrc sub && git commit -q -m sub && cd ..`;
add("setup: inside a submodule", ["setup"], {
  repo: false, setup: [SUB], env: { X_CD: "top/sub" }, after: ["cat top/sub/.gitignore 2>&1", "ls -A top/.git/modules/sub/hooks | grep -v sample"],
  back: "a submodule's configuration names core.worktree" });
add("enc: inside a submodule, no record yet", ["enc"], {
  repo: false, setup: [SUB, "printf '.env*\\n!.env*.enc\\n' > top/sub/.gitignore", "printf 'A=1\\n' > top/sub/.env.prod", keysFile({ _PROD: 1 }, "top/sub/.env.keys")], env: { X_CD: "top/sub" },
  after: ["ls -A top/sub", `cd top/sub && ${PROBE} enc .env.prod.enc .env.keys`, "ls top/.git/modules/sub/dotenvdotenc 2>&1", "ls top/.git/dotenvdotenc 2>&1"] });
add("enc: inside a submodule whose own record is a list", ["enc"], {
  repo: false, setup: [SUB, "printf '.env*\\n!.env*.enc\\n' > top/sub/.gitignore", "printf 'A=1\\n' > top/sub/.env.prod", keysFile({ _PROD: 1 }, "top/sub/.env.keys"), "mkdir -p top/.git/modules/sub/dotenvdotenc && echo '[]' > top/.git/modules/sub/dotenvdotenc/state.json"], env: { X_CD: "top/sub" },
  after: ["ls -A top/sub", "cat top/.git/modules/sub/dotenvdotenc/state.json"], back: "a sync record that is not an object" });
add("enc: in a linked worktree whose own record is a list", ["enc"], {
  repo: false, setup: [MAIN, "git -C main worktree add -q ../wt", "printf 'A=1\\n' > wt/.env.prod", keysFile({ _PROD: 1 }, "wt/.env.keys"), "mkdir -p main/.git/worktrees/wt/dotenvdotenc && echo '[]' > main/.git/worktrees/wt/dotenvdotenc/state.json"], env: { X_CD: "wt" },
  after: ["ls -A wt", "cat main/.git/worktrees/wt/dotenvdotenc/state.json"], back: "a sync record that is not an object" });
add("enc: in a linked worktree, the main repository's record a list and the worktree's none", ["enc"], {
  repo: false, setup: [MAIN, "git -C main worktree add -q ../wt", "printf 'A=1\\n' > wt/.env.prod", keysFile({ _PROD: 1 }, "wt/.env.keys"), "mkdir -p main/.git/dotenvdotenc && echo '[]' > main/.git/dotenvdotenc/state.json"], env: { X_CD: "wt" },
  after: ["ls -A wt", "cat main/.git/dotenvdotenc/state.json", "ls main/.git/worktrees/wt/dotenvdotenc", `cd wt && ${PROBE} enc .env.prod.enc .env.keys`] });
add("enc: a .git file with a relative gitdir and CRLF, its record a list", ["enc"], {
  repo: false, setup: ["git init -q -b main --separate-git-dir=gd w", "printf 'gitdir: ../gd\\r\\n' > w/.git", "printf '.env*\\n!.env*.enc\\n' > w/.gitignore", "printf 'A=1\\n' > w/.env.prod", keysFile({ _PROD: 1 }, "w/.env.keys"), "mkdir -p gd/dotenvdotenc && echo '[]' > gd/dotenvdotenc/state.json"], env: { X_CD: "w" },
  after: ["ls -A w", "cat gd/dotenvdotenc/state.json"], back: "a sync record that is not an object" });
add("enc: .git a link to a git directory elsewhere, its record a list", ["enc"], {
  repo: false, setup: ["git init -q -b main w && mv w/.git realgit && ln -s ../realgit w/.git", "printf '.env*\\n!.env*.enc\\n' > w/.gitignore", "printf 'A=1\\n' > w/.env.prod", keysFile({ _PROD: 1 }, "w/.env.keys"), "mkdir -p realgit/dotenvdotenc && echo '[]' > realgit/dotenvdotenc/state.json"], env: { X_CD: "w" },
  after: ["ls -A w", "cat realgit/dotenvdotenc/state.json"], back: "a sync record that is not an object" });
add("dec: run from a directory reached through a link, the record a list", ["dec"], {
  repo: false, setup: ["git init -q -b main real && printf '.env*\\n!.env*.enc\\n' > real/.gitignore", "mkdir -p real/sub", `printf 'A=1\\n' > real/sub/.env.prod && ${keysFile({ _PROD: 1 }, "real/sub/.env.keys")} && cd real/sub && X_CD= PARITY_GIT_LOG= sh <REPO>/rs/parity/run.sh bun <REPO>/dede.ts enc 2>/dev/null; rm .env.prod; cd ../..`, "echo '[]' > real/.git/dotenvdotenc/state.json", "ln -s real/sub link"], env: { X_CD: "link" },
  after: ["ls -A real/sub", "cat real/.git/dotenvdotenc/state.json"], back: "a sync record that is not an object" });

// ═════════ C. the large-value margin, on both sides ═════════
const WRITE = (file, expr) => `node -e 'require("fs").writeFileSync(${JSON.stringify(file)}, ${expr})'`;
const KPROD = keysFile({ _PROD: 1 });
const MARGIN = "within the margin kept from what bun's regular expressions give up on";
const BIG_AFTER = [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`, `bun <REPO>/dede.ts get BIG > got.txt 2>&1; wc -c < got.txt; rm got.txt`, `${PROBE} state`];
// The .enc keeps a quoted value quoted: span = 1 + 10 + 4*ceil((97+n)/3); 98198 is the largest n within 131,072.
for (const [label, q] of [["double quotes", '\\"'], ["single quotes", "\\x27"], ["backticks", "`"]]) {
  add(`enc, ${label}, 98198 bytes: the largest whose ciphertext stays within the margin`, ["enc"], { setup: [KPROD, WRITE(".env.prod", `"A=1\\nBIG=${q}" + "a".repeat(98198) + "${q}\\nZ=2\\n"`)], after: BIG_AFTER, timeout: 120000 });
  add(`enc, ${label}, 98199 bytes: the smallest past it`, ["enc"], { setup: [KPROD, WRITE(".env.prod", `"A=1\\nBIG=${q}" + "a".repeat(98199) + "${q}\\nZ=2\\n"`)], after: BIG_AFTER, back: MARGIN, timeout: 120000 });
}
// A bare value: 2 * (10 + 4*ceil((97+n)/3)) + 39 <= 524288 up to n = 196487.
add("enc, a bare value of 196487 bytes: the largest within the upsert margin", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=" + "a".repeat(196487) + "\\nZ=2\\n"')], after: BIG_AFTER, timeout: 120000 });
add("enc, a bare value of 196488 bytes: the smallest past it", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=" + "a".repeat(196488) + "\\nZ=2\\n"')], after: BIG_AFTER, back: MARGIN, timeout: 120000 });
// The scanner's span exactly at 131,072 (native) and 131,073 (back), in an .enc, read by get.
const Z_ENC = seal(1, "2", "zval");
const A_ENC = seal(1, "1", "aval");
// (Written by node when the case runs, rather than standing in the cases file.)
const js = (text) => JSON.stringify(text).replace(/'/g, "\\u0027");
const spanEnc = (open, close, span) => WRITE(".env.prod.enc", `${js(`${header(".env.prod", 1)}A=${A_ENC}\nBIG=${open}encrypted:`)} + "A".repeat(${span - 11}) + ${js(`${close}\nZ=${Z_ENC}\n`)}`);
for (const [label, q] of [["double", '"'], ["single", "'"], ["backtick", "`"]]) {
  add(`get Z after a ${label}-quoted stand-in ciphertext spanning 131,072 units`, ["get", "Z"], { setup: [KPROD, spanEnc(q, q, 131072)] });
  add(`get Z after a ${label}-quoted stand-in ciphertext spanning 131,073 units`, ["get", "Z"], { setup: [KPROD, spanEnc(q, q, 131073)], back: MARGIN });
}
add("get BIG, a double-quoted stand-in ciphertext of 131,072 units: cannot decrypt", ["get", "BIG"], { setup: [KPROD, spanEnc('"', '"', 131072)] });
add("status, a single-quoted value of 65,535 emoji (131,071 units)", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\x27" + "\\u{1F600}".repeat(65535) + "\\x27\\nZ=2\\n"')] });
add("status, a single-quoted value of 65,536 emoji (131,073 units)", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\x27" + "\\u{1F600}".repeat(65536) + "\\x27\\nZ=2\\n"')], back: MARGIN });
add("status, an unclosed double quote running 131,072 units to the end", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\"" + "x".repeat(131071)')] });
add("status, an unclosed double quote running 131,073 units to the end", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\"" + "x".repeat(131072)')], back: MARGIN });
add("status, export and a colon before a 131,073-unit single-quoted value", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nexport BIG: \\x27" + "x".repeat(131072) + "\\x27\\nZ=2\\n"')], back: MARGIN });
add("status, a 300,000-unit quote after a name without = or : starts nothing", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG \\x27" + "x".repeat(300000) + "\\x27\\nZ=2\\n"')] });
add("status, a 131,073-unit quote after =, a line break and spaces", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\n   \\"" + "x".repeat(131072) + "\\"\\nZ=2\\n"')], back: MARGIN });
add("status, a 131,073-unit quote after a line separator U+2028", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\u2028BIG=\\"" + "x".repeat(131072) + "\\"\\nZ=2\\n"')], back: MARGIN });
add("status, escaped quotes inside a 131,073-unit double-quoted value", ["status", ".env.prod"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\"" + "x\\\\\\"".repeat(43690) + "xx\\"\\nZ=2\\n"')], back: MARGIN });
add("get, a keys file with a quoted note spanning 131,072 units", ["get", "A"], { files: { ".env.prod.enc": `${header(".env.prod", 1)}A=${A_ENC}\n` }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(131071) + "\\"\\n"'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"] });
add("get, a keys file with a quoted note spanning 131,073 units", ["get", "A"], { files: { ".env.prod.enc": `${header(".env.prod", 1)}A=${A_ENC}\n` }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(131072) + "\\"\\n"'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"], back: MARGIN });
// A real ciphertext at 131,071 units in an .enc, decrypted; and kept by an enc that changes A only.
const BIGV = "a".repeat(98198);
const BIG_PLAIN = `A=1\nBIG="${BIGV}"\nZ=2\n`;
// (Under node, upsert cannot build its expression for a value this large, so
// these two .enc files are put together as upsert writes them under bun: each
// value replaced in place, its quotes kept. rs/parity.gen.mjs runs on node.)
const encFileOf = (name, digit, variant, lines) => `${header(name, digit)}${lines.map(([k, v, q = ""]) => `${k}=${q}${seal(digit, v, `${variant}${k}#0`)}${q}\n`).join("")}`;
const BIG_ENC = encFileOf(".env.prod", 1, "edge", [["A", "1"], ["BIG", BIGV, '"'], ["Z", "2"]]);
add("dec, an .enc with a quoted ciphertext of 131,070 characters", ["dec"], { files: { ".env.prod.enc": BIG_ENC }, setup: [KPROD], after: [LS, "wc -c < .env.prod", "sha256sum .env.prod", `${PROBE} state`] });
const BIG_PLAIN2 = `A=3\nBIG="${BIGV}"\nZ=2\n`;
add("enc, A changed, the 131,070-character ciphertext of BIG kept", ["enc"], {
  files: { ".env.prod.enc": BIG_ENC, ".env.prod": BIG_PLAIN2, "state.fixture": stateText({ ".env.prod": [BIG_PLAIN, BIG_ENC] }) },
  setup: ["mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json", KPROD],
  after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`, "grep '^BIG=' .env.prod.enc | sha256sum", "grep '^A=' .env.prod.enc | wc -c", `${PROBE} state`],
  back: "both files there and different, over 120,000 units together: the pre-read hands back a possible merge" });
const MIDV = "m".repeat(50000);
const MID_PLAIN = `A=1\nBIG="${MIDV}"\nZ=2\n`;
const MID_ENC = encFileOf(".env.prod", 1, "mid", [["A", "1"], ["BIG", MIDV, '"'], ["Z", "2"]]);
add("enc, A changed, the ciphertext of a 50,000-byte BIG kept (100,000 units together)", ["enc"], {
  files: { ".env.prod.enc": MID_ENC, ".env.prod": MID_PLAIN.replace("A=1", "A=3"), "state.fixture": stateText({ ".env.prod": [MID_PLAIN, MID_ENC] }) },
  setup: ["mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json", KPROD],
  after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`, "grep '^BIG=' .env.prod.enc | sha256sum", "grep '^A=' .env.prod.enc | wc -c", `${PROBE} state`],
  back: "both files and both sides' ciphertexts past 131,072 units: the pre-read hands back a possible merge" });
add("dec, both changed and mergeable, 100,000 units together", ["dec"], {
  files: { ".env.prod.enc": MID_ENC, ".env.prod": MID_PLAIN.replace("Z=2", "Z=9"), "state.fixture": stateText({ ".env.prod": [MID_PLAIN.replace("A=1", "A=0"), "x"] }) },
  setup: ["mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json", KPROD],
  after: [LS, "grep -v '^BIG' .env.prod", "sha256sum .env.prod", `${PROBE} state`] });

// Many short values: the "possible merge" check counts every value's ciphertext twice.
for (const n of [300, 450]) {
  const plain = Array.from({ length: n }, (_, i) => `V_${i}=v${String(i).padStart(8, "0")}\n`).join("");
  const enc = encFile(".env.prod", 1, plain, `many${n}`);
  add(`enc after one edit of a file of ${n} ten-byte values`, ["enc"], {
    files: { ".env.prod.enc": enc, ".env.prod": plain.replace("V_7=v00000007", "V_7=edited"), "state.fixture": stateText({ ".env.prod": [plain, enc] }) },
    setup: ["mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json", KPROD],
    after: [LS, `${PROBE} enc .env.prod.enc .env.keys | wc -c`, "grep -c '^V_' .env.prod.enc", `${PROBE} state`] });
  // (450 was marked handback at 2c2a075, whose pre-read counted every
  // ciphertext of both sides; a possible merge is now bounded per name.)
}

// ═════════ D. hand-back before the first write, keys and records ═════════
add("enc, a new key appended to a keys file ending in an unclosed quote of 130,950 units (plus the new key past the margin)", ["enc", ".env.stage"], {
  files: { ".env.stage": "A=1\n" }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(130950)'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"], after: [LS, "tail -c 200 .env.keys | grep -c DOTENV_PRIVATE_KEY_STAGE"],
  back: MARGIN });
add("enc, a new key appended to a keys file ending in an unclosed quote of 120,000 units", ["enc", ".env.stage"], {
  files: { ".env.stage": "A=1\n" }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(120000)'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"], after: [LS, "tail -c 200 .env.keys | wc -l", `${PROBE} enc .env.stage.enc .env.keys | cut -c1-60`] });

if (sealedNew) fs.writeFileSync(FIXTURES_PATH, JSON.stringify(fixtures, null, 1) + "\n");
