#!/usr/bin/env node
// Writes rs/parity.json, the parity cases for dede (Rust against TypeScript).
//
//   node rs/parity.gen.mjs            rewrite rs/parity.json
//   node rs/parity.gen.mjs --check    fail if rs/parity.json is out of date
//   node rs/parity.gen.mjs --seal     also make the ciphertexts that
//                                     rs/parity.fixtures.json lacks
//
// How to run the cases (from the repository root, after `bun install` and
// `cargo build --release --manifest-path rs/Cargo.toml`):
//
//   node <rustify>/templates/parity/parity.mjs --cases rs/parity.json \
//     --ts "sh rs/parity/run.sh bun dede.ts" \
//     --rs "sh rs/parity/run.sh env DOTENVDOTENC_PACKAGE_ROOT=$PWD rs/target/release/dotenvdotenc"
//   node <rustify>/templates/parity/parity.mjs --cases rs/parity.json \
//     --rs "sh rs/parity/run.sh rs/target/release/dotenvdotenc" \
//     --handback DOTENVDOTENC_PACKAGE_ROOT=dede.ts
//
// The first compares everything a case names; DOTENVDOTENC_PACKAGE_ROOT lets
// the binary hand back what it does not answer itself. The second runs the
// binary against a stand-in package and fails unless exactly the cases
// marked `handback` reached the JavaScript.
//
// rs/parity/run.sh starts the command for a case (see there): it puts the
// throwaway private keys a case asks for into the environment, and a `git`
// that notes every call in front of git, so that each case also compares
// what the two implementations asked git, in order.
//
// Secrets. Every key and value in here was made up for these cases. No
// private key stands in this file or in parity.json: a key is a digit
// repeated 64 times, written out by a shell line when the case runs.
// Ciphertext is random, so no case compares it. Reading is proven with fixed
// ciphertexts made by @dotenvx/primitives (rs/parity.fixtures.json); writing
// by rs/parity/probe.mjs, which decrypts what was written with
// @dotenvx/primitives and shows the plaintext in its place.
// rs/cross-compat.sh adds what one case cannot show: the two implementations
// taking turns on the same files.

import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { encrypt, derive, scan, upsert } = createRequire(import.meta.url)("@dotenvx/primitives");
const flags = new Set(process.argv.slice(2));

// ── keys and ciphertexts ───────────────────────────────────────────────────

/** The public key of throwaway key `digit` (the digit, 64 times). */
const pub = (digit) => derive(String(digit).repeat(64));
/** Shell: the private key `digit`. */
const key = (digit) => `$(printf %064d 0 | tr 0 ${digit})`;
/** Shell: write a keys file. `{ _LOCAL: 1, "": "2" }`; a list of digits gives a comma-separated value. */
const keysFile = (map, file = ".env.keys") =>
  `{ ${Object.entries(map)
    .map(([suffix, digits]) => `printf 'DOTENV_PRIVATE_KEY${suffix}=%s\\n' "${[].concat(digits).map(key).join(",")}"`)
    .join("; ")}; } > ${file}`;

const FIXTURES_PATH = path.join(HERE, "parity.fixtures.json");
const fixtures = JSON.parse(fs.readFileSync(FIXTURES_PATH, "utf8"));
let sealedNew = 0;
/** `value` encrypted for key `digit` by @dotenvx/primitives, the same ciphertext on every run of this script. */
function seal(digit, value, variant = "") {
  const id = `${digit}|${variant}|${value}`;
  if (!fixtures[id]) {
    if (!flags.has("--seal")) throw new Error(`no ciphertext recorded for ${JSON.stringify(id)}: run with --seal`);
    fixtures[id] = encrypt(pub(digit), value);
    sealedNew++;
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

/** The body of an .enc: `plain` with every value encrypted for key `digit`, the way dede's buildEnc writes it. */
function encBody(digit, plain, variant = "") {
  const text = lf(plain);
  let out = text;
  for (const [k, vs] of Object.entries(scan(text).parsed)) out = upsert(out, k, vs.map((v, i) => seal(digit, v, `${variant}${k}#${i}`)));
  return text.endsWith("\n") && !out.endsWith("\n") ? `${out}\n` : out;
}
/** A whole .enc file for the plaintext file `name`. */
const encFile = (name, digit, plain, variant = "") => `${BANNER}\nDOTENV_PUBLIC_KEY${suffixOf(name)}="${pub(digit)}"\n\n${encBody(digit, plain, variant)}`;

// The sync record as dede.ts's saveState writes it, with a fixed salt.
const sha = (text) => createHash("sha256").update(lf(text)).digest("hex");
const hmac = (salt, text) => createHmac("sha256", salt).update(text).digest("hex").slice(0, 24);
const commentsOf = (text) => text.split("\n").filter((l) => l.trimStart().startsWith("#")).join("\n");
const SALT = "000102030405060708090a0b0c0d0e0f";
/** `{ ".env.local": [plaintext, enc text] }` → the text of state.json */
function stateText(entries, { salt = SALT, perKey = true } = {}) {
  const all = {};
  for (const [file, [plain, enc]] of Object.entries(entries)) {
    all[file] = { plain: sha(plain), enc: sha(enc) };
    if (perKey) {
      all[file].salt = salt;
      all[file].keys = Object.fromEntries(Object.entries(scan(plain).parsed).map(([k, v]) => [k, hmac(salt, JSON.stringify(v))]));
      all[file].notes = hmac(salt, commentsOf(lf(plain)));
    }
  }
  return JSON.stringify(all, null, 2) + "\n";
}

// ── scenery ────────────────────────────────────────────────────────────────

const IGNORE = ".env*\n!.env*.enc\n";
const INIT = "git init -q -b main";
const IDENT = "git config --global user.name Parity && git config --global user.email parity@example.com";
/** Shell: put the sync record (given as the file `state.fixture`) where dede keeps it. */
const STATE = "mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json";
const PROBE = "node <REPO>/rs/parity/probe.mjs";
const GIT_LOG = "cat <HOME>/git.log 2>&1";
/** What is in the directory, with modes: nothing may be left behind (temp files) or loosened. */
const LS = "ls -A | grep -v '^\\.git$' | while read -r f; do stat -c '%a %F %n' \"$f\"; done";

const cases = [];
/**
 * One case. `o.repo`: false for no repository, else the .gitignore text (default: dede's rules).
 * `o.keys`: PARITY_KEYS for the environment. `o.back`: why the case is meant to reach the JavaScript.
 */
function add(name, args, o = {}) {
  const repo = o.repo === undefined ? IGNORE : o.repo;
  const files = { ...(repo === false || repo === "" ? {} : { ".gitignore": repo }), ...(o.files || {}) };
  const setup = [...(repo === false ? [] : [INIT]), ...("state.fixture" in files ? [STATE] : []), ...(o.setup || [])];
  const env = { ...(o.keys ? { PARITY_KEYS: o.keys } : {}), ...(o.env || {}) };
  const testCase = { name, args };
  if (o.stdin !== undefined) testCase.stdin = o.stdin;
  if (Object.keys(env).length) testCase.env = env;
  if (Object.keys(files).length) testCase.files = files;
  if (setup.length) testCase.setup = setup;
  testCase.after = [...(o.after || []), GIT_LOG];
  if (o.normalize) testCase.normalize = o.normalize;
  if (o.back) testCase.handback = o.back;
  if (cases.some((c) => c.name === name)) throw new Error(`two cases named ${JSON.stringify(name)}`);
  cases.push(testCase);
}

// ── fixtures used by many cases ────────────────────────────────────────────

const LOCAL = "# api\nAPI_KEY=dummy-1\nNAME=\"hello world\"\n";
const LOCAL_ENC = encFile(".env.local", 1, LOCAL);
const PROD = "API_KEY=dummy-prod\nURL=https://example.test/x?y=1\n";
const PROD_ENC = encFile(".env.production", 2, PROD);

// ═══════════════════════════ usage ═══════════════════════════

add("usage: no arguments prints the usage", [], { repo: false });
add("usage: help", ["help"], { repo: false });
add("usage: --help", ["--help"], { repo: false });
add("usage: -h", ["-h"], { repo: false });
add("usage: help ignores what follows", ["help", "enc", "--force"], { repo: false });
add("usage: an unknown command prints the usage to stderr and exits 4", ["frobnicate"], { repo: false });
add("usage: --version is an unknown command", ["--version"], { repo: false });
add("usage: an empty first argument is an unknown command", [""], { repo: false });
add("usage: a flag in the command's place is an unknown command", ["-fk", "x"], { repo: false });
add("usage: -fk without a path, even after help", ["help", "-fk"], { repo: false });
add("usage: --env-keys-file without a path, after an unknown command", ["frobnicate", "--env-keys-file"], { repo: false });
add("usage: --key without a name, after help", ["help", "--key"], { repo: false });
add("usage: --key with a lower-case name", ["--help", "--key", "taku"], { repo: false });
add("usage: --key with a good name changes nothing for help", ["help", "--key", "TAKU_2"], { repo: false });
add("usage: help in a directory with env files", ["help"], { files: { ".env": "A=1\n", ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC } });
add("usage: DOTENVDOTENC_NO_NATIVE=1 hands help back", ["help"], { repo: false, env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });
add("usage: DOTENVDOTENC_NO_NATIVE=1 hands an unknown command back", ["frobnicate"], { repo: false, env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });

// ═══════════════════════════ get ═══════════════════════════

const RAW = [
  "A=$HOME",
  "B='$(touch pwned)'",
  "C=\"he said 'hi'\"",
  "D='she said \"yo\"'",
  "E=back\\slash",
  "F=naïve café ✓ 😀",
  'G="l1\\nl2"',
  "H=`tick`",
  "I=a=b=c",
  "J=",
  'K="two\nlines"',
  "L=first",
  "L=second",
  "M=  padded  # note",
  "",
].join("\n");
const RAW_ENC = encFile(".env.local", 1, RAW);
const K1 = keysFile({ _LOCAL: 1 });

add("get: one value, the key in .env.keys, no plaintext", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a quoted value", ["get", "NAME"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: with the plaintext beside it (bun loads .env.local)", ["get", "API_KEY"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
for (const name of ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"]) {
  add(`get: raw and unevaluated, ${name}`, ["get", name], { files: { ".env.local.enc": RAW_ENC }, setup: [K1], after: ["ls pwned 2>&1"] });
}
add("get: the key in the environment", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, keys: "_LOCAL=1" });
add("get: the key in the environment under another name", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, keys: "_SOMETHING_ELSE=1" });
add("get: the key in the environment, second of two", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, keys: "_LOCAL=2,1" });
add("get: another key in the environment and the right one in .env.keys", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], keys: "_LOCAL=2" });
add("get: only another key", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, keys: "_LOCAL=2" });
add("get: an invalid key in the environment is no key", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, keys: "_LOCAL=f" });
add("get: no key at all", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC } });
add("get: no key, for .env", ["get", "A"], { files: { ".env.enc": encFile(".env", 1, "A=1\n") } });
add("get: several keys in one .env.keys line, and a keys file with comments", ["get", "API_KEY"], {
  files: { ".env.local.enc": LOCAL_ENC },
  setup: [`{ echo '# keys'; printf 'DOTENV_PRIVATE_KEY_A="%s"\\n' "${key(3)},${key(1)}"; echo 'OTHER=x'; } > .env.keys`],
});
add("get: -fk names the keys file", ["get", "API_KEY", "-fk", "../keys/k"], { files: { ".env.local.enc": LOCAL_ENC }, setup: ["mkdir ../keys", keysFile({ _X: 1 }, "../keys/k")] });
add("get: -fk before the name", ["get", "-fk", "k", "NAME"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 1 }, "k")] });
add("get: --env-keys-file <path>", ["get", "API_KEY", "--env-keys-file", "k"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 1 }, "k")] });
add("get: --env-keys-file=<path>", ["get", "API_KEY", "--env-keys-file=k"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 1 }, "k")] });
add("get: DOTENV_KEYS_FILE", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 1 }, "k")], env: { DOTENV_KEYS_FILE: "k" } });
add("get: -fk wins over DOTENV_KEYS_FILE", ["get", "API_KEY", "-fk", "k"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 1 }, "k"), keysFile({ _X: 2 }, "other")], env: { DOTENV_KEYS_FILE: "other" } });
add("get: with -fk, ./.env.keys is not read", ["get", "API_KEY", "-fk", "k"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1, keysFile({ _X: 2 }, "k")] });
add("get: -fk to a file that is not there", ["get", "API_KEY", "-fk", "sub/missing"], { files: { ".env.local.enc": LOCAL_ENC } });
add("get: an empty --env-keys-file= is no keys file", ["get", "API_KEY", "--env-keys-file="], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: an empty DOTENV_KEYS_FILE is none", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { DOTENV_KEYS_FILE: "" } });
add("get: -fk without a path", ["get", "API_KEY", "-fk"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });

const TWO = { ".env.local.enc": LOCAL_ENC, ".env.production.enc": encFile(".env.production", 2, "API_KEY=dummy-1\nONLY=prod\n") };
const TWO_KEYS = keysFile({ _LOCAL: 1, _PRODUCTION: 2 });
add("get: the same value in two files", ["get", "API_KEY"], { files: TWO, setup: [TWO_KEYS] });
add("get: a name only one file has", ["get", "ONLY"], { files: TWO, setup: [TWO_KEYS] });
add("get: different values in two files", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS] });
add("get: a file argument picks one", ["get", "API_KEY", ".env.production"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS] });
add("get: the file named by its .enc", ["get", "API_KEY", ".env.local.enc"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS] });
add("get: two file arguments that differ", ["get", "API_KEY", ".env.production", "./.env.local"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS] });
add("get: the same file named twice", ["get", "API_KEY", ".env.local", ".env.local.enc"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a file in another directory, its own .env.keys", ["get", "API_KEY", "sub/.env.local"], { files: { "sub/.env.local.enc": LOCAL_ENC }, setup: [keysFile({ _LOCAL: 1 }, "sub/.env.keys")] });
add("get: a file in another directory does not use the keys here", ["get", "API_KEY", "sub/.env.local"], { files: { "sub/.env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: an absolute path", ["get", "API_KEY", "<CWD>/sub/../.env.local.enc"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a file that is not there", ["get", "API_KEY", ".env.staging"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a directory that is not there", ["get", "API_KEY", "nowhere/.env.local"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: not an env file", ["get", "API_KEY", "README.md"], { files: { ".env.local.enc": LOCAL_ENC, "README.md": "x\n" }, setup: [K1] });
add("get: a name that starts with .env but is no env file is passed over", ["get", "API_KEY", ".env.example", ".envrc"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: .env.keys as the file argument is passed over", ["get", "API_KEY", ".env.keys"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a flag that is no flag is taken for a file", ["get", "API_KEY", "--verbose"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: --force, --all, --quiet and -y mean nothing to it", ["get", "--force", "API_KEY", "--all", "--quiet", "-y", "--yes"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });

add("get: a name that is not there", ["get", "MISSING"], { files: TWO, setup: [TWO_KEYS] });
add("get: a name that is not there, in a named file", ["get", "MISSING", ".env.local"], { files: TWO, setup: [TWO_KEYS] });
add("get: no .enc here", ["get", "API_KEY"], { files: { ".env.local": LOCAL } });
add("get: an empty directory outside any repository", ["get", "API_KEY"], { repo: false });
add("get: outside any repository", ["get", "API_KEY"], { repo: false, files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: without a name", ["get"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: an empty name", ["get", ""], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a name that is no name", ["get", "API KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a name starting with a digit", ["get", "1A"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a name with a dot and a dash", ["get", "A.B-C"], { files: { ".env.local.enc": encFile(".env.local", 1, "A.B-C=dotted\n") }, setup: [K1] });
add("get: a name every JavaScript object has", ["get", "constructor"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], back: "the TypeScript ends in an uncaught TypeError" });

const TAMPERED = LOCAL_ENC.replace(/(API_KEY=encrypted:.{60})(.)/, (_, a, b) => a + (b === "A" ? "B" : "A"));
add("get: a damaged ciphertext", ["get", "API_KEY"], { files: { ".env.local.enc": TAMPERED }, setup: [K1] });
add("get: another value of a file with a damaged ciphertext", ["get", "NAME"], { files: { ".env.local.enc": TAMPERED }, setup: [K1] });
add("get: a ciphertext that is no base64", ["get", "A"], { files: { ".env.local.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\nA=encrypted:!!!\n` }, setup: [K1] });
add("get: a value that is not encrypted", ["get", "A"], { files: { ".env.local.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\nA=plain\n` }, setup: [K1] });
add("get: an empty value was encrypted too, and needs the key", ["get", "J"], { files: { ".env.local.enc": RAW_ENC } });
add("get: a value left empty in the .enc needs no key", ["get", "EMPTY"], { files: { ".env.local.enc": `${LOCAL_ENC}EMPTY=\nQUOTED=""\n` } });
add("get: a value left empty in quotes in the .enc", ["get", "QUOTED"], { files: { ".env.local.enc": `${LOCAL_ENC}EMPTY=\nQUOTED=""\n` } });
add("get: no header", ["get", "A"], { files: { ".env.local.enc": "A=encrypted:AAAA\n" }, setup: [K1] });
add("get: a header without the banner, unquoted", ["get", "API_KEY"], { files: { ".env.local.enc": `DOTENV_PUBLIC_KEY_LOCAL=${pub(1)}\n${encBody(1, LOCAL)}` }, setup: [K1] });
add("get: an empty .enc", ["get", "A"], { files: { ".env.local.enc": "" }, setup: [K1] });
add("get: CRLF line endings", ["get", "NAME"], { files: { ".env.local.enc": LOCAL_ENC.replace(/\n/g, "\r\n") }, setup: [K1] });
add("get: a public key among the values", ["get", "A"], { files: { ".env.local.enc": `${LOCAL_ENC}DOTENV_PUBLIC_KEY_X="${pub(2)}"\n` }, setup: [K1] });
add("get: a private key name among the values", ["get", "API_KEY"], { files: { ".env.local.enc": `${LOCAL_ENC}DOTENV_PRIVATE_KEY_X=\n` }, setup: [K1] });
add("get: the .enc is a symlink", ["get", "API_KEY"], { files: { "real.enc": LOCAL_ENC }, setup: [K1, "ln -s real.enc .env.local.enc"] });
add("get: the plaintext is a symlink, default run", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"] });
add("get: the plaintext is a symlink, named", ["get", "API_KEY", ".env.local"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"] });
add("get: the plaintext is committed, so the pair is passed over", ["get", "API_KEY"], { repo: "", files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [IDENT, "git add .env.local && git commit -q -m plain", K1] });
add("get: the .enc is a directory", ["get", "API_KEY"], { files: { ".env.local.enc/x": "" }, setup: [K1], back: "reading a directory ends the TypeScript in an uncaught EISDIR" });
add("get: a glob", ["get", "API_KEY", ".env.*"], { files: TWO, setup: [TWO_KEYS], back: "Bun.Glob does the matching" });
add("get: a glob that matches nothing", ["get", "API_KEY", "*.nothing"], { files: TWO, setup: [TWO_KEYS], back: "Bun.Glob does the matching" });
add("get: DOTENVDOTENC_NO_NATIVE=1", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });

// ═══════════════════════════ the .env files bun loads ═══════════════════════════
//
// The published dede is run by bun, which loads `.env*` files of the current
// directory into the environment before the program starts. A keys file
// named that way shows in the message about a missing key, which makes the
// value bun read visible.

const NO_KEY = { ".env.local.enc": LOCAL_ENC };
const bunEnv = (name, files, o = {}) => add(`bun env: ${name}`, ["get", "API_KEY"], { ...o, files: { ...NO_KEY, ...files } });
bunEnv("DOTENV_KEYS_FILE in .env", { ".env": "DOTENV_KEYS_FILE=from-env-file\n" });
bunEnv("in .env.local", { ".env.local": "DOTENV_KEYS_FILE=from-local\n" });
bunEnv("in .env.development", { ".env.development": "DOTENV_KEYS_FILE=from-development\n" });
bunEnv("in .env.development.local", { ".env.development.local": "DOTENV_KEYS_FILE=from-development-local\n" });
bunEnv(".env.production is not read", { ".env.production": "DOTENV_KEYS_FILE=from-production\n" });
bunEnv(".env.keys and .env.test are not read", { ".env.test": "DOTENV_KEYS_FILE=from-test\n", ".env.keys": "DOTENV_KEYS_FILE=from-keys\n" });
const FOUR = { ".env": "DOTENV_KEYS_FILE=from-env-file\nT_ONE=env\n", ".env.development": "DOTENV_KEYS_FILE=from-development\nT_TWO=development\n", ".env.local": "DOTENV_KEYS_FILE=from-local\nT_THREE=local\n", ".env.development.local": "DOTENV_KEYS_FILE=from-development-local\n" };
bunEnv(".env.development.local wins", FOUR);
bunEnv(".env.local wins over .env.development and .env", { ".env": FOUR[".env"], ".env.development": FOUR[".env.development"], ".env.local": FOUR[".env.local"] });
bunEnv(".env.development wins over .env", { ".env": FOUR[".env"], ".env.development": FOUR[".env.development"] });
bunEnv("the real environment wins", FOUR, { env: { DOTENV_KEYS_FILE: "from-the-environment" } });
bunEnv("a variable set to nothing in the real environment stays so", FOUR, { env: { DOTENV_KEYS_FILE: "" } });
bunEnv("-fk wins over the files", FOUR, { });
cases[cases.length - 1].args.push("-fk", "from-the-flag");
bunEnv("NODE_ENV=production reads .env.production.local, .env.local, .env.production, .env", { ...FOUR, ".env.production": "DOTENV_KEYS_FILE=from-production\n", ".env.production.local": "DOTENV_KEYS_FILE=from-production-local\n" }, { env: { NODE_ENV: "production" } });
bunEnv("NODE_ENV=production, .env.local over .env.production", { ".env": FOUR[".env"], ".env.development.local": FOUR[".env.development.local"], ".env.local": FOUR[".env.local"], ".env.production": "DOTENV_KEYS_FILE=from-production\n" }, { env: { NODE_ENV: "production" } });
bunEnv("NODE_ENV=production, .env.production over .env", { ".env": FOUR[".env"], ".env.development": FOUR[".env.development"], ".env.production": "DOTENV_KEYS_FILE=from-production\n" }, { env: { NODE_ENV: "production" } });
bunEnv("NODE_ENV=test reads .env.test.local, .env.test, .env and not .env.local", { ...FOUR, ".env.test": "DOTENV_KEYS_FILE=from-test\n", ".env.test.local": "DOTENV_KEYS_FILE=from-test-local\n" }, { env: { NODE_ENV: "test" } });
bunEnv("NODE_ENV=test, .env.test over .env; .env.local is not read", { ".env": FOUR[".env"], ".env.local": FOUR[".env.local"], ".env.test": "DOTENV_KEYS_FILE=from-test\n" }, { env: { NODE_ENV: "test" } });
bunEnv("NODE_ENV=test, only .env.local", { ".env.local": FOUR[".env.local"] }, { env: { NODE_ENV: "test" } });
bunEnv("NODE_ENV=staging reads the development files", { ...FOUR, ".env.staging": "DOTENV_KEYS_FILE=from-staging\n" }, { env: { NODE_ENV: "staging" } });
bunEnv("NODE_ENV=development", FOUR, { env: { NODE_ENV: "development" } });
bunEnv("an empty NODE_ENV", FOUR, { env: { NODE_ENV: "" } });
bunEnv("NODE_ENV set in .env does not change which files are read", { ".env": "NODE_ENV=production\n", ".env.production": "DOTENV_KEYS_FILE=from-production\n", ".env.development": "DOTENV_KEYS_FILE=from-development\n" });
bunEnv("files in the parent directory are not read", { "../.env": "DOTENV_KEYS_FILE=from-parent\n" });

for (const [what, line, back] of [
  ["a bare value", "DOTENV_KEYS_FILE=dir/keys.txt"],
  ["spaces around a bare value", "DOTENV_KEYS_FILE= \t dir/k \t "],
  ["a bare value with a space inside", "DOTENV_KEYS_FILE=my keys"],
  ["a comment after a bare value", "DOTENV_KEYS_FILE=dir/k # the keys"],
  ["a # glued to a bare value", "DOTENV_KEYS_FILE=dir/k#not-part"],
  ["an empty value", "DOTENV_KEYS_FILE="],
  ["only a comment as value", "DOTENV_KEYS_FILE= # nothing"],
  ["double quotes", 'DOTENV_KEYS_FILE="my keys/k #1"'],
  ["double quotes, padded inside", 'DOTENV_KEYS_FILE=" k "'],
  ["double quotes and a comment", 'DOTENV_KEYS_FILE="k" # c'],
  ["double quotes and a glued comment", 'DOTENV_KEYS_FILE="k"#c'],
  ["a single quote inside double quotes", 'DOTENV_KEYS_FILE="it\'s"'],
  ["a backtick inside double quotes", 'DOTENV_KEYS_FILE="a`b"'],
  ["single quotes", "DOTENV_KEYS_FILE='my keys/k #1'"],
  ["double quotes inside single quotes", "DOTENV_KEYS_FILE='{\"a\":1}'"],
  ["a backtick inside single quotes", "DOTENV_KEYS_FILE='a`b'"],
  ["empty double quotes", 'DOTENV_KEYS_FILE=""'],
  ["empty single quotes", "DOTENV_KEYS_FILE=''"],
  ["an equals sign in the value", "DOTENV_KEYS_FILE=a=b"],
  ["a backslash in a bare value", "DOTENV_KEYS_FILE=a\\b"],
  ["letters beyond ASCII", "DOTENV_KEYS_FILE=clés→鍵"],
  ["a tab before the quote", 'DOTENV_KEYS_FILE=\t"k"'],
  // What bun interprets, or what was not looked at closely enough to imitate.
  ["a $ in a bare value", "DOTENV_KEYS_FILE=a$b", "bun expands $b"],
  ["a $ at the end", "DOTENV_KEYS_FILE=cost$", "a $ is where bun starts to expand"],
  ["${…} in double quotes", 'DOTENV_KEYS_FILE="${HOME}/k"', "bun expands ${HOME}"],
  ["a $ in single quotes", "DOTENV_KEYS_FILE='a$b'", "bun expands even in single quotes"],
  ["an escape in double quotes", 'DOTENV_KEYS_FILE="a\\nb"', "bun unescapes \\n"],
  ["a backslash in single quotes", "DOTENV_KEYS_FILE='a\\nb'", "backslashes in quotes are not imitated"],
  ["a value over two lines", 'DOTENV_KEYS_FILE="a\nb"', "values over several lines are not imitated"],
  ["no closing quote", 'DOTENV_KEYS_FILE="a', "an open quote is not imitated"],
  ["backticks", "DOTENV_KEYS_FILE=`k`", "backtick quoting is not imitated"],
  ["a quote inside a bare value", "DOTENV_KEYS_FILE=it's", "quotes inside a bare value are not imitated"],
  ["text after the closing quote", 'DOTENV_KEYS_FILE="a"b', "text after a closing quote is not imitated"],
  ["a quote in the comment", "DOTENV_KEYS_FILE=k # it's", "quotes in a comment are not imitated"],
  ["a tab inside a bare value", "DOTENV_KEYS_FILE=a\tb", "control characters in a value are not imitated"],
  ["export", "export DOTENV_KEYS_FILE=k", "export is not imitated"],
  ["an indented line", "  DOTENV_KEYS_FILE=k", "indentation is not imitated"],
  ["a space before the equals sign", "DOTENV_KEYS_FILE =k", "spaces before = are not imitated"],
  ["a line without an equals sign", "DOTENV_KEYS_FILE", "a line without = is not imitated"],
  ["a name with a dot", "A.B=1\nDOTENV_KEYS_FILE=k", "names with . or - are not imitated"],
  ["the same name twice", "DOTENV_KEYS_FILE=k1\nDOTENV_KEYS_FILE=k2", "a name given twice is not imitated"],
  ["a byte order mark", "﻿DOTENV_KEYS_FILE=k", "a byte order mark is not imitated"],
  ["a lone carriage return", "A=1\rDOTENV_KEYS_FILE=k", "a lone carriage return is not imitated"],
  ["a variable for bun", "BUN_CONFIG_VERBOSE_FETCH=1\nDOTENV_KEYS_FILE=k", "variables that steer bun are not imitated"],
  ["NODE_OPTIONS in the file", "NODE_OPTIONS=--no-warnings\nDOTENV_KEYS_FILE=k", "variables that steer bun are not imitated"],
  ["PATH in the file", "PATH=/nowhere\nDOTENV_KEYS_FILE=k", "a PATH from a .env file is not imitated"],
]) {
  bunEnv(`${what}`, { ".env.development": `# comment\n\n${line}\nT_AFTER=1\n` }, back ? { back } : {});
  if (!back) bunEnv(`${what}, CRLF`, { ".env.development": `# comment\r\n\r\n${line}\r\nT_AFTER=1\r\n` });
}
bunEnv("no newline at the end", { ".env.development": "DOTENV_KEYS_FILE=k" });
bunEnv("an empty file", { ".env.development": "" });
bunEnv("comments and blank lines only", { ".env.development": "# a\n\n   \n\t\n#b" });
bunEnv("a file that is not UTF-8", { ".env.development": "DOTENV_KEYS_FILE=k\n" }, { setup: ["printf 'A=\\377\\n' >> .env.development"], back: "a .env file that is not UTF-8 is not imitated" });
bunEnv("a .env that is a directory", {}, { setup: ["mkdir .env.development"], back: "a .env that is not a file is not imitated" });
bunEnv("a .env that is a symlink is read", { "elsewhere": "DOTENV_KEYS_FILE=from-link\n" }, { setup: ["ln -s elsewhere .env.development"] });
bunEnv("a bunfig.toml here", { ".env": FOUR[".env"], "bunfig.toml": "env = false\n" }, { back: "bunfig.toml changes what bun does before the program starts" });
bunEnv("a .bunfig.toml in the home directory", { ".env": FOUR[".env"] }, { setup: ["echo 'telemetry = false' > ~/.bunfig.toml"], back: "bunfig.toml changes what bun does before the program starts" });
bunEnv("BUN_OPTIONS", { ".env": FOUR[".env"] }, { env: { BUN_OPTIONS: "--no-env-file" }, back: "BUN_OPTIONS changes how bun starts" });
bunEnv("NODE_OPTIONS", { ".env": FOUR[".env"] }, { env: { NODE_OPTIONS: "--no-warnings" }, back: "NODE_OPTIONS changes how bun starts" });
bunEnv("BUN_ENV", { ".env": FOUR[".env"], ".env.production": "DOTENV_KEYS_FILE=from-production\n" }, { env: { BUN_ENV: "production" }, back: "BUN_ENV is not imitated" });

// The variables of those files are in the environment of every git dede starts.
add("bun env: the variables reach git", ["get", "API_KEY"], {
  files: { ".env": "T_ONE=env\nT_TWO=env\nT_REAL=file\n", ".env.local": "T_TWO='local value'\nAPI_KEY=dummy-1\nNAME=\"hello world\"\n", ".env.local.enc": LOCAL_ENC },
  setup: [K1],
  env: { PARITY_GIT_ENV: "T_ONE T_TWO T_REAL API_KEY NAME", T_REAL: "real" },
});
// A private key in a file bun loads is a key in the environment.
add("bun env: a private key in .env.development.local opens the .enc", ["get", "API_KEY"], { files: NO_KEY, setup: [keysFile({ _ANYTHING: 1 }, ".env.development.local")] });
add("bun env: a private key in .env, which dede then refuses as an env file", ["status"], { files: { ...NO_KEY, ".env.local": LOCAL }, setup: [keysFile({ _LOCAL: 1 }, ".env")], back: "status is not ported yet" });

// ═══════════════════════════ write ═══════════════════════════

const out = { env: { TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1", PARITY_GIT_LOG: "<HOME>/git.log" }, cases };
const text = JSON.stringify(out, null, 1) + "\n";
if (/DOTENV_PRIVATE_KEY[A-Z0-9_]*["']?\s*[=:]\s*["']?[0-9a-fA-F]{64}/.test(text)) throw new Error("a private key would stand in parity.json");
if (sealedNew) {
  fs.writeFileSync(FIXTURES_PATH, JSON.stringify(fixtures, null, 1) + "\n");
  console.error(`sealed ${sealedNew} new ciphertext(s) into rs/parity.fixtures.json`);
}
const target = path.join(HERE, "parity.json");
if (flags.has("--check")) {
  if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== text) {
    console.error("rs/parity.json is not what rs/parity.gen.mjs writes; run `node rs/parity.gen.mjs`");
    process.exit(1);
  }
  console.error(`rs/parity.json is up to date (${cases.length} cases)`);
} else {
  fs.writeFileSync(target, text);
  console.error(`wrote rs/parity.json (${cases.length} cases, ${cases.filter((c) => c.handback).length} of them handed back)`);
}
