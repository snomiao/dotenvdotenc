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
  const files = Object.fromEntries(Object.entries({ ...(repo === false || repo === "" ? {} : { ".gitignore": repo }), ...(o.files || {}) }).filter(([, text]) => text !== undefined));
  const setup = [...(repo === false ? [] : [INIT]), ...("state.fixture" in files ? [STATE] : []), ...(o.setup || [])];
  const env = { ...(o.keys ? { PARITY_KEYS: o.keys } : {}), ...(o.env || {}) };
  const testCase = { name, args };
  if (o.stdin !== undefined) testCase.stdin = o.stdin;
  if (Object.keys(env).length) testCase.env = env;
  if (Object.keys(files).length) testCase.files = files;
  if (setup.length) testCase.setup = setup;
  // A case that is handed back may have asked git a few things before it
  // was (the JavaScript then asks them again), so what git was asked is only
  // compared where the binary answers.
  testCase.after = [...(o.after || []), ...(o.back ? [] : [GIT_LOG])];
  if (!testCase.after.length) delete testCase.after;
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
  ["the same name twice: the last wins", "DOTENV_KEYS_FILE=k1\nT_OTHER=1\nDOTENV_KEYS_FILE=k2"],
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
add("bun env: a private key in .env, which dede then refuses as an env file", ["status"], { files: { ...NO_KEY, ".env.local": LOCAL }, setup: [keysFile({ _LOCAL: 1 }, ".env")] });

// ═══════════════════════════ scenes: a pair and its sync record ═══════════════════════════

/** Files of a pair in a given state: plaintext, .enc and the record of the last sync (of LOCAL with LOCAL_ENC). */
const pair = (plain, enc, record = [LOCAL, LOCAL_ENC], o = {}) => ({
  ...(plain === null ? {} : { ".env.local": plain }),
  ...(enc === null ? {} : { ".env.local.enc": enc }),
  ...(record === null ? {} : { "state.fixture": stateText({ ".env.local": record }, o) }),
});
const EDITED = "# api\nAPI_KEY=dummy-2\nNAME=\"hello world\"\nNEW=added\n";
const PULLED = "# api\nAPI_KEY=dummy-1\nNAME=\"hello there\"\nEXTRA=from-enc\n";
const PULLED_ENC = encFile(".env.local", 1, PULLED);
const CLASH = "# api\nAPI_KEY=dummy-3\nNAME=\"hello world\"\n";
const CLASH_ENC = encFile(".env.local", 1, CLASH);
const SCENES = {
  "in sync": pair(LOCAL, LOCAL_ENC),
  "in sync, never recorded": pair(LOCAL, LOCAL_ENC, null),
  "in sync, CRLF plaintext": pair(LOCAL.replace(/\n/g, "\r\n"), LOCAL_ENC),
  "in sync, CRLF .enc": pair(LOCAL, LOCAL_ENC.replace(/\n/g, "\r\n")),
  "plaintext edited": pair(EDITED, LOCAL_ENC),
  "plaintext edited, comment only": pair(LOCAL.replace("# api", "# the api"), LOCAL_ENC),
  "plaintext edited, record without per-key hashes": pair(EDITED, LOCAL_ENC, [LOCAL, LOCAL_ENC], { perKey: false }),
  ".enc changed": pair(LOCAL, PULLED_ENC),
  "both changed, other keys": pair(EDITED, PULLED_ENC),
  "both changed, the same key": pair(EDITED, CLASH_ENC),
  "both changed to the same": pair(CLASH, CLASH_ENC),
  "both changed, record without per-key hashes": pair(EDITED, PULLED_ENC, [LOCAL, LOCAL_ENC], { perKey: false }),
  "both changed, comments on both sides": pair(LOCAL.replace("# api", "# mine"), encFile(".env.local", 1, LOCAL.replace("# api", "# theirs"))),
  "both changed, a comment here and a key there": pair(LOCAL.replace("# api", "# mine"), PULLED_ENC),
  "both changed, a key deleted here and one edited there": pair("# api\nNAME=\"hello world\"\n", encFile(".env.local", 1, "# api\nAPI_KEY=dummy-1\nNAME=\"hello there\"\n")),
  "both changed, a key added here and one deleted there": pair(LOCAL + "MINE=1\n", encFile(".env.local", 1, "# api\nAPI_KEY=dummy-1\n")),
  "differ, never recorded": pair(EDITED, PULLED_ENC, null),
  "differ in formatting only, never recorded": pair("# other comment\nAPI_KEY=dummy-1\nNAME=\"hello world\"\n", LOCAL_ENC, null),
  "differ, the record fits both files": pair(EDITED, PULLED_ENC, [EDITED, PULLED_ENC]),
  "many keys differ": pair("A=1\nB=1\nC=1\nD=1\nE=1\nF=1\nG=1\nH=1\nONLY_HERE=1\n", encFile(".env.local", 1, "A=2\nB=2\nC=2\nD=2\nE=2\nF=2\nG=2\nH=2\nONLY_THERE=1\n"), null),
  "no .enc yet": pair(LOCAL, null, null),
  "no plaintext": pair(null, LOCAL_ENC, null),
  "a repeated name": pair("A=1\nA=2\nB=x\n", encFile(".env.local", 1, "A=1\nA=2\nB=x\n"), null),
  "a repeated name, edited": pair("A=1\nA=3\nB=x\n", encFile(".env.local", 1, "A=1\nA=2\nB=x\n"), ["A=1\nA=2\nB=x\n", encFile(".env.local", 1, "A=1\nA=2\nB=x\n")]),
  "a name every JavaScript object has": pair("A=1\nconstructor=x\n", LOCAL_ENC, null),
  "a public key in the plaintext": pair(`DOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\nA=1\n`, LOCAL_ENC, null),
  "a private key name in the plaintext": pair("DOTENV_PRIVATE_KEY_X=not-a-key\nA=1\n", LOCAL_ENC, null),
  "a damaged ciphertext": pair(LOCAL, TAMPERED),
  "a value not encrypted in the .enc": pair(LOCAL, `${LOCAL_ENC}PLAIN=oops\n`),
  "an .enc without header": pair(LOCAL, "API_KEY=encrypted:AAAA\n"),
  "the record is not JSON": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": "{ not json" },
  "the record is an empty object": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": "{}\n" },
  "the record has other entries only": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": stateText({ "sub/.env.local": [LOCAL, LOCAL_ENC], ".env.other": [PROD, PROD_ENC] }) },
};
// Not imitated: a record that is not what dede writes.
const ODD_SCENES = {
  "the record holds a number": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": '{"x": 1.5}\n' },
  "the record is a list": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": "[]\n" },
  "the record is null": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": "null\n" },
  "the entry is a string": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": '{".env.local": "x"}\n' },
  "the entry has a list for keys": { ...pair(EDITED, LOCAL_ENC, null), "state.fixture": '{".env.local": {"plain": "x", "enc": "y", "keys": []}}\n' },
};
const ODD_RECORD = "a sync record that is not of the shape dede writes is not imitated";

// ═══════════════════════════ status ═══════════════════════════

for (const [scene, files] of Object.entries(SCENES)) add(`status: ${scene}`, ["status"], { files, setup: [K1] });
for (const [scene, files] of Object.entries(ODD_SCENES)) add(`status: ${scene}`, ["status"], { files, setup: [K1], back: ODD_RECORD });
add("status: in sync, --quiet prints nothing", ["status", "--quiet"], { files: SCENES["in sync"], setup: [K1] });
add("status: edited, --quiet still says so", ["status", "--quiet"], { files: SCENES["plaintext edited"], setup: [K1] });
add("status: no private key", ["status"], { files: SCENES["plaintext edited"] });
add("status: the key in the environment", ["status"], { files: SCENES["plaintext edited"], keys: "_LOCAL=1" });
add("status: another key only", ["status"], { files: SCENES["plaintext edited"], keys: "_LOCAL=2" });
add("status: -fk", ["status", "-fk", "k"], { files: SCENES[".enc changed"], setup: [keysFile({ _LOCAL: 1 }, "k")] });
add("status: nothing here", ["status"], {});
add("status: a named file that is not there", ["status", ".env.staging"], {});
add("status: a named file, by its .enc", ["status", ".env.local.enc"], { files: SCENES["in sync"], setup: [K1] });
add("status: not an env file", ["status", "package.json"], { files: SCENES["in sync"], setup: [K1] });
add("status: outside any repository", ["status"], { repo: false, files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("status: outside any repository, files differ", ["status"], { repo: false, files: { ".env.local": EDITED, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("status: outside any repository, nothing here", ["status"], { repo: false });
const SEVERAL = {
  ".env": "A=1\n",
  ".env.enc": encFile(".env", 1, "A=1\n"),
  ".env.local": EDITED,
  ".env.local.enc": LOCAL_ENC,
  ".env.production.enc": PROD_ENC,
  ".env.staging": "S=1\n",
  ".env.example": "API_KEY=\n",
  ".env.keys.backup": "X=1\n",
  "state.fixture": stateText({ ".env": ["A=1\n", encFile(".env", 1, "A=1\n")], ".env.local": [LOCAL, LOCAL_ENC] }),
};
const SEVERAL_KEYS = keysFile({ "": 1, _LOCAL: 1, _PRODUCTION: 2 });
add("status: several files in different states", ["status"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("status: several files, --quiet", ["status", "--quiet"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("status: two of several, named", ["status", ".env.production", ".env"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("status: one file fails, the others are still reported", ["status"], { files: { ...SEVERAL, ".env.local.enc": TAMPERED, ".env.staging.enc": "nothing\n" }, setup: [SEVERAL_KEYS] });
add("status: unmanaged files elsewhere in the repository", ["status"], {
  files: { ...SCENES["in sync"], "app/.env.prod": "X=1\n", "app/.env.local": "X=1\n", "app/.env.example": "X=\n", "app/.env.managed": "X=1\n", "app/.env.managed.enc": encFile(".env.managed", 1, "X=1\n"), "node_modules/pkg/.env.test": "X=1\n", "app/node_modules/pkg/.env.x": "X=1\n" },
  setup: [K1],
});
// The case directory as a subdirectory (`cwd/`) of a repository one level up.
const ABOVE = { "../.gitignore": `${IGNORE}/home/\n/tmp/\n/cache/\n` };
const INIT_ABOVE = "git -C .. init -q -b main";
add("status: from a subdirectory; unmanaged files anywhere in the repository", ["status"], {
  repo: false,
  files: { ...ABOVE, "../.env.root": "X=1\n", "../app/.env.prod": "X=1\n", ".env.here": "X=1\n", "deep/.env.deep": "X=1\n", ".env.local": EDITED, ".env.local.enc": LOCAL_ENC, "../record.fixture": stateText({ "cwd/.env.local": [LOCAL, LOCAL_ENC] }) },
  setup: [INIT_ABOVE, "mkdir -p ../.git/dotenvdotenc && mv ../record.fixture ../.git/dotenvdotenc/state.json", K1],
});
add("status: an unmanaged file that is not ignored", ["status"], { repo: "node_modules/\n", files: { ".env.prod": "X=1\n" } });
add("status: a committed plaintext file is public config", ["status"], { repo: "", files: { ".env.shared": "PUBLIC=1\n", ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC, ".gitignore": ".env.local\n.env.keys\n" }, setup: [IDENT, "git add .env.shared .gitignore && git commit -q -m public", K1] });
add("status: a committed plaintext file, named", ["status", ".env.shared"], { repo: "", files: { ".env.shared": "PUBLIC=1\n", ".gitignore": ".env.keys\n" }, setup: [IDENT, "git add .env.shared && git commit -q -m public"] });
add("status: the plaintext is a symlink", ["status"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"] });
add("status: the plaintext is a symlink, named", ["status", ".env.local"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"] });
add("status: the .enc is a symlink", ["status"], { files: { ".env.local": LOCAL, "elsewhere": LOCAL_ENC }, setup: [K1, "ln -s elsewhere .env.local.enc"] });
add("status: a glob", ["status", ".env.*"], { files: SEVERAL, setup: [SEVERAL_KEYS], back: "Bun.Glob does the matching" });
add("status: in a linked worktree, its own record", ["status"], {
  repo: false,
  files: { "../main/.gitignore": IGNORE, "../main/README": "x\n", ".env.local": EDITED, ".env.local.enc": LOCAL_ENC, "record.fixture": stateText({ ".env.local": [LOCAL, LOCAL_ENC] }) },
  setup: [
    IDENT,
    "cd ../main && git init -q -b main && git add . && git commit -q -m init && git worktree add -q ../wt -b side",
    // Make the case directory that worktree.
    "mv ../wt/.git ../wt/.gitignore . && pwd > /dev/null && echo \"$PWD/.git\" > ../main/.git/worktrees/wt/gitdir",
    "mkdir -p \"$(git rev-parse --git-path dotenvdotenc)\" && mv record.fixture \"$(git rev-parse --git-path dotenvdotenc)/state.json\"",
    K1,
  ],
  after: ["git rev-parse --git-path dotenvdotenc/state.json"],
});

// ═══════════════════════════ diff ═══════════════════════════

for (const scene of ["in sync", "in sync, CRLF plaintext", "plaintext edited", ".enc changed", "both changed, other keys", "differ in formatting only, never recorded", "many keys differ", "no .enc yet", "no plaintext", "a repeated name", "a repeated name, edited", "a name every JavaScript object has", "a private key name in the plaintext", "a damaged ciphertext", "an .enc without header"]) {
  add(`diff: ${scene}`, ["diff"], { files: SCENES[scene], setup: [K1] });
}
add("diff: no private key", ["diff"], { files: SCENES["plaintext edited"] });
add("diff: nothing here", ["diff"], {});
add("diff: several files", ["diff"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("diff: one named file", ["diff", ".env.local"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("diff: a named file that is not there", ["diff", ".env.nope"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("diff: outside any repository", ["diff"], { repo: false, files: { ".env.local": EDITED, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("diff: a glob", ["diff", ".env*"], { files: SEVERAL, setup: [SEVERAL_KEYS], back: "Bun.Glob does the matching" });

// ═══════════════════════════ keys ═══════════════════════════

add("keys: each .enc and where its key is", ["keys"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("keys: a key that is missing", ["keys"], { files: SEVERAL, setup: [K1] });
add("keys: no keys at all", ["keys"], { files: SEVERAL });
add("keys: from the environment", ["keys"], { files: SEVERAL, keys: "_A=1 _B=2" });
add("keys: the environment is named before the file", ["keys"], { files: SEVERAL, setup: [SEVERAL_KEYS], keys: "_PRODUCTION=2" });
add("keys: -fk", ["keys", "-fk", "../k"], { files: SEVERAL, setup: [keysFile({ _X: 2 }, "../k")] });
add("keys: DOTENV_KEYS_FILE", ["keys"], { files: SEVERAL, setup: ["mkdir sub", keysFile({ _X: 1 }, "sub/k")], env: { DOTENV_KEYS_FILE: "sub/k" } });
add("keys: named files", ["keys", ".env.production", ".env.local.enc"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("keys: a named file that is not there", ["keys", ".env.nope"], { files: SEVERAL, setup: [SEVERAL_KEYS] });
add("keys: nothing here", ["keys"], {});
add("keys: outside any repository", ["keys"], { repo: false, files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("keys: a public key named in the environment counts as held", ["keys"], { files: SEVERAL, env: { DOTENV_PUBLIC_KEY_PRODUCTION: pub(2) } });
add("keys: an .enc without header", ["keys"], { files: { ".env.a.enc": encFile(".env.a", 1, "A=1\n"), ".env.b.enc": "B=1\n", ".env.c.enc": encFile(".env.c", 1, "C=1\n") }, setup: [K1] });
add("keys: CRLF .enc", ["keys"], { files: { ".env.local.enc": LOCAL_ENC.replace(/\n/g, "\r\n") }, setup: [K1] });
add("keys: the .enc is a symlink", ["keys"], { files: { "elsewhere": LOCAL_ENC }, setup: [K1, "ln -s elsewhere .env.local.enc"] });
add("keys: .env.keys is a link to another checkout's", ["keys"], { files: SEVERAL, setup: ["mkdir ../other", keysFile({ _LOCAL: 1, "": 1 }, "../other/.env.keys"), "ln -s ../other/.env.keys .env.keys"] });
add("keys: .env.keys is a link to nowhere", ["keys"], { files: SEVERAL, setup: ["ln -s ../other/.env.keys .env.keys"], back: "the TypeScript ends in an uncaught ENOENT" });
add("keys: a glob", ["keys", ".env.*"], { files: SEVERAL, setup: [SEVERAL_KEYS], back: "Bun.Glob does the matching" });

// The key tree: .env.keys.<name>.enc files that held keys open.
const TEAM_KEYS = encFile(".env.keys.team", 1, "# team keys\nDOTENV_PRIVATE_KEY_PRODUCTION=PLACEHOLDER_2\nDOTENV_PRIVATE_KEY_DEEP=PLACEHOLDER_3\n");
const TREE = {
  ".env.local.enc": LOCAL_ENC,
  ".env.production.enc": PROD_ENC,
  ".env.deep.enc": encFile(".env.deep", 4, "DEEP=down\n"),
};
/** Shell: an .env.keys.<name>.enc, encrypted for key `digit`, holding the given private keys. Made when the case runs, by the package. */
const treeNode = (name, digit, map, dir = ".") =>
  `node -e 'const {encrypt,derive}=require("<REPO>/node_modules/@dotenvx/primitives");const k=(d)=>String(d).repeat(64);const m=JSON.parse(process.argv[1]);let t="#/ keys\\nDOTENV_PUBLIC_KEY_KEYS_${name.toUpperCase()}=\\""+derive(k(${digit}))+"\\"\\n\\n# held for the team\\n";for(const [n,d] of Object.entries(m))t+="DOTENV_PRIVATE_KEY"+n+"="+encrypt(derive(k(${digit})),[].concat(d).map(k).join(","))+"\\n";require("fs").writeFileSync(process.argv[2],t)' '${JSON.stringify(map)}' ${dir}/.env.keys.${name}.enc`;
void TEAM_KEYS;
const TREE_SETUP = [keysFile({ _ROOT: 1 }), treeNode("team", 1, { _PRODUCTION: 2, _MID: 3 }), treeNode("deep", 3, { _DEEP: 4 })];
add("keys: the key tree, two levels down", ["keys"], { files: TREE, setup: TREE_SETUP });
add("keys: the key tree, the root key in the environment", ["keys"], { files: TREE, setup: TREE_SETUP.slice(1), keys: "_ROOT=1" });
add("keys: the key tree without its root key", ["keys"], { files: TREE, setup: TREE_SETUP.slice(1) });
add("keys: the key tree, a branch whose key is not held", ["keys"], { files: TREE, setup: [keysFile({ _ROOT: 1 }), treeNode("team", 1, { _PRODUCTION: 2 }), treeNode("deep", 3, { _DEEP: 4 })] });
add("keys: the key tree, a node that is not a keys file", ["keys"], { files: { ...TREE, ".env.keys.broken.enc": "not an enc\n", ".env.keys.plain.enc": `DOTENV_PUBLIC_KEY="${pub(1)}"\n\nDOTENV_PRIVATE_KEY_X=not-encrypted\n` }, setup: TREE_SETUP });
add("keys: the key tree, next to a linked .env.keys", ["keys"], { files: TREE, setup: ["mkdir ../vault", keysFile({ _ROOT: 1 }, "../vault/.env.keys"), treeNode("team", 1, { _PRODUCTION: 2, _MID: 3 }, "../vault"), treeNode("deep", 3, { _DEEP: 4 }), "ln -s ../vault/.env.keys .env.keys"] });
add("keys: the key tree, next to the file -fk names", ["keys", "-fk", "../vault/k"], { files: TREE, setup: ["mkdir ../vault", keysFile({ _ROOT: 1 }, "../vault/k"), treeNode("team", 1, { _PRODUCTION: 2, _MID: 3 }, "../vault"), treeNode("deep", 3, { _DEEP: 4 }, "../vault")] });
add("keys: the key tree, a list of keys and words that are no keys in a node", ["keys"], { files: TREE, setup: [keysFile({ _ROOT: 1 }), `node -e 'const {encrypt,derive}=require("<REPO>/node_modules/@dotenvx/primitives");const k=(d)=>String(d).repeat(64);require("fs").writeFileSync(".env.keys.team.enc","DOTENV_PUBLIC_KEY=\\""+derive(k(1))+"\\"\\nOTHER="+encrypt(derive(k(1)),k(2))+"\\nDOTENV_PRIVATE_KEY_A="+encrypt(derive(k(1)),"nonsense, "+k(4)+" ,"+k(2).toUpperCase().replace(/2/g,"A")+",short")+"\\nDOTENV_PRIVATE_KEY_EMPTY=\\n")'`] });
add("keys: the key tree, a node holding a key that is none", ["keys"], { files: TREE, setup: [keysFile({ _ROOT: 1 }), treeNode("team", 1, { _ZERO: 0 })], back: "the TypeScript ends in an uncaught error from the key library" });
add("get: through the key tree", ["get", "DEEP"], { files: TREE, setup: TREE_SETUP });
add("get: the key tree without its root key", ["get", "DEEP"], { files: TREE, setup: TREE_SETUP.slice(1) });
add("status: through the key tree", ["status"], { files: { ...TREE, ".env.deep": "DEEP=down\n", ".env.production": "API_KEY=changed\n" }, setup: TREE_SETUP });

// keys link
add("keys link: links .env.keys to another checkout's", ["keys", "link", "../other/.env.keys"], { files: { ".env.local.enc": LOCAL_ENC }, setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "chmod 600 ../other/.env.keys"], after: ["readlink .env.keys", LS] });
add("keys link: warns when the target is readable by others", ["keys", "link", "../other/.env.keys"], { setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "chmod 644 ../other/.env.keys"], after: ["readlink .env.keys", "stat -c %a ../other/.env.keys"] });
add("keys link: an absolute target", ["keys", "link", "<CWD>/../other/k"], { setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/k"), "chmod 600 ../other/k"], after: ["readlink .env.keys"] });
add("keys link: without a target", ["keys", "link"], { after: [LS] });
add("keys link: an empty target", ["keys", "link", ""], { after: [LS] });
add("keys link: a target that is not there", ["keys", "link", "../nowhere/.env.keys"], { after: [LS] });
add("keys link: a target that is a directory", ["keys", "link", ".."], { after: [LS] });
add("keys link: .env.keys is already here", ["keys", "link", "../other/.env.keys"], { setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), keysFile({ _LOCAL: 2 })], after: [LS] });
add("keys link: already linked there", ["keys", "link", "../other/.env.keys"], { setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "ln -s ../other/.env.keys .env.keys"], after: ["readlink .env.keys"] });
add("keys link: linked somewhere else", ["keys", "link", "../other/.env.keys"], { setup: ["mkdir ../other ../third", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), keysFile({ _LOCAL: 2 }, "../third/.env.keys"), "ln -s ../third/.env.keys .env.keys"], after: ["readlink .env.keys"] });
add("keys link: a dangling .env.keys link is in the way", ["keys", "link", "../other/.env.keys"], { setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "ln -s ../gone .env.keys"], after: ["readlink .env.keys"] });
add("keys link: linking to itself", ["keys", "link", ".env.keys"], { setup: [K1], after: [LS] });
add("keys link: .env.keys would not be gitignored", ["keys", "link", "../other/.env.keys"], { repo: "node_modules/\n", setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys")], after: [LS] });
add("keys link: outside any repository", ["keys", "link", "../other/.env.keys"], { repo: false, setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "chmod 600 ../other/.env.keys"], after: ["readlink .env.keys"] });
add("keys link: then the keys are found through the link", ["keys"], { files: { ".env.local.enc": LOCAL_ENC }, setup: ["mkdir ../other", keysFile({ _LOCAL: 1 }, "../other/.env.keys"), "ln -s ../other/.env.keys .env.keys"] });

// ═══════════════════════════ dec ═══════════════════════════

/** What a case that writes looks at: both files (the .enc read back with key `digit` or the keys file), what is in the directory, the record. */
const written = (name = ".env.local", keySource = "1") => [`cat ${name} 2>&1`, `${PROBE} enc ${name}.enc ${keySource}`, LS, `${PROBE} state`];
const WRITTEN = written();

for (const [scene, files] of Object.entries(SCENES)) {
  add(`dec: ${scene}`, ["dec"], { files, setup: [K1], after: WRITTEN });
  add(`dec --force: ${scene}`, ["dec", "--force"], { files, setup: [K1], after: WRITTEN });
}
for (const [scene, files] of Object.entries(ODD_SCENES)) add(`dec: ${scene}`, ["dec"], { files, setup: [K1], back: ODD_RECORD, after: WRITTEN });
add("dec: a fresh checkout", ["dec"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC, ".env.enc": encFile(".env", 1, "A=1\n") }, setup: [SEVERAL_KEYS], after: ["cat .env .env.local .env.production", LS, `${PROBE} state`] });
add("dec: no private key", ["dec"], { files: SCENES["no plaintext"], after: WRITTEN });
add("dec: another key only", ["dec"], { files: SCENES["no plaintext"], keys: "_LOCAL=2", after: WRITTEN });
add("dec: the key in the environment", ["dec"], { files: SCENES["no plaintext"], keys: "_LOCAL=1", after: WRITTEN });
add("dec: -fk", ["dec", "-fk", "../k"], { files: SCENES["no plaintext"], setup: [keysFile({ _X: 1 }, "../k")], after: WRITTEN });
add("dec: through the key tree", ["dec"], { files: TREE, setup: TREE_SETUP, after: ["cat .env.deep .env.local .env.production 2>&1", LS, `${PROBE} state`] });
add("dec: one named file of several", ["dec", ".env.production"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS], after: [LS, "cat .env.production"] });
add("dec: named by its .enc, and twice", ["dec", ".env.local.enc", ".env.local"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": PROD_ENC }, setup: [TWO_KEYS], after: [LS] });
add("dec: a named file that is not there", ["dec", ".env.staging"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], after: [LS] });
add("dec: a named file without .enc, the plaintext is there", ["dec", ".env.staging"], { files: { ".env.staging": "S=1\n" }, setup: [K1], after: [LS] });
add("dec: not an env file", ["dec", "notes.txt"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], after: [LS] });
add("dec: nothing here", ["dec"], { after: [LS] });
add("dec: one file fails, the others are decrypted", ["dec"], { files: { ".env.a.enc": encFile(".env.a", 1, "A=1\n"), ".env.b.enc": TAMPERED, ".env.c.enc": encFile(".env.c", 2, "C=1\n"), ".env.d.enc": encFile(".env.d", 1, "D=1\n") }, setup: [K1], after: ["cat .env.a .env.b .env.c .env.d 2>&1", LS, `${PROBE} state`] });
add("dec: the plaintext would not be gitignored", ["dec"], { repo: "node_modules/\n", files: SCENES["no plaintext"], setup: [K1], after: [LS] });
add("dec: outside any repository", ["dec"], { repo: false, files: SCENES["no plaintext"], setup: [K1], after: [LS] });
add("dec: the .enc is gitignored too", ["dec"], { repo: ".env*\n", files: SCENES["no plaintext"], setup: [K1], after: [LS, "cat .env.local"] });
add("dec: in a subdirectory with its own keys", ["dec", "app/.env.local"], { files: { "app/.env.local.enc": LOCAL_ENC }, setup: [keysFile({ _LOCAL: 1 }, "app/.env.keys")], after: ["cat app/.env.local", "ls -A app", `${PROBE} state`] });
add("dec: run in a subdirectory of the repository", ["dec"], { repo: false, files: { ...ABOVE, ".env.local.enc": LOCAL_ENC }, setup: [INIT_ABOVE, K1], after: ["cat .env.local", `${PROBE} state`] });
add("dec: a file one directory up", ["dec", "../.env.local"], { repo: false, files: { ...ABOVE, "../.env.local.enc": LOCAL_ENC }, setup: [INIT_ABOVE, keysFile({ _LOCAL: 1 }, "../.env.keys")], after: ["cat ../.env.local", `${PROBE} state`] });
add("dec: the plaintext is a symlink", ["dec"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": "OLD=1\n" }, setup: [K1, "ln -s elsewhere .env.local"], after: [LS, "cat elsewhere"] });
add("dec: the plaintext is a symlink, named", ["dec", ".env.local"], { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": "OLD=1\n" }, setup: [K1, "ln -s elsewhere .env.local"], after: [LS, "cat elsewhere"] });
add("dec: the plaintext is a link to nowhere, named", ["dec", ".env.local"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1, "ln -s nowhere .env.local"], after: [LS] });
add("dec: the plaintext is committed", ["dec"], { repo: "", files: { ".env.local": "OLD=1\n", ".env.local.enc": LOCAL_ENC, ".gitignore": ".env.keys\n" }, setup: [IDENT, "git add .env.local && git commit -q -m plain", K1], after: [LS, "cat .env.local"] });
add("dec: a loosely readable plaintext is replaced by one for the owner only", ["dec"], { files: SCENES[".enc changed"], setup: [K1, "chmod 644 .env.local"], after: WRITTEN });
add("dec: with a wide-open umask the plaintext is still for the owner only", ["dec"], { files: SCENES["no plaintext"], setup: [K1], after: WRITTEN });
cases[cases.length - 1].args = ["dec"];
add("dec: a glob", ["dec", ".env.*"], { files: SCENES["no plaintext"], setup: [K1], back: "Bun.Glob does the matching", after: [LS] });
add("dec: DOTENVDOTENC_NO_NATIVE=1", ["dec"], { files: SCENES["no plaintext"], setup: [K1], env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back", after: WRITTEN });

// What a plaintext may look like. `.env.production` is not among the files
// bun loads, so nothing about its syntax sends the invocation back.
const RICH = [
  "# database",
  "export DB_URL=\"postgres://user:p@ss@db.test:5432/app?x=1#frag\" # primary",
  "DB_PASS='lit $X and `tick`'",
  "  INDENTED = spaced value  ",
  "MULTI=\"line one",
  "line two\"",
  "ESCAPED=\"a\\nb\\tc\"",
  "JSON='{\"k\": [1, 2]}'",
  "EMPTY=",
  "",
  "QUOTED_EMPTY=\"\"",
  "DOLLAR=$HOME/$(whoami)",
  "UNICODE=naïve café ✓ 😀",
  "DUP=one",
  "DUP=two",
  "BACKTICK=`cmd`",
  "EQUALS=a=b=c",
  "LAST=",
  "",
].join("\n");
const RICH_ENC = encFile(".env.production", 2, RICH);
const K2P = keysFile({ _PRODUCTION: 2 });
const WRITTEN_PROD = written(".env.production", "2");
add("dec: every kind of value, from a fixed .enc", ["dec"], { files: { ".env.production.enc": RICH_ENC }, setup: [K2P], after: WRITTEN_PROD });
add("dec: every kind of value, CRLF .enc", ["dec"], { files: { ".env.production.enc": RICH_ENC.replace(/\n/g, "\r\n") }, setup: [K2P], after: ["od -c .env.production | head -40", LS, `${PROBE} state`] });
add("dec: an .enc with only a header", ["dec"], { files: { ".env.production.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_PRODUCTION="${pub(2)}"\n` }, setup: [K2P], after: WRITTEN_PROD });
add("dec: an .enc with comments only", ["dec"], { files: { ".env.production.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_PRODUCTION="${pub(2)}"\n\n# nothing yet\n` }, setup: [K2P], after: WRITTEN_PROD });
add("dec: an empty value last keeps the final newline", ["dec"], { files: { ".env.production.enc": encFile(".env.production", 2, "A=1\nB=\n") }, setup: [K2P], after: ["od -c .env.production"] });
add("dec: values left empty in the .enc", ["dec"], { files: { ".env.production.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_PRODUCTION="${pub(2)}"\n\nA=\nB=""\nC=''\n` }, setup: [K2P], after: ["od -c .env.production"] });
add("dec: a keys file restored from its backup", ["dec", ".env.keys.myproj"], { files: {}, setup: [keysFile({ _ME: 1 }), treeNode("myproj", 1, { _PRODUCTION: 2, "": 3 })], after: [`${PROBE} keys .env.keys.myproj`, LS] });

// ═══════════════════════════ enc ═══════════════════════════

for (const [scene, files] of Object.entries(SCENES)) {
  add(`enc: ${scene}`, ["enc"], { files, setup: [K1], after: WRITTEN });
  add(`enc --force: ${scene}`, ["enc", "--force"], { files, setup: [K1], after: WRITTEN });
}
for (const [scene, files] of Object.entries(ODD_SCENES)) add(`enc: ${scene}`, ["enc"], { files, setup: [K1], back: ODD_RECORD, after: WRITTEN });
// Unchanged values keep their ciphertext, so their lines in the .enc do not move.
add("enc: an edit changes that line of the .enc only", ["enc"], { files: SCENES["plaintext edited"], setup: [K1], after: ["grep -n -e '^#' -e '^NAME=' -e '^DOTENV' .env.local.enc", "grep -c encrypted: .env.local.enc"] });
add("enc: in sync leaves the .enc as it is", ["enc"], { files: SCENES["in sync"], setup: [K1], after: ["cat .env.local.enc"] });

const FIRST = [`${PROBE} enc .env.local.enc .env.keys`, `${PROBE} keys .env.keys .env.local.enc`, LS, `${PROBE} state`];
add("enc: the first time makes a key, the .enc and the record", ["enc"], { files: { ".env.local": LOCAL }, after: FIRST });
add("enc: the first time, .env", ["enc"], { files: { ".env": "A=1\n" }, after: [`${PROBE} enc .env.enc .env.keys`, `${PROBE} keys .env.keys .env.enc`, LS, `${PROBE} state`] });
add("enc: a key of that name in .env.keys is used", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1], after: [...WRITTEN, "wc -l .env.keys"] });
add("enc: a key of that name in the environment is used, no keys file", ["enc"], { files: { ".env.local": LOCAL }, keys: "_LOCAL=1", after: WRITTEN });
add("enc: the environment before .env.keys", ["enc"], { files: { ".env.local": LOCAL }, setup: [keysFile({ _LOCAL: 2 })], keys: "_LOCAL=1", after: WRITTEN });
add("enc: the first of several keys of that name", ["enc"], { files: { ".env.local": LOCAL }, setup: [keysFile({ _LOCAL: [1, 2] })], after: WRITTEN });
add("enc: a key of another name in .env.keys is not used; a new one is added", ["enc"], { files: { ".env.local": LOCAL }, setup: [keysFile({ _OTHER: 1 })], after: FIRST });
add("enc: a new key goes to a .env.keys without a final newline", ["enc"], { files: { ".env.local": LOCAL }, setup: ["printf 'OTHER=1' > .env.keys"], after: FIRST });
add("enc: a key of that name in the key tree is used", ["enc"], { files: { ".env.production": PROD }, setup: [keysFile({ _ROOT: 1 }), treeNode("team", 1, { _PRODUCTION: 2 })], after: WRITTEN_PROD });
add("enc: an invalid key of that name", ["enc"], { files: { ".env.local": LOCAL, ".env.production": PROD }, setup: [keysFile({ _LOCAL: 0, _PRODUCTION: 2 })], after: [LS] });
add("enc: -fk, the new key goes there", ["enc", "-fk", "../vault/keys"], { files: { ".env.local": LOCAL }, setup: ["mkdir ../vault"], after: [`${PROBE} enc .env.local.enc ../vault/keys`, `${PROBE} keys ../vault/keys .env.local.enc`, LS, "stat -c '%a %n' ../vault/keys"] });
add("enc: -fk to a file here that is not gitignored", ["enc", "-fk", "keys.txt"], { files: { ".env.local": LOCAL }, after: [LS] });
add("enc: .env.keys is a link; the new key lands in its target", ["enc"], { files: { ".env.local": LOCAL }, setup: ["mkdir ../other", keysFile({ _OTHER: 3 }, "../other/.env.keys"), "ln -s ../other/.env.keys .env.keys"], after: [`${PROBE} enc .env.local.enc ../other/.env.keys`, `${PROBE} keys ../other/.env.keys .env.local.enc`, LS, "readlink .env.keys"] });
add("enc: .env.keys would not be gitignored", ["enc"], { repo: ".env.local\n", files: { ".env.local": LOCAL }, after: [LS] });
add("enc: the plaintext is not gitignored", ["enc"], { repo: "node_modules/\n", files: { ".env.local": LOCAL }, after: [LS] });
add("enc: outside any repository", ["enc"], { repo: false, files: { ".env.local": LOCAL }, after: [LS] });
add("enc: the .enc is gitignored too", ["enc"], { repo: ".env*\n", files: { ".env.local": LOCAL }, setup: [K1], after: WRITTEN });
add("enc: nothing here", ["enc"], { after: [LS] });
add("enc: only an .enc here", ["enc"], { files: SCENES["no plaintext"], setup: [K1], after: [LS] });
add("enc: a named file that is not there, its .enc is", ["enc", ".env.local"], { files: SCENES["no plaintext"], setup: [K1], after: [LS] });
add("enc: a named file that is not there at all", ["enc", ".env.nope"], { after: [LS] });
add("enc: a loosely readable plaintext is tightened", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1, "chmod 664 .env.local"], after: WRITTEN });
add("enc: several files, each its own new key", ["enc"], { files: { ".env": "A=1\n", ".env.local": LOCAL, ".env.production": PROD, ".env.example": "A=\n" }, after: [`${PROBE} keys .env.keys .env.enc .env.local.enc .env.production.enc`, `${PROBE} enc .env.production.enc .env.keys`, LS, `${PROBE} state`] });
add("enc: two named files", ["enc", ".env.production", ".env.local"], { files: { ".env": "A=1\n", ".env.local": LOCAL, ".env.production": PROD }, setup: [TWO_KEYS], after: [LS, `${PROBE} state`] });
add("enc: one file fails, the others are encrypted", ["enc"], { files: { ".env.a": "A=1\n", ".env.b": "this is no assignment\n", ".env.c": "C=1\n" }, setup: [keysFile({ _A: 1, _B: 1, _C: 1 })], after: [LS, `${PROBE} state`] });
add("enc: the plaintext is a symlink", ["enc"], { files: { "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"], after: [LS] });
add("enc: the plaintext is a symlink, named", ["enc", ".env.local"], { files: { "elsewhere": LOCAL }, setup: [K1, "ln -s elsewhere .env.local"], after: [LS] });
add("enc: the .enc is a symlink", ["enc"], { files: { ".env.local": LOCAL, "elsewhere": LOCAL_ENC }, setup: [K1, "ln -s elsewhere .env.local.enc"], after: [LS] });
add("enc: the .enc is a link to nowhere", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1, "ln -s nowhere .env.local.enc"], after: [LS] });
add("enc: the plaintext is committed", ["enc"], { repo: "", files: { ".env.shared": "PUBLIC=1\n", ".gitignore": ".env.keys\n" }, setup: [IDENT, "git add .env.shared && git commit -q -m public"], after: [LS] });
add("enc: the plaintext is committed, named", ["enc", ".env.shared"], { repo: "", files: { ".env.shared": "PUBLIC=1\n", ".gitignore": ".env.keys\n" }, setup: [IDENT, "git add .env.shared && git commit -q -m public"], after: [LS] });
add("enc: in a subdirectory, the key next to the file", ["enc", "app/.env.local"], { files: { "app/.env.local": LOCAL }, after: ["ls -A . app", `${PROBE} state`] });
add("enc: run in a subdirectory of the repository", ["enc"], { repo: false, files: { ...ABOVE, ".env.local": LOCAL }, setup: [INIT_ABOVE], after: [...FIRST] });
add("enc: run in a subdirectory, edited since the last sync", ["enc"], { repo: false, files: { ...ABOVE, ".env.local": EDITED, ".env.local.enc": LOCAL_ENC, "../record.fixture": stateText({ "cwd/.env.local": [LOCAL, LOCAL_ENC] }) }, setup: [INIT_ABOVE, "mkdir -p ../.git/dotenvdotenc && mv ../record.fixture ../.git/dotenvdotenc/state.json", K1], after: WRITTEN });
add("enc: a glob", ["enc", ".env.*"], { files: { ".env.local": LOCAL }, setup: [K1], back: "Bun.Glob does the matching", after: [LS] });
add("enc: DOTENVDOTENC_NO_NATIVE=1", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1], env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back", after: WRITTEN });

// What may and may not be committed.
add("enc: every kind of value", ["enc"], { files: { ".env.production": RICH }, setup: [K2P], after: WRITTEN_PROD });
add("enc: every kind of value, CRLF plaintext", ["enc"], { files: { ".env.production": RICH.replace(/\n/g, "\r\n") }, setup: [K2P], after: [`${PROBE} enc .env.production.enc 2 | od -c | head -30`, LS, `${PROBE} state`] });
add("enc: every kind of value, then dec gives the plaintext back", ["dec"], { files: { ".env.production": RICH }, setup: [K2P, "sh <REPO>/rs/parity/run.sh bun <REPO>/dede.ts enc >/dev/null 2>&1", "mv .env.production original && rm -rf .git/dotenvdotenc"], after: ["cmp .env.production original && echo identical", LS] });
add("enc: an empty plaintext", ["enc"], { files: { ".env.production": "" }, setup: [K2P], after: WRITTEN_PROD });
add("enc: comments only", ["enc"], { files: { ".env.production": "# nothing yet\n\n" }, setup: [K2P], after: WRITTEN_PROD });
add("enc: no newline at the end", ["enc"], { files: { ".env.production": "A=1\nB=2" }, setup: [K2P], after: [`${PROBE} enc .env.production.enc 2 | od -c | tail -4`] });
add("enc: an empty value last keeps the final newline", ["enc"], { files: { ".env.production": "A=1\nB=\n" }, setup: [K2P], after: WRITTEN_PROD });
for (const [what, text] of [
  ["a line that is no assignment", "A=1\njust some words\n"],
  ["text glued to a value as a comment", "PASSWORD=abc#def\n"],
  ["text after a closing quote", "A=\"x\"y\n"],
  ["a commented-out assignment with a long value", "A=1\n# OLD_TOKEN=abcdefghijklmnopqrstuvwxyz\n"],
  ["a commented-out assignment with a short value is fine", "A=1\n# DEBUG=true\n"],
  ["a comment with a URL carrying a password", "A=1\n# see https://user:hunter2@example.test/x\n"],
  ["a comment with a plain URL is fine", "A=1\n# see https://example.test/x?y=1\n"],
  ["a commented-out assignment of 16 characters counted as JavaScript counts them", "A=1\n# T=😀😀😀😀😀😀😀😀\n"],
  ["a commented-out assignment of 15 such characters is fine", "A=1\n# T=😀😀😀😀😀😀😀x\n"],
  ["a spaced comment after a value is fine", "A=1 # the answer\nB=\"two\" # words\n"],
  ["a public key among the values of .env.production", `A=1\nDOTENV_PUBLIC_KEY_PRODUCTION="${pub(2)}"\n`],
  ["a private key name among the values of .env.production", "A=1\nDOTENV_PRIVATE_KEY_PRODUCTION=nope\n"],
  ["toString as a name", "A=1\ntoString=x\n"],
  ["a name with a dot and one with a dash", "A.B=1\nC-D=2\n"],
  ["a name that is a number", "1=one\nA=x\n10=ten\n2=two\n"],
  ["a colon instead of an equals sign", "A: 1\n"],
  ["an unterminated quote", "A=\"open\nB=1\n"],
  ["a value with every regular expression character", "A=a|b\\c{d}(e)[f]^g$h+i*j?k.l-m\nB=\"$& $1 $$ $` $'\"\n"],
  ["the same value under two names", "A=same\nB=same\nC=\"same\"\n"],
  ["a name that is the end of another", "XA=1\nA=1\nAA=1\n"],
  ["blank lines after an empty value", "A=\n\n\nB=2\n"],
  ["a byte order mark", "﻿A=1\nB=2\n"],
  ["a lone carriage return between two assignments", "A=1\rB=2\n"],
  ["a value in a line separator's company", "A=1 B=2\n"],
  ["bytes that are not UTF-8", null],
]) {
  add(`enc: ${what}`, ["enc"], { files: { ".env.production": text ?? "A=1\n" }, setup: [K2P, ...(text === null ? ["printf 'B=\\377\\376\\n' >> .env.production"] : [])], after: WRITTEN_PROD });
}

// --key NAME: the key for a new .enc.
add("enc --key: a keys file backed up with a chosen key", ["enc", ".env.keys.myproj", "--key", "ME"], { files: {}, setup: [keysFile({ _ME: 1 }), keysFile({ _PRODUCTION: 2, "": 3 }, ".env.keys.myproj")], after: [`${PROBE} enc .env.keys.myproj.enc 1 | sed -E 's/[0-9a-f]{64}/<a private key>/g'`, LS, "wc -l .env.keys"] });
add("enc --key: the key from the environment", ["enc", "--key", "CI", ".env.production"], { files: { ".env.production": PROD }, keys: "_CI=2", after: WRITTEN_PROD });
add("enc --key: the key from the key tree", ["enc", "--key", "MID", ".env.production"], { files: { ".env.production": PROD }, setup: [keysFile({ _ROOT: 1 }), treeNode("team", 1, { _MID: 2 })], after: WRITTEN_PROD });
add("enc --key: a key that is not held", ["enc", "--key", "NOPE", ".env.production"], { files: { ".env.production": PROD }, setup: [K1], after: [LS] });
add("enc --key: without a name", ["enc", ".env.production", "--key"], { files: { ".env.production": PROD }, setup: [K1], after: [LS] });
add("enc --key: a lower-case name", ["enc", "--key", "me", ".env.production"], { files: { ".env.production": PROD }, setup: [K1], after: [LS] });
add("enc --key: the .enc is there and has that key", ["enc", "--key", "TWO"], { files: { ".env.production": PROD + "MORE=1\n", ".env.production.enc": PROD_ENC, "state.fixture": stateText({ ".env.production": [PROD, PROD_ENC] }) }, setup: [keysFile({ _TWO: 2 })], after: WRITTEN_PROD });
add("enc --key: the .enc is there and has another key", ["enc", "--key", "ONE"], { files: { ".env.production": PROD + "MORE=1\n", ".env.production.enc": PROD_ENC }, setup: [keysFile({ _ONE: 1, _PRODUCTION: 2 })], after: [LS] });
add("enc --key: the .enc is there and the chosen key is not held", ["enc", "--key", "NOPE"], { files: { ".env.production": PROD + "MORE=1\n", ".env.production.enc": PROD_ENC, "state.fixture": stateText({ ".env.production": [PROD, PROD_ENC] }) }, setup: [K2P], after: WRITTEN_PROD });
add("enc: a keys file as plaintext may hold private keys", ["enc", ".env.keys.myproj"], { files: {}, setup: [keysFile({ _KEYS_MYPROJ: 1 }), keysFile({ _PRODUCTION: 2 }, ".env.keys.myproj")], after: [`${PROBE} enc .env.keys.myproj.enc 1 | sed -E 's/[0-9a-f]{64}/<a private key>/g'`, LS] });

// -y: commit what was written.
const COMMITTED = ["git log --format='%s%n%an <%ae>' 2>&1", "git status --porcelain", "git show --stat --format= HEAD 2>&1 | sed 's/ *|.*//'"];
add("enc -y: commits the written .enc", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: [IDENT, "git add .gitignore && git commit -q -m init", K1], after: COMMITTED });
add("enc --yes: the same", ["enc", "--yes"], { files: { ".env.local": LOCAL }, setup: [IDENT, "git add .gitignore && git commit -q -m init", K1], after: COMMITTED });
add("enc -y: only the written .enc files; other staged changes stay staged", ["enc", "-y"], {
  files: { ...SCENES["plaintext edited"], ".env.production": PROD, ".env.production.enc": PROD_ENC, "other.txt": "staged\n", ".env.a": "A=1\n", ".env.b": "B=1\n", ".env.c": "C=1\n" },
  setup: [IDENT, "git add .gitignore .env.local.enc .env.production.enc && git commit -q -m init", keysFile({ _LOCAL: 1, _PRODUCTION: 2, _A: 1, _B: 1, _C: 1 }), "git add other.txt"],
  after: COMMITTED,
});
add("enc -y: nothing written, nothing committed", ["enc", "-y"], { files: SCENES["in sync"], setup: [IDENT, "git add .gitignore .env.local.enc && git commit -q -m init", K1], after: COMMITTED });
add("enc -y: the commit fails without an identity", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: ["git config --global user.useConfigOnly true", K1], after: ["git log --format=%s 2>&1 | head -3", "git status --porcelain"] });
add("enc -y: a pre-commit hook that refuses", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: [IDENT, K1, "printf '#!/bin/sh\\necho hook says no >&2\\nexit 1\\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit"], after: ["git log --format=%s 2>&1 | head -3", "git status --porcelain"] });
add("enc -y: a hook sees the variables of the .env files bun loaded", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: [IDENT, K1, "printf '#!/bin/sh\\necho \"hook: API_KEY=$API_KEY NAME=$NAME\"\\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit"], after: COMMITTED });
add("enc -y: the .enc is gitignored, so git refuses to add it", ["enc", "-y"], { repo: ".env*\n", files: { ".env.local": LOCAL }, setup: [IDENT, K1], after: ["git status --porcelain"] });
add("enc: without -y and without a terminal nothing is committed", ["enc"], { files: { ".env.local": LOCAL }, setup: [IDENT, "git add .gitignore && git commit -q -m init", K1], after: COMMITTED });
add("enc -y: one file fails, the others are committed, exit code of the failure", ["enc", "-y"], { files: { ".env.a": "A=1\n", ".env.b": "no assignment\n" }, setup: [IDENT, keysFile({ _A: 1, _B: 1 })], after: COMMITTED });

// The plaintext is one of the files bun loads; what bun would interpret sends the invocation back.
add("enc: a $ in .env.local", ["enc"], { files: { ".env.local": "A=$HOME\n" }, setup: [K1], back: "bun expands $HOME when it loads .env.local", after: WRITTEN });
add("enc: a value over two lines in .env", ["enc"], { files: { ".env": "A=\"one\ntwo\"\n" }, setup: [keysFile({ "": 1 })], back: "values over several lines in a file bun loads are not imitated", after: written(".env") });
add("enc: export in .env.development", ["enc"], { files: { ".env.development": "export A=1\n" }, setup: [keysFile({ _DEVELOPMENT: 1 })], back: "export in a file bun loads is not imitated", after: written(".env.development") });
add("enc: the same $ in .env.production, which bun does not load", ["enc"], { files: { ".env.production": "A=$HOME\n" }, setup: [K2P], after: WRITTEN_PROD });
add("enc: the same $ in .env.local under NODE_ENV=test, when bun does not load it", ["enc"], { files: { ".env.local": "A=$HOME\n" }, setup: [K1], env: { NODE_ENV: "test" }, after: WRITTEN });

// ═══════════════════════════ guard ═══════════════════════════

const BASE = [IDENT, "git add .gitignore && git commit -q -m init"];
const guard = (name, o = {}, args = ["guard"]) => add(`guard: ${name}`, args, { ...o, setup: [...BASE, ...(o.setup || [])] });
guard("nothing staged");
guard("a real .enc passes", { files: { ".env.local.enc": LOCAL_ENC }, setup: ["git add .env.local.enc"] });
guard("a real .enc with CRLF passes", { files: { ".env.local.enc": LOCAL_ENC.replace(/\n/g, "\r\n") }, setup: ["git -c core.autocrlf=false add .env.local.enc"] });
guard("several kinds of file staged, all fine", { files: { ".env.local.enc": LOCAL_ENC, "src/app.js": "console.log(1)\n", ".env.example": "API_KEY=\n", "a b/é.txt": "x\n" }, setup: ["git add ."] });
guard("a new plaintext env file", { files: { ".env.prod": "A=1\n" }, setup: ["git add -f .env.prod"] });
guard("a new plaintext env file in a subdirectory, from another one", { files: { "app/.env.prod": "A=1\n", "docs/x": "" }, setup: ["git add -f app/.env.prod"] });
guard(".env.keys", { setup: [K1, "git add -f .env.keys"] });
guard("a keys file under another name", { setup: [keysFile({ _X: 1 }, "keys.txt"), "git add keys.txt"] });
guard("a temp file of dede", { files: { ".env.dede-tmp-123-abcd0123": "A=1\n" }, setup: ["git add -f .env.dede-tmp-123-abcd0123"] });
guard("an .enc with a value that is not encrypted", { files: { ".env.local.enc": `${LOCAL_ENC}PLAIN=oops\n` }, setup: ["git add .env.local.enc"] });
guard("an .enc with plaintext glued after the ciphertext", { files: { ".env.local.enc": LOCAL_ENC.replace(/^(API_KEY=encrypted:\S+)$/m, "$1#glued-secret") }, setup: ["git add .env.local.enc"] });
guard("an .enc with a spaced comment after the ciphertext passes", { files: { ".env.local.enc": LOCAL_ENC.replace(/^(API_KEY=encrypted:\S+)$/m, "$1 # fine") }, setup: ["git add .env.local.enc"] });
guard("an .enc whose comment holds a credential; the line number counts the header", { files: { ".env.local.enc": `${LOCAL_ENC}# OLD_TOKEN=abcdefghijklmnopqrstuvwxyz\n` }, setup: ["git add .env.local.enc"] });
guard("an .enc whose comment holds a URL with a password", { files: { ".env.local.enc": LOCAL_ENC.replace("# api", "# https://me:hunter2@example.test") }, setup: ["git add .env.local.enc"] });
guard("an .enc with a line that is no assignment", { files: { ".env.local.enc": `${LOCAL_ENC}oops plain words\n` }, setup: ["git add .env.local.enc"] });
guard("an .enc without header", { files: { ".env.local.enc": "API_KEY=encrypted:AAAA\n" }, setup: ["git add .env.local.enc"] });
guard("an .enc with a name every JavaScript object has", { files: { ".env.local.enc": `${LOCAL_ENC}constructor=encrypted:AAAA\n` }, setup: ["git add .env.local.enc"] });
guard("an .enc that holds a private key name", { files: { ".env.local.enc": `${LOCAL_ENC}DOTENV_PRIVATE_KEY_X=encrypted:AAAA\n` }, setup: ["git add .env.local.enc"] });
guard("an .enc of a keys file may hold private key names", { setup: [K1, treeNode("team", 1, { _PRODUCTION: 2 }), "git add .env.keys.team.enc"] });
guard("an .enc that is a symlink is read as its target's name", { files: { "elsewhere": LOCAL_ENC }, setup: ["ln -s elsewhere .env.local.enc", "git add .env.local.enc"] });
guard("an .enc that is no env name is not looked into", { files: { "notes.enc": "plain words\n", ".env.example.enc": "A=1\n" }, setup: ["git add -f notes.enc .env.example.enc"] });
guard("a private key in YAML, in JSON and in upper case", {
  setup: [
    `printf 'env:\\n  DOTENV_PRIVATE_KEY_PROD: "%s"\\n' "${key(1)}" > deploy.yml`,
    `printf '{"DOTENV_PRIVATE_KEY":"%s"}\\n' "${key(2)}" > secrets.json`,
    `printf 'DOTENV_PRIVATE_KEY_X=%s\\n' "$(printf %064d 0 | tr 0 A)" > upper.txt`,
    `printf 'DOTENV_PRIVATE_KEY_X=%s\\n' "$(printf %063d 0 | tr 0 1)" > short.txt`,
    "git add deploy.yml secrets.json upper.txt short.txt",
  ],
});
guard("an edit to a committed plaintext env file passes", { repo: ".env.keys\n", files: { ".env.shared": "PUBLIC=1\n" }, setup: ["git add .env.shared && git commit -q -m public", "echo MORE=2 >> .env.shared && git add .env.shared"] });
guard("a private key added to a committed plaintext env file", { repo: ".env.keys\n", files: { ".env.shared": "PUBLIC=1\n" }, setup: ["git add .env.shared && git commit -q -m public", `printf 'DOTENV_PRIVATE_KEY=%s\\n' "${key(1)}" >> .env.shared && git add .env.shared`] });
guard("a file renamed into an env name", { repo: ".env.keys\n", files: { "config.txt": "A=1\nB=2\nC=3\n" }, setup: ["git add config.txt && git commit -q -m config", "git mv config.txt .env.renamed"] });
guard("a symlink replaced by a file with a key in it", { setup: ["ln -s elsewhere link && git add link && git commit -q -m link", `rm link && printf 'DOTENV_PRIVATE_KEY=%s\\n' "${key(1)}" > link && git add link`] });
guard("a deleted plaintext env file is no concern", { repo: ".env.keys\n", files: { ".env.shared": "PUBLIC=1\n" }, setup: ["git add .env.shared && git commit -q -m public", "git rm -q .env.shared"] });
guard("a file that is not text", { setup: ["printf '\\377\\376\\000binary' > blob.bin && git add blob.bin"] });
guard("an unmanaged plaintext env file blocks, staged or not", { files: { ".env.prod": "A=1\n", "app/.env.stage": "B=1\n" } });
guard("what is not unmanaged: an .enc twin, *.local, examples, node_modules", { files: { ".env.local": "A=1\n", ".env.development.local": "A=1\n", ".env.example": "A=\n", ".env.sample": "A=\n", ".env.template": "A=\n", ".env.vault": "x\n", ".env.me": "x\n", ".env.prod": PROD, ".env.prod.enc": encFile(".env.prod", 2, PROD), "node_modules/pkg/.env.test": "A=1\n", "app/node_modules/.env.x": "A=1\n" }, setup: [keysFile({ _PROD: 2 })] });
guard("an unmanaged file that is not ignored either", { repo: "node_modules/\n", files: { ".env.prod": "A=1\n" } });
guard("a committed plaintext env file is not unmanaged", { repo: ".env.keys\n", files: { ".env.shared": "PUBLIC=1\n" }, setup: ["git add .env.shared && git commit -q -m public"] });
guard("edits not encrypted yet, naming the keys", { files: SCENES["plaintext edited"], setup: [K1] });
guard("edits not encrypted yet, without the key at hand", { files: SCENES["plaintext edited"] });
guard("edits not encrypted yet, a record without per-key hashes", { files: SCENES["plaintext edited, record without per-key hashes"], setup: [K1] });
guard("in sync passes", { files: SCENES["in sync"], setup: [K1] });
guard("a pull that only changed the .enc does not block", { files: SCENES[".enc changed"], setup: [K1] });
guard("never synced and different, the key at hand", { files: SCENES["differ, never recorded"], setup: [K1] });
guard("never synced and different, no key: not compared", { files: SCENES["differ, never recorded"] });
guard("never synced and the same", { files: SCENES["in sync, never recorded"], setup: [K1] });
guard("never synced, a damaged .enc", { files: { ".env.local": LOCAL, ".env.local.enc": TAMPERED }, setup: [K1] });
guard("the .enc twin of an edited plaintext is a symlink", { files: { ".env.local": LOCAL, "elsewhere": LOCAL_ENC }, setup: [K1, "ln -s elsewhere .env.local.enc"] });
guard("a symlinked plaintext with an .enc twin is passed over", { files: { ".env.local.enc": LOCAL_ENC, "elsewhere": EDITED }, setup: [K1, "ln -s elsewhere .env.local"] });
guard("several things wrong at once, in order", { files: { ...SCENES["plaintext edited"], ".env.prod": "A=1\n", ".env.stage": "A=1\n", ".env.stage.enc": `${encFile(".env.stage", 1, "A=1\n")}B=plain\n` }, setup: [K1, "git add -f .env.stage .env.stage.enc .env.keys"] });
add("guard: from a subdirectory", ["guard"], {
  repo: false,
  files: { ...ABOVE, "../.env.root": "X=1\n", "../app/.env.stage.enc": "A=1\n", ".env.here.enc": "B=1\n", ".env.local": EDITED, ".env.local.enc": LOCAL_ENC, "../record.fixture": stateText({ "cwd/.env.local": [LOCAL, LOCAL_ENC] }) },
  setup: [INIT_ABOVE, IDENT, "mkdir -p ../.git/dotenvdotenc && mv ../record.fixture ../.git/dotenvdotenc/state.json", K1, "git add ../app/.env.stage.enc .env.here.enc"],
});
add("guard: outside any repository", ["guard"], { repo: false });
guard("--all: every tracked file", { repo: ".env.keys\n.env.local\n", files: { ".env.shared": "PUBLIC=1\n", ".env.local.enc": LOCAL_ENC, "src/x.js": "1\n" }, setup: ["git add . && git commit -q -m all"] }, ["guard", "--all"]);
guard("--all: a tracked keys file, a tracked key, a tracked bad .enc", { repo: "node_modules/\n", files: { ".env.bad.enc": "A=1\n", "src/x.js": "1\n" }, setup: [K1, keysFile({ _X: 2 }, "old.txt"), "git add . && git commit -q -m all"] }, ["guard", "--all"]);
guard("--all does not look at what is staged as new", { files: { ".env.prod": "A=1\n" }, setup: ["git add -f .env.prod"] }, ["guard", "--all"]);
guard("a staged file larger than bun's buffer", { setup: ["head -c 1500000 /dev/zero | tr '\\0' a > big.txt && git add big.txt"], back: "bun cuts the output of git off at about 1 MiB" });
guard("DOTENVDOTENC_NO_NATIVE=1", { files: { ".env.prod": "A=1\n" }, env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });

// ═══════════════════════════ health ═══════════════════════════
//
// Ages are counted from now, so a commit is dated a number of days and twelve
// hours back from the moment the case is set up: the day counts printed are
// then the same whenever the case runs. (The one thing that can still differ
// between the two runs of a case is a date, in the instant the clock passes
// noon or midnight UTC between them.)

const HEALTH = "API_TOKEN=t1\nexport DB_PASS=p1\nTOTP_SECRET=s1\nPLAIN_NAME=n1\n";
const HEALTH_ENC = encFile(".env.prod", 2, HEALTH);
/** Shell: commit what is staged, dated `days` and a half back. */
const commitAgo = (days, message = "x") => `d="$(( $(date +%s) - ${days} * 86400 - 43200 )) +0000" && GIT_AUTHOR_DATE="$d" GIT_COMMITTER_DATE="$d" git commit -q -m ${message}`;
const health = (name, yaml, o = {}, args = ["health"]) =>
  add(`health: ${name}`, args, {
    ...o,
    files: { ".env.prod.enc": HEALTH_ENC, ...(yaml === null ? {} : { ".dede.yaml": yaml }), ...(o.files || {}) },
    setup: [IDENT, ...(o.setup || [`git add . && ${commitAgo(100)}`])],
  });
const README_RULES = `# .dede.yaml — first matching rule wins; values no rule matches are counted, not checked
rotate:
  - keys: API_TOKEN                # glob(s) over value names (default: all)
    expires: 2099-01-26            # the credential's own expiry date
    note: "admin console → Keys"   # where to rotate it; printed in the report
  - keys: ["*_TOTP_SECRET", "TOTP_*"]
    every: never                   # exempt
  - keys: ["*_TOKEN*", "*_API_KEY", "*_PASS*"]
    every: 90d                     # Nd, Nw, Nm (months), Ny
    warn: 14d                      # "due soon" window (default 30d)
  - files: ".env.production"       # glob(s) over plaintext file names (default: all)
    every: 1y
`;
health("the rules of the README", README_RULES);
health("the rules of the README, --all", README_RULES, {}, ["health", "--all"]);
health("overdue, with the rule's note", 'rotate:\n  - keys: "*_TOKEN*"\n    every: 90d\n    note: Settings → Tokens\n');
health("due soon, inside the default window of 30 days", "rotate:\n  - keys: API_TOKEN\n    every: 120d\n");
health("due soon, exactly at the edge of the window", "rotate:\n  - keys: API_TOKEN\n    every: 120d\n    warn: 19d\n");
health("in date, just outside the window: counted, not printed", "rotate:\n  - keys: API_TOKEN\n    every: 120d\n    warn: 18d\n");
health("in date, printed with --all", "rotate:\n  - keys: API_TOKEN\n    every: 1y\n", {}, ["health", "--all"]);
health("weeks, months and years", "rotate:\n  - keys: API_TOKEN\n    every: 12w\n  - keys: DB_PASS\n    every: 6m\n  - keys: TOTP_SECRET\n    every: 1y\n  - every: 2 y\n", {}, ["health", "--all"]);
health("an expiry long past", "rotate:\n  - keys: API_TOKEN\n    expires: 2020-02-29\n    note: 'expired'\n");
health("an expiry far ahead, --all", "rotate:\n  - keys: API_TOKEN\n    expires: 2199-12-31\n", {}, ["health", "--all"]);
health("an expiry on a day the month does not have", "rotate:\n  - keys: API_TOKEN\n    expires: 2020-02-30\n");
health("an expiry and an age: whichever comes first", "rotate:\n  - keys: API_TOKEN\n    expires: 2199-12-31\n    every: 90d\n  - keys: DB_PASS\n    expires: 2020-01-01\n    every: 10y\n", {}, ["health", "--all"]);
health("every: never exempts; values without a rule are counted", "rotate:\n  - keys: [API_TOKEN, DB_PASS]\n    every: never\n");
health("never, and an expiry all the same", "rotate:\n  - every: never\n    expires: 2020-01-01\n");
health("the first matching rule wins", "rotate:\n  - keys: \"*\"\n    every: 1y\n  - keys: API_TOKEN\n    every: 1d\n", {}, ["health", "--all"]);
health("a rule for all values of all files", "rotate:\n  - every: 90d\n");
health("a rule for one file by name, another by glob", "rotate:\n  - files: .env.other\n    every: 1d\n  - files: \".env.p*\"\n    keys: \"?B_PASS\"\n    every: 90d\n");
health("an empty list of keys matches nothing", "rotate:\n  - keys: []\n    every: 1d\n");
health("a wait of zero days", "rotate:\n  - keys: API_TOKEN\n    every: 0d\n");
health("no rules: rotate is an empty list", "rotate: []\n");
health("an empty file has no rules", "");
health("comments only", "# nothing yet\n\n  # later\n");
health("CRLF line endings", "rotate:\r\n  - keys: API_TOKEN\r\n    every: 90d\r\n");
health("rules at the left margin, a byte order mark", "﻿rotate:\n- keys: API_TOKEN\n  every: 90d\n- keys: DB_PASS\n  every: 90d\n");
health("no .dede.yaml", null);
health("rotate without a list", "rotate:\n");
health("an unknown field", "rotate:\n  - keys: API_TOKEN\n    every: 90d\n  - key: X\n    every: 1d\n");
health("a duration that is none", "rotate:\n  - keys: API_TOKEN\n    every: ninety days\n");
health("a number for a duration", "rotate:\n  - keys: API_TOKEN\n    every: 90\n");
health("a window that is none", "rotate:\n  - keys: API_TOKEN\n    every: 90d\n    warn: soon\n");
health("a date that is none", "rotate:\n  - keys: API_TOKEN\n    expires: 2027-13-01\n");
health("the first mistake is reported: field, then date, then duration", "rotate:\n  - expires: 2027-00-00\n    every: x\n    warn: y\n  - nope: 1\n");
health("a number as a name and as a note", "rotate:\n  - keys: 123\n    every: 90d\n  - keys: API_TOKEN\n    every: 90d\n    note: 42\n");
health("a value changed later is younger than the rest", "rotate:\n  - every: 90d\n", {
  files: { "later.enc": encFile(".env.prod", 2, HEALTH.replace("p1", "p2")) },
  setup: [`git add .env.prod.enc .dede.yaml && ${commitAgo(200)}`, `mv later.enc .env.prod.enc && git add .env.prod.enc && ${commitAgo(10)}`],
});
health("an .enc that is not committed", "rotate:\n  - keys: API_TOKEN\n    every: 90d\n    warn: 1d\n", { setup: ["true"] }, ["health", "--all"]);
health("an edit not committed yet counts as changed now", "rotate:\n  - every: 90d\n    warn: 1d\n", { files: { "later.enc": encFile(".env.prod", 2, HEALTH.replace("p1", "p2")) }, setup: [`git add .env.prod.enc .dede.yaml && ${commitAgo(200)}`, "mv later.enc .env.prod.enc"] });
health("the last assignment of a name counts; a public key is no value", "rotate:\n  - every: 90d\n", {
  files: { ".env.prod.enc": `${HEALTH_ENC}API_TOKEN=${seal(2, "t1", "again")}\nDOTENV_PUBLIC_KEY_X="${pub(1)}"\n  # c\n\nnot an assignment\n` },
  setup: [`git add .env.prod.enc .dede.yaml && ${commitAgo(200)}`, "sed -i '$d' .env.prod.enc && echo 'ZED=encrypted:x' >> .env.prod.enc && git add . && " + commitAgo(10)],
});
health("several files", "rotate:\n  - keys: \"*\"\n    files: [.env.prod, \".env.local\"]\n    every: 90d\n", { files: { ".env.local.enc": LOCAL_ENC, ".env.other.enc": PROD_ENC } });
health("one named file", "rotate:\n  - every: 90d\n", { files: { ".env.local.enc": LOCAL_ENC } }, ["health", ".env.local"]);
health("a named file that is not there", "rotate:\n  - every: 90d\n", {}, ["health", ".env.nope"]);
health("no .enc here", "rotate:\n  - every: 90d\n", { files: { ".env.prod.enc": undefined }, setup: ["true"] });
health("the .enc is a symlink", "rotate:\n  - every: 90d\n", { files: { "elsewhere": LOCAL_ENC }, setup: ["ln -s elsewhere .env.local.enc"] });
add("health: outside any repository", ["health"], { repo: false, files: { ".env.prod.enc": HEALTH_ENC, ".dede.yaml": "rotate: []\n" } });
add("health: run in a subdirectory, the rules at the root", ["health"], { repo: false, files: { ...ABOVE, "../.dede.yaml": "rotate:\n  - every: 90d\n", ".env.prod.enc": HEALTH_ENC, ".dede.yaml": "rotate: []\n" }, setup: [INIT_ABOVE, IDENT, `git add .env.prod.enc && ${commitAgo(100)}`] });
// What bun's YAML reader or its globs make of these is not imitated.
for (const [what, yaml, why] of [
  ["a number that is no plain integer", "rotate:\n  - keys: API_TOKEN\n    every: 1.5\n", "YAML numbers other than plain integers are not imitated"],
  ["true for a name", "rotate:\n  - keys: true\n    every: 90d\n", "YAML booleans are not imitated"],
  ["a field without a value", "rotate:\n  - keys:\n    every: 90d\n", "YAML null is not imitated"],
  ["a rule in braces", "rotate:\n  - {keys: API_TOKEN, every: 90d}\n", "YAML flow mappings are not imitated"],
  ["rotate that is a number", "rotate: 5\n", "only a block list under rotate is imitated"],
  ["another top-level key", "version: 1\nrotate: []\n", "only rotate at the top level is imitated"],
  ["an escape in quotes", "rotate:\n  - keys: API_TOKEN\n    every: 90d\n    note: \"a\\tb\"\n", "YAML escapes are not imitated"],
  ["a note with a colon", "rotate:\n  - keys: API_TOKEN\n    every: 90d\n    note: see: the wiki\n", "bun's YAML reader rejects it, in its own words"],
  ["a tab for indentation", "rotate:\n\t- keys: API_TOKEN\n", "bun's YAML reader rejects it, in its own words"],
  ["an expiry with a time", "rotate:\n  - keys: API_TOKEN\n    expires: 2099-01-26T10:00\n", "Date.parse of anything but YYYY-MM-DD is not imitated"],
  ["a glob with braces", "rotate:\n  - keys: \"{API,DB}_*\"\n    every: 90d\n", "Bun.Glob beyond * and ? is not imitated"],
  ["a glob with a character class", "rotate:\n  - keys: \"[A-D]*\"\n    every: 90d\n", "Bun.Glob beyond * and ? is not imitated"],
  ["a glob with two stars", "rotate:\n  - keys: \"**\"\n    every: 90d\n", "Bun.Glob beyond * and ? is not imitated"],
  ["a duration of seven digits", "rotate:\n  - keys: API_TOKEN\n    every: 1000000d\n", "JavaScript's arithmetic on very large numbers is not imitated"],
]) {
  health(what, yaml, { back: why });
}
health("a glob for the files to check", "rotate: []\n", { back: "Bun.Glob does the matching" }, ["health", ".env.*"]);
health("DOTENVDOTENC_NO_NATIVE=1", "rotate: []\n", { env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });

// ═══════════════════════════ setup ═══════════════════════════

/** Shell: the hooks in a directory, each with its mode and text. */
const hooksIn = (dir) => `for h in pre-commit post-merge post-checkout; do if [ -e ${dir}/$h ]; then stat -c '--- %a %n' ${dir}/$h; cat ${dir}/$h; fi; done; ls -A ${dir} 2>&1 | grep -v -e '\\.sample$' -e '^_$'`;
const HOOKS = hooksIn(".git/hooks");
const IGNORED = "cat .gitignore 2>&1";
const setup = (name, o = {}) => add(`setup: ${name}`, ["setup"], { repo: "", ...o, after: [IGNORED, ...(o.after || [HOOKS]), LS] });
setup("a fresh repository");
setup("a second time changes nothing", { setup: ["sh <REPO>/rs/parity/run.sh bun <REPO>/dede.ts setup 2>/dev/null"] });
setup("the rules are there already", { repo: IGNORE });
setup("a .gitignore with other rules", { repo: "node_modules/\ndist/\n" });
setup("a .gitignore without a final newline", { repo: "node_modules/" });
setup("a .gitignore that ignores .env but would ignore the .enc too", { repo: ".env*\n" });
setup("a .gitignore whose later rule un-ignores .env.local: the block goes after it", { repo: ".env*\n!.env*.enc\n!.env.local\n" });
setup("the rules come from .git/info/exclude", { setup: ["printf '.env*\\n!.env*.enc\\n' >> .git/info/exclude"] });
setup(".gitignore is a symlink", { files: { "elsewhere": "x\n" }, setup: ["ln -s elsewhere .gitignore"], after: [HOOKS, "cat elsewhere"] });
setup("an existing hook: the guard goes right after its first line", { setup: ["printf '#!/bin/sh\\necho before\\nexec other-tool \"$@\"\\n' > .git/hooks/pre-commit && chmod 755 .git/hooks/pre-commit"] });
setup("an existing hook without a first line for the shell", { setup: ["printf 'echo plain\\n' > .git/hooks/pre-commit"] });
setup("an existing hook that is only a first line, without a newline", { setup: ["printf '#!/usr/bin/env bash' > .git/hooks/pre-commit && chmod 700 .git/hooks/pre-commit"] });
setup("an existing hook keeps its mode", { setup: ["printf '#!/bin/sh\\ntrue\\n' > .git/hooks/pre-commit && chmod 644 .git/hooks/pre-commit", "printf '#!/bin/zsh\\ntrue\\n' > .git/hooks/post-merge && chmod 750 .git/hooks/post-merge"] });
setup("an existing hook that already calls dede guard", { setup: ["printf '#!/bin/sh\\nnpx dede guard\\n' > .git/hooks/pre-commit", "printf '#!/bin/sh\\ndede status --quiet\\n' > .git/hooks/post-checkout"] });
setup("an existing hook that is not a shell script", { setup: ["printf '#!/usr/bin/env python3\\nprint(1)\\n' > .git/hooks/pre-commit"] });
setup("a post-merge hook that is not a shell script: pre-commit is installed first", { setup: ["printf '#!/usr/bin/env node\\n' > .git/hooks/post-merge"] });
setup("an existing hook that is a symlink", { files: { "elsewhere": "#!/bin/sh\n" }, setup: ["ln -s ../../elsewhere .git/hooks/pre-commit"] });
setup("core.hooksPath names a directory", { setup: ["git config core.hooksPath .githooks"], after: [hooksIn(".githooks")] });
setup("core.hooksPath is husky's .husky/_", { setup: ["git config core.hooksPath .husky/_", "mkdir -p .husky/_"], after: [hooksIn(".husky")] });
setup("core.hooksPath is .husky/_/ and there is a package.json", { files: { "package.json": "{}\n" }, setup: ["git config core.hooksPath .husky/_/"], after: [hooksIn(".husky"), "cat package.json"] });
setup("core.hooksPath starts with ~", { setup: ["git config core.hooksPath '~/my hooks'"], after: [hooksIn("\"$HOME/my hooks\"")] });
setup("a .husky directory without core.hooksPath", { files: { "package.json": "{}\n", ".husky/pre-push": "true\n" }, after: [hooksIn(".husky"), "cat package.json"] });
setup("lefthook.yml: a snippet to paste", { files: { "lefthook.yml": "pre-push:\n  commands: {}\n", "package.json": "{}\n" }, after: ["cat lefthook.yml package.json", HOOKS] });
setup(".lefthook.yaml that already has the guard", { files: { ".lefthook.yaml": "pre-commit:\n  commands:\n    x:\n      run: dede guard\n" } });
setup("lefthook.yaml before .lefthook.yml", { files: { "lefthook.yaml": "a: 1\n", ".lefthook.yml": "run: dede guard\n" } });
const HUSKY = [hooksIn(".husky"), "cat package.json", "stat -c '%a %n' package.json", HOOKS];
setup("a package.json: husky is set up", { files: { "package.json": '{\n  "name": "app",\n  "version": "1.0.0",\n  "private": true\n}\n' }, after: HUSKY });
setup("a package.json with four spaces, a prepare script and its own mode", { files: { "package.json": '{\n    "name": "app",\n    "scripts": {\n        "prepare": "node build.js",\n        "test": "x"\n    },\n    "devDependencies": {\n        "typescript": "^5"\n    }\n}' }, setup: ["chmod 600 package.json"], after: HUSKY });
setup("a package.json with tabs, where husky is already a dependency and in prepare", { files: { "package.json": '{\n\t"scripts": {"prepare": "husky"},\n\t"dependencies": {"husky": "^9"},\n\t"files": ["a", "b"],\n\t"count": 3,\n\t"nothing": null\n}\n' }, after: HUSKY });
setup("a package.json on one line", { files: { "package.json": '{"name":"app","scripts":null,"devDependencies":null}' }, after: HUSKY });
setup("a package.json with keys that are numbers and text beyond ASCII", { files: { "package.json": '{\n  "name": "café \\u2028 \\"q\\"",\n  "2": "two",\n  "1": "one",\n  "é": {"x": []}\n}\n' }, after: HUSKY });
setup("husky's own hooks are kept where they exist", { files: { "package.json": "{}\n" }, setup: ["mkdir .husky.tmp && printf 'mine\\n' > .husky.tmp/post-merge && mkdir -p node_modules/.bin && true"], after: HUSKY });
setup("husky is installed: it is run", { files: { "package.json": "{}\n" }, setup: ["mkdir -p node_modules/.bin && printf '#!/bin/sh\\necho ran in \"$(pwd)\" > husky.ran\\n' > node_modules/.bin/husky && chmod +x node_modules/.bin/husky"], after: [...HUSKY, "cat husky.ran"] });
setup("husky is installed and fails", { files: { "package.json": "{}\n" }, setup: ["mkdir -p node_modules/.bin && printf '#!/bin/sh\\nexit 3\\n' > node_modules/.bin/husky && chmod +x node_modules/.bin/husky"], after: HUSKY });
setup("a package.json that is a symlink", { files: { "real.json": "{}\n" }, setup: ["ln -s real.json package.json"], after: ["cat real.json", "ls -A .husky 2>&1"] });
setup("a package.json that is not JSON", { files: { "package.json": "{ name: app }\n" }, back: "JSON.parse fails and the TypeScript ends in an uncaught SyntaxError", after: [HOOKS] });
setup("a package.json with a number that is no plain integer", { files: { "package.json": '{"version": 1.50}\n' }, back: "JSON.stringify would write the number back in JavaScript's form", after: ["cat package.json"] });
setup("a package.json whose scripts are no object", { files: { "package.json": '{"scripts": "none"}\n' }, back: "the TypeScript ends in an uncaught TypeError", after: ["cat package.json"] });
setup("a package.json that is a list", { files: { "package.json": "[]\n" }, back: "what JavaScript does with a package.json that is no object is not imitated", after: ["cat package.json"] });
add("setup: outside any repository", ["setup"], { repo: false, after: [LS] });
add("setup: run in a subdirectory: the repository's .gitignore and hooks", ["setup"], { repo: false, files: { "../.gitignore": "/home/\n/tmp/\n/cache/\n" }, setup: [INIT_ABOVE], after: ["cat ../.gitignore", hooksIn("../.git/hooks"), LS] });
add("setup: in a linked worktree the hooks are the repository's", ["setup"], {
  repo: false,
  files: { "../main/README": "x\n" },
  setup: [IDENT, "cd ../main && git init -q -b main && git add . && git commit -q -m init && git worktree add -q ../wt -b side", "mv ../wt/.git . && echo \"$PWD/.git\" > ../main/.git/worktrees/wt/gitdir"],
  after: [IGNORED, hooksIn("../main/.git/hooks"), LS],
});
setup("DOTENVDOTENC_NO_NATIVE=1", { env: { DOTENVDOTENC_NO_NATIVE: "1" }, back: "DOTENVDOTENC_NO_NATIVE=1 hands everything back" });

// ═══════════════════════════ colour ═══════════════════════════
//
// bun prints console.error in red when it takes the output for a terminal's,
// or is told to. Without a terminal (as here) that is a matter of FORCE_COLOR
// and NO_COLOR; with one, rs/tty-compat.py compares the two implementations.

for (const value of ["1", "", "true", "2", " "]) {
  add(`colour: FORCE_COLOR=${JSON.stringify(value)} makes what goes to stderr red, into a pipe too`, ["status"], { files: { ...SEVERAL, ".env.local.enc": TAMPERED }, setup: [SEVERAL_KEYS], env: { FORCE_COLOR: value } });
}
for (const value of ["0", "false", "no", "00"]) {
  add(`colour: FORCE_COLOR=${JSON.stringify(value)} does not`, ["status"], { files: { ...SEVERAL, ".env.local.enc": TAMPERED }, setup: [SEVERAL_KEYS], env: { FORCE_COLOR: value } });
}
add("colour: FORCE_COLOR=1, the usage on stderr is red as a whole", ["frobnicate"], { repo: false, env: { FORCE_COLOR: "1" } });
add("colour: FORCE_COLOR=1, the usage on stdout is not", ["help"], { repo: false, env: { FORCE_COLOR: "1" } });
add("colour: FORCE_COLOR=1, a refusal of several lines", ["guard"], { files: { ".env.prod": "A=1\n", ".env.stage": "A=1\n" }, env: { FORCE_COLOR: "1" } });
add("colour: FORCE_COLOR=1, get prints the value plain", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { FORCE_COLOR: "1" } });
add("colour: FORCE_COLOR=1, enc -y: dede's lines are red, git's are git's", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: ["git config --global user.useConfigOnly true", K1], env: { FORCE_COLOR: "1" } });
add("colour: FORCE_COLOR=1 wins over NO_COLOR=1", ["get", "MISSING"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { FORCE_COLOR: "1", NO_COLOR: "1" } });
for (const value of ["1", "true", "", "0"]) {
  add(`colour: NO_COLOR=${JSON.stringify(value)}, nothing is red without a terminal anyway`, ["get", "MISSING"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { NO_COLOR: value } });
}
add("colour: FORCE_COLOR in a .env file bun loads changes nothing", ["get", "MISSING"], { files: { ".env.local.enc": LOCAL_ENC, ".env": "FORCE_COLOR=1\n" }, setup: [K1] });
add("colour: a FORCE_COLOR that was not tried", ["get", "MISSING"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { FORCE_COLOR: "3" }, back: "what bun makes of this value of FORCE_COLOR was not recorded" });
add("colour: a NO_COLOR that was not tried", ["get", "MISSING"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { NO_COLOR: "yes" }, back: "what bun makes of this value of NO_COLOR was not recorded" });

// ═══════════════════════════ what bun's regular expressions give up on ═══════════════════════════
//
// Under bun the scanner of @dotenvx/primitives stops at a quoted value of
// more than 393,214 to 540,669 code units, and upsert cannot build an
// expression of more than 1,048,576 (primitives::QUOTED_SPAN_LIMIT in
// rs/src). The binary hands back what comes within a third of the first or
// half of the second, foreseeing the ciphertexts enc will write; these cases
// sit on both sides of that margin. Large files are written by node when a
// case runs; .enc files of them are made with @dotenvx/primitives there too.

const WRITE = (file, expr) => `node -e 'require("fs").writeFileSync(${JSON.stringify(file)}, ${expr})'`;
const ENC_OF = (file, expr) =>
  `node -e 'const { encrypt, derive } = require("<REPO>/node_modules/@dotenvx/primitives"); const pub = derive("1".repeat(64)); const e = (v) => encrypt(pub, v); require("fs").writeFileSync(${JSON.stringify(file)}, ${JSON.stringify(BANNER + "\nDOTENV_PUBLIC_KEY_PROD=\"")} + pub + "\\"\\n\\n" + ${expr})'`;
const KPROD = keysFile({ _PROD: 1 });
const MARGIN = "within the margin kept from what bun's regular expressions give up on";
const BIG_AFTER = [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`, `${PROBE} state`];
add("large: enc, a quoted value whose ciphertext stays within the margin", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\"" + "a".repeat(90000) + "\\"\\nZ=2\\n"')], after: BIG_AFTER });
add("large: enc, a quoted value whose ciphertext would not", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=\\"" + "a".repeat(100000) + "\\"\\nZ=2\\n"')], after: BIG_AFTER, back: MARGIN });
add("large: enc, a quoted value of three-byte letters whose ciphertext would not", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=`" + "€".repeat(33000) + "`\\nZ=2\\n"')], after: BIG_AFTER, back: MARGIN });
add("large: enc, a bare value whose ciphertext stays within the margin", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=" + "a".repeat(180000) + "\\nZ=2\\n"')], after: BIG_AFTER });
add("large: enc, a bare value of minus signs, escaped four times over, within the margin", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=" + "-".repeat(120000) + "\\nZ=2\\n"')], after: BIG_AFTER });
add("large: enc, a bare value of minus signs past the margin", ["enc"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nBIG=" + "-".repeat(140000) + "\\nZ=2\\n"')], after: BIG_AFTER, back: MARGIN });
add("large: enc, three hundred values whose .enc is larger than the margin, each one well within it", ["enc"], { setup: [KPROD, WRITE(".env.prod", 'Array.from({ length: 300 }, (_, i) => `V_${i}="${"x".repeat(400)}"\\n`).join("")')], after: [LS, `${PROBE} enc .env.prod.enc .env.keys | wc -c`, `${PROBE} state`] });
add("large: get, a quoted ciphertext within the margin", ["get", "Z"], { setup: [KPROD, ENC_OF(".env.prod.enc", '"A=" + e("1") + "\\nBIG=\\"" + e("a".repeat(97000)) + "\\"\\nZ=" + e("2") + "\\n"')] });
add("large: get, a quoted ciphertext past the margin", ["get", "Z"], { setup: [KPROD, ENC_OF(".env.prod.enc", '"A=" + e("1") + "\\nBIG=\\"" + e("a".repeat(99000)) + "\\"\\nZ=" + e("2") + "\\n"')], back: MARGIN });
add("large: dec, a quoted ciphertext past the margin", ["dec"], { setup: [KPROD, ENC_OF(".env.prod.enc", '"A=" + e("1") + "\\nBIG=\\"" + e("a".repeat(99000)) + "\\"\\nZ=" + e("2") + "\\n"')], back: MARGIN, after: [LS] });
add("large: status, an unclosed quote with less than the margin after it", ["status"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nB=\\"" + "x\\n".repeat(60000) + "Z=2\\n"')] });
add("large: status, an unclosed quote with more than the margin after it", ["status"], { setup: [KPROD, WRITE(".env.prod", '"A=1\\nB=\\"" + "x\\n".repeat(70000) + "Z=2\\n"')], back: MARGIN });
add("large: status, quotes in comments and inside values start nothing", ["status"], { setup: [KPROD, WRITE(".env.prod", '"# it\\x27s\\nA=it\\x27s\\nB=\\"x\\" # \\x27q\\n# " + "c".repeat(140000) + "\\nZ=1\\n"')] });
add("large: status, 100,000 blank lines before a quoted value", ["status"], { setup: [KPROD, WRITE(".env.prod", '"\\n".repeat(100000) + "A=\\"x\\"\\n"')] });
add("large: get, a keys file with a quoted value past the margin", ["get", "A"], { files: { ".env.prod.enc": encFile(".env.prod", 1, "A=1\n", "big-keys") }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(140000) + "\\"\\n"'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"], back: MARGIN });
add("large: enc, a keys file a new key would push past the margin", ["enc", ".env.stage"], { files: { ".env.stage": "A=1\n" }, setup: [KPROD, WRITE(".env.keys.note", '"NOTE=\\"" + "n".repeat(131000)'), "cat .env.keys.note >> .env.keys && rm .env.keys.note"], after: [LS], back: MARGIN });
add("large: enc, both sides changed in files too large to merge here", ["enc"], {
  files: { "state.fixture": stateText({ ".env.prod": ["A=1\nB=1\n", "x"] }) },
  setup: [KPROD, WRITE(".env.prod", '"A=2\\nB=1\\nPAD=\\"" + "p".repeat(70000) + "\\"\\n"'), ENC_OF(".env.prod.enc", '"A=" + e("1") + "\\nB=" + e("2") + "\\nPAD=\\"" + e("p".repeat(70000)) + "\\"\\n"')],
  after: [LS],
  back: MARGIN,
});

// A possible merge in enc is bounded per name (rs/src/dede.rs
// merged_enc_bound): both files twice, plus per name and place the longest
// ciphertext it can get, against the same margin. Here the .enc is made by
// dede.ts, then changed on both sides since the record, so the binary
// merges: 23 values of 1,000 bytes come to 126,840 units (answered), 24 to
// 132,340 (handed back), and an edited file of 450 short values to about
// 100,000 (at 2c2a075, which counted every ciphertext of both sides, it went
// back).
const BOTH_CHANGED = (count, size) => [
  KPROD,
  WRITE(".env.prod", `Array.from({ length: ${count} }, (_, i) => "V_" + i + "=" + String(i).padStart(${size}, "v") + "\\n").join("")`),
  "X_CD= PARITY_GIT_LOG= sh <REPO>/rs/parity/run.sh bun <REPO>/dede.ts enc 2>/dev/null",
  "cp .git/dotenvdotenc/state.json state.synced",
  "sed -i 's/^V_8=v/V_8=w/' .env.prod && X_CD= PARITY_GIT_LOG= sh <REPO>/rs/parity/run.sh bun <REPO>/dede.ts enc 2>/dev/null",
  "mv state.synced .git/dotenvdotenc/state.json && sed -i 's/^V_8=w/V_8=v/; s/^V_7=v/V_7=x/' .env.prod",
];
const MERGED_AFTER = [LS, `${PROBE} enc .env.prod.enc .env.keys | grep -c '^V_'`, `${PROBE} enc .env.prod.enc .env.keys | grep -E '^V_[78]=' | cut -c1-12`, "grep -E '^V_[78]=' .env.prod | cut -c1-12", "sha256sum .env.prod", `${PROBE} state`];
add("large: enc, both sides changed in 23 values of 1,000 bytes: merged here", ["enc"], { setup: BOTH_CHANGED(23, 1000), after: MERGED_AFTER });
add("large: enc, both sides changed in 24 values of 1,000 bytes: past the margin", ["enc"], { setup: BOTH_CHANGED(24, 1000), after: MERGED_AFTER, back: MARGIN });
add("large: enc, both sides changed in a file of 450 short values: merged here", ["enc"], { setup: BOTH_CHANGED(450, 9), after: MERGED_AFTER });
add("large: dec, both sides changed in a file of 450 short values: merged here", ["dec"], { setup: BOTH_CHANGED(450, 9), after: MERGED_AFTER });

// ═══════════════════════════ setup: what the pre-read sees ═══════════════════════════
//
// Before its first write setup looks at everything it will read, make or
// replace, in the hooks directory git will name (rs/src/repo.rs), and hands
// back where the TypeScript would end in an uncaught error after writing.
// Which directory that is it reads from git's configuration files itself;
// what it cannot be sure of goes back. (Directories that cannot be written,
// files that cannot be read and sticky directories need another user:
// rs/perm-compat.sh.)

const UNCAUGHT = "the TypeScript writes and then ends in an uncaught error; seen before the first write";
const UNSURE = "git's configuration in a form the pre-read does not read";
setup("core.hooksPath in the user's .gitconfig names a directory", { setup: ["mkdir ../hooks-dir", "git config --global core.hooksPath \"$(cd .. && pwd)/hooks-dir\""], after: [hooksIn("../hooks-dir")] });
setup("core.hooksPath in the user's .gitconfig starts with ~", { setup: ["mkdir \"$HOME/my hooks\"", "git config --global core.hooksPath '~/my hooks'"], after: [hooksIn("\"$HOME/my hooks\"")] });
setup("core.hooksPath in the user's .gitconfig names a file", { setup: ["echo x > ../hooks-file", "git config --global core.hooksPath \"$(cd .. && pwd)/hooks-file\""], after: ["cat ../hooks-file"], back: UNCAUGHT });
setup("core.hooksPath in the XDG configuration names a file", { setup: ["echo x > hooks-file", "mkdir -p \"$XDG_CONFIG_HOME/git\"", "printf '[core]\\n\\thooksPath = hooks-file\\n' > \"$XDG_CONFIG_HOME/git/config\""], back: UNCAUGHT });
setup("core.hooksPath in the XDG configuration, the repository's own wins", { setup: ["mkdir -p \"$XDG_CONFIG_HOME/git\" mine", "printf '[core]\\n\\thooksPath = nowhere/x\\n' > \"$XDG_CONFIG_HOME/git/config\"", "git config core.hooksPath mine"], after: [hooksIn("mine")] });
setup("core.hooksPath names a path through a file", { setup: ["echo x > hooks-file", "git config core.hooksPath hooks-file/sub"], back: UNCAUGHT });
setup("core.hooksPath names a directory to be made", { setup: ["git config core.hooksPath made/by/setup"], after: [hooksIn("made/by/setup")] });
// git names the link's target, which the TypeScript then makes (marked as
// handed back at 2c2a075, whose pre-read looked at the link itself).
setup("core.hooksPath names a link to nowhere", { setup: ["ln -s nowhere hooks-link", "git config core.hooksPath hooks-link"], after: [hooksIn("nowhere"), "ls -l hooks-link | sed 's/.* -> //'"] });
setup("core.hooksPath with .. in it", { setup: ["mkdir -p a hooks", "git config core.hooksPath a/../hooks"], after: [hooksIn("hooks")], back: UNSURE });
setup("core.hooksPath in quotes", { setup: ["mkdir ' lead'", "git config core.hooksPath ' lead'"], after: [hooksIn("' lead'")], back: UNSURE });
setup("an include in the repository's configuration", { setup: ["printf '[core]\\n\\thooksPath = h\\n' > ../extra.config", "git config include.path ../../extra.config"], after: [HOOKS], back: UNSURE });
setup("GIT_DIR in the environment", { env: { GIT_DIR: ".git" }, back: "GIT_DIR moves what git finds" });
setup("the pre-commit hook is a directory", { setup: ["mkdir -p .git/hooks/pre-commit"], back: UNCAUGHT });
setup("the post-checkout hook is a directory, not reached after a refusal of dede's own at post-merge", { setup: ["printf '#!/usr/bin/env python3\\n' > .git/hooks/post-merge", "printf '#!/bin/sh\\ndede guard\\n' > .git/hooks/pre-commit", "mkdir -p .git/hooks/post-checkout"] });
setup(".husky is a link to nowhere, and there is a package.json", { files: { "package.json": "{}\n" }, setup: ["ln -s nowhere .husky"], after: ["cat package.json"], back: UNCAUGHT });
setup(".husky is a directory and its pre-commit a directory", { files: { "package.json": "{}\n", ".husky/pre-commit/keep": "" }, after: ["cat package.json"], back: UNCAUGHT });
setup(".husky's pre-commit is a link to nowhere: a refusal of dede's own", { files: { "package.json": "{}\n" }, setup: ["mkdir .husky", "ln -s nowhere .husky/pre-commit"], after: ["cat package.json", "ls -A .husky"] });

// ═══════════════════════════ enc: the sync record where git finds it ═══════════════════════════
//
// Before its first write enc looks at every sync record git could take
// (rs/src/repo.rs): along the path as written and the real one, past a .git
// that git passes over, in a parent repository too. One it does not read the
// way the TypeScript does sends the invocation back.

add("enc: a file reached through a link into a repository whose record is a list", ["enc", "link/.env.prod"], {
  repo: false,
  setup: ["git init -q -b main real && printf '.env*\\n!.env*.enc\\n' > real/.gitignore && mkdir -p real/sub real/.git/dotenvdotenc && echo '[]' > real/.git/dotenvdotenc/state.json && printf 'A=1\\n' > real/sub/.env.prod && ln -s real/sub link"],
  after: ["ls -A real/sub", "cat real/.git/dotenvdotenc/state.json"],
  back: ODD_RECORD,
});
add("enc: a file reached through a link into a repository", ["enc", "link/.env.prod"], {
  repo: false,
  setup: ["git init -q -b main real && printf '.env*\\n!.env*.enc\\n' > real/.gitignore && mkdir -p real/sub && printf 'A=1\\n' > real/sub/.env.prod && ln -s real/sub link"],
  after: ["ls -A real/sub", "cd real/sub && " + PROBE + " enc .env.prod.enc .env.keys"],
});
add("enc: a record that is a list in a parent repository, the file in a nested one", ["enc", "nested/.env.prod"], {
  files: { "nested/.env.prod": "A=1\n" },
  setup: ["mkdir -p .git/dotenvdotenc && echo '[]' > .git/dotenvdotenc/state.json", "git init -q -b main nested && printf '.env*\\n!.env*.enc\\n' > nested/.gitignore"],
  after: ["ls -A nested", "cat .git/dotenvdotenc/state.json"],
  back: "a sync record that is not an object, in a repository around the one git finds: the pre-read does not judge which one git takes",
});
add("enc: another file's entry in the record is not of dede's shape", ["enc"], { files: { ".env.local": LOCAL, "state.fixture": '{"sub/.env.other": {"plain": 1}}\n' }, setup: [K1], after: [LS], back: ODD_RECORD });

// ═══════════════════════════ the verifier's cases ═══════════════════════════
//
// 285 cases an independent verifier wrote against the port at 24d24a9
// (rs/parity.more.mjs), in the order it wrote them.

const more = await import("./parity.more.mjs");
for (const testCase of more.cases) {
  if (cases.some((c) => c.name === testCase.name)) throw new Error(`two cases named ${JSON.stringify(testCase.name)}`);
  cases.push(testCase);
}

// ═══════════════════════════ the second check's cases ═══════════════════════════
//
// 63 cases a second independent check wrote against the repaired port at
// 2c2a075 (rs/parity.recheck.mjs): the hooks directory through symbolic
// links, worktrees and submodules, both sides of the large-value margin.

const recheck = await import("./parity.recheck.mjs");
for (const testCase of recheck.cases) {
  if (cases.some((c) => c.name === testCase.name)) throw new Error(`two cases named ${JSON.stringify(testCase.name)}`);
  cases.push(testCase);
}

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
