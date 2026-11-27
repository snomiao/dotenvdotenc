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
