// The verifier's cases for dede (Rust against TypeScript), kept as they were
// written and run against the port at 24d24a9, with the cases the port now
// hands back marked so. rs/parity.gen.mjs adds them to rs/parity.json, after
// its own; run them from there.
//
// Every key is a digit repeated 64 times, written by a shell line or by
// rs/parity/run.sh when the case runs (@1@ stands for the digit 1 sixty-four
// times; see there); every value is made up. Fixed ciphertexts (made once with
// @dotenvx/primitives for those throwaway keys) are kept in
// rs/parity.more.fixtures.json; `node rs/parity.gen.mjs --seal` makes the
// ones it lacks.

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
    .map(([suffix, digits]) => `printf 'DOTENV_PRIVATE_KEY${suffix}=%s\\n' "${[].concat(digits).map(key).join(",")}"`)
    .join("; ")}; } > ${file}`;

const FIXTURES_PATH = path.join(HERE, "parity.more.fixtures.json");
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
function stateText(entries, { salt = SALT } = {}) {
  const all = {};
  for (const [file, [plain, enc]] of Object.entries(entries)) {
    all[file] = { plain: sha(plain), enc: sha(enc), salt };
    all[file].keys = Object.fromEntries(Object.entries(scan(plain).parsed).map(([k, v]) => [k, hmac(salt, JSON.stringify(v))]));
    all[file].notes = hmac(salt, commentsOf(lf(plain)));
  }
  return JSON.stringify(all, null, 2) + "\n";
}

const IGNORE = ".env*\n!.env*.enc\n";
const INIT = "git init -q -b main";
const IDENT = "git config --global user.name Parity && git config --global user.email parity@example.com";
const STATE = "mkdir -p .git/dotenvdotenc && mv state.fixture .git/dotenvdotenc/state.json";
const PROBE = "node <REPO>/rs/parity/probe.mjs";
const GIT_LOG = "cat <HOME>/git.log 2>&1";
const LS = "ls -A | grep -v '^\\.git$' | while read -r f; do stat -c '%a %F %n' \"$f\"; done";

export const cases = [];
/** A key in a file or a variable: placeholders rs/parity/run.sh expands. */
const PLACEHOLDER = /@[0-9A-Fa-fN]@/;
function add(name, args, o = {}) {
  const repo = o.repo === undefined ? IGNORE : o.repo;
  const files = Object.fromEntries(Object.entries({ ...(repo === false || repo === "" ? {} : { ".gitignore": repo }), ...(o.files || {}) }).filter(([, text]) => text !== undefined));
  const keyed = Object.keys(files).filter((file) => PLACEHOLDER.test(files[file]));
  const expand = keyed.length ? [`sh <REPO>/rs/parity/run.sh --expand ${keyed.map((file) => `'${file}'`).join(" ")}`] : [];
  const setup = [...(repo === false ? [] : [INIT]), ...("state.fixture" in files ? [STATE] : []), ...expand, ...(o.setup || [])];
  const env = { ...(o.keys ? { PARITY_KEYS: o.keys } : {}), ...(o.env || {}) };
  const keyedEnv = Object.keys(env).filter((name) => PLACEHOLDER.test(env[name]));
  if (keyedEnv.length) env.PARITY_EXPAND = keyedEnv.join(" ");
  const testCase = { name, args };
  if (o.stdin !== undefined) testCase.stdin = o.stdin;
  if (Object.keys(env).length) testCase.env = env;
  if (Object.keys(files).length) testCase.files = files;
  if (setup.length) testCase.setup = setup;
  testCase.after = [...(o.after || [LS]), ...(o.back || o.nolog ? [] : [GIT_LOG])];
  if (o.back) testCase.handback = o.back;
  if (o.timeout) testCase.timeout = o.timeout;
  if (cases.some((c) => c.name === name)) throw new Error(`two cases named ${JSON.stringify(name)}`);
  cases.push(testCase);
}

/** Why a case with a very large value goes back (see primitives::QUOTED_SPAN_LIMIT in rs/src). */
const BEYOND = "beyond what bun's regular expressions do, or within the margin kept from it";

const LOCAL = "# api\nAPI_KEY=dummy-1\nNAME=\"hello world\"\n";
const LOCAL_ENC = encFile(".env.local", 1, LOCAL);
const K1 = keysFile({ _LOCAL: 1 });
const HEAD1 = header(".env.local", 1);

// ═══════════════════════════ get: how a ciphertext is read ═══════════════════════════
//
// decrypt() of @dotenvx/primitives reads the text after `encrypted:` with
// Buffer.from(…, "base64"), which is lenient in bun's own way.

// 97 + 1 bytes: one `=` of padding; with a `+` and a `/` in it.
const PAD1 = seal(1, "x", "pad1", (c) => c.endsWith("=") && !c.endsWith("==") && c.includes("+") && c.includes("/"));
// 97 + 0 bytes: `==`.
const PAD2 = seal(1, "", "pad2", (c) => c.endsWith("==") && c.includes("+") && c.includes("/"));
// 97 + 2 bytes: no padding.
const PAD0 = seal(1, "xy", "pad0", (c) => !c.endsWith("=") && c.includes("+") && c.includes("/"));
const b64 = (c) => c.slice("encrypted:".length);
const ct = (name, line) => add(`get: ${name}`, ["get", "A"], { files: { ".env.local.enc": `${HEAD1}${line}\n` }, setup: [K1] });
ct("base64 in the URL alphabet", `A=encrypted:${b64(PAD1).replace(/\+/g, "-").replace(/\//g, "_")}`);
ct("base64 without its one = of padding", `A=encrypted:${b64(PAD1).replace(/=+$/, "")}`);
ct("base64 without its == of padding", `A=encrypted:${b64(PAD2).replace(/=+$/, "")}`);
ct("base64 with one = where two belong", `A=encrypted:${b64(PAD2).replace(/==$/, "=")}`);
ct("base64 with padding it does not need", `A=encrypted:${b64(PAD0)}==`);
ct("base64 with three = at the end", `A=encrypted:${b64(PAD1)}==`);
ct("base64 with spaces inside, in quotes", `A="encrypted:${b64(PAD1).slice(0, 40)} ${b64(PAD1).slice(40, 80)}  ${b64(PAD1).slice(80)}"`);
ct("base64 over two lines, in quotes", `A="encrypted:${b64(PAD1).slice(0, 60)}\n${b64(PAD1).slice(60)}"`);
ct("base64 with characters that are none in between", `A="encrypted:${b64(PAD1).slice(0, 30)}!*.,;:${b64(PAD1).slice(30)}"`);
ct("base64 followed by more after the padding", `A=encrypted:${b64(PAD1)}QUJD`);
ct("base64 followed by text that is none after the padding", `A="encrypted:${b64(PAD1)} (old)"`);
ct("base64 with a = in the middle", `A=encrypted:${b64(PAD1).slice(0, 64)}=${b64(PAD1).slice(64)}`);
ct("base64 cut short by one character", `A=encrypted:${b64(PAD0).slice(0, -1)}`);
ct("base64 cut to one byte", `A=encrypted:QQ==`);
ct("nothing after encrypted:", `A=encrypted:`);
ct("encrypted: in upper case is not encrypted", `A=ENCRYPTED:${b64(PAD1)}`);
ct("a space after encrypted:", `A="encrypted: ${b64(PAD1)}"`);
ct("the ciphertext twice in one value", `A=encrypted:${b64(PAD0)}${b64(PAD0)}`);
ct("in single quotes", `A='encrypted:${b64(PAD1)}'`);
ct("in backticks", `A=\`encrypted:${b64(PAD1)}\``);
ct("with export and spaces around the equals sign", `  export   A  =  encrypted:${b64(PAD1)}   # note`);
ct("with a colon instead of the equals sign", `A: encrypted:${b64(PAD1)}`);
add("get: a ciphertext with a letter beyond ASCII goes back", ["get", "A"], {
  files: { ".env.local.enc": `${HEAD1}A="encrypted:${b64(PAD1).slice(0, 30)}é${b64(PAD1).slice(30)}"\n` },
  setup: [K1],
  back: "ciphertext with characters beyond ASCII: bun's base64 reading of it was not recorded",
});

// ═══════════════════════════ get: how a private key is read ═══════════════════════════
//
// Buffer.from(key, "hex"), lenient again; a keys file is split at commas and
// not trimmed, a variable is taken whole.

const K = "@1@";
const keyLine = (name, line, o = {}) => add(`get: the key ${name}`, ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC, ".env.keys": `${line}\n` }, ...o });
// (the keys below are the digit 1 or 2 sixty-four times, made up, and stand
// here as @1@ and @2@, which rs/parity/run.sh expands when the case runs)
const one = () => "@1@";
keyLine("in double quotes", `DOTENV_PRIVATE_KEY_LOCAL="${one()}"`);
keyLine("in single quotes with spaces around", `DOTENV_PRIVATE_KEY_LOCAL = '${one()}'  # mine`);
keyLine("with export", `export DOTENV_PRIVATE_KEY_LOCAL=${one()}`);
keyLine("followed by letters that are no hex", `DOTENV_PRIVATE_KEY_LOCAL=${one()}zz`);
keyLine("followed by one more digit", `DOTENV_PRIVATE_KEY_LOCAL=${one()}1`);
keyLine("followed by two more digits", `DOTENV_PRIVATE_KEY_LOCAL=${one()}11`);
keyLine("one digit short", `DOTENV_PRIVATE_KEY_LOCAL=${"1".repeat(63)}`);
keyLine("with 0x in front", `DOTENV_PRIVATE_KEY_LOCAL=0x${one()}`);
keyLine("with a space in the middle, in quotes", `DOTENV_PRIVATE_KEY_LOCAL="${"1".repeat(32)} ${"1".repeat(32)}"`);
keyLine("after a comma and a space", `DOTENV_PRIVATE_KEY_LOCAL="@2@, ${one()}"`);
keyLine("before a comma and a space", `DOTENV_PRIVATE_KEY_LOCAL="${one()} ,@2@"`);
keyLine("under a name that only starts like one", `DOTENV_PRIVATE_KEYRING=${one()}`);
keyLine("under a lower-case name", `dotenv_private_key_local=${one()}`);
keyLine("given twice, the first one wrong", `DOTENV_PRIVATE_KEY_LOCAL=@2@\nDOTENV_PRIVATE_KEY_LOCAL=${one()}`);
keyLine("in a file with a byte order mark", `﻿DOTENV_PRIVATE_KEY_LOCAL=${one()}`);
keyLine("in a file with CRLF line endings", `# keys\r\nDOTENV_PRIVATE_KEY_LOCAL=${one()}\r`);
keyLine("with a colon instead of the equals sign", `DOTENV_PRIVATE_KEY_LOCAL: ${one()}`);
keyLine("that is all zeros", `DOTENV_PRIVATE_KEY_LOCAL=@0@`);
keyLine("that is the group order", `DOTENV_PRIVATE_KEY_LOCAL=@N@`);
keyLine("with letters beyond ASCII goes back", `DOTENV_PRIVATE_KEY_LOCAL=${"1".repeat(62)}é1`, { back: "a private key with characters beyond ASCII: bun's hex reading of it was not recorded" });
const envKey = (name, value, o = {}) => add(`get: the key in the environment ${name}`, ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, env: { DOTENV_PRIVATE_KEY_LOCAL: value }, ...o });
// (written as a shell-free literal: the digit 1, 64 times, is no secret)
envKey("with a space in front", ` ${K}`);
envKey("with a newline at the end", `${K}\n`);
envKey("followed by one more digit", `${K}1`);
envKey("followed by a comma and nothing", `${K},`);
envKey("after a comma", `,${K}`);
envKey("empty, and the right one in .env.keys", "", { setup: [K1] });
add("get: a DOTENV_PUBLIC_KEY variable for it, and no private key", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, env: { DOTENV_PUBLIC_KEY_LOCAL: pub(1) } });
add("get: DOTENV_PUBLIC_KEY variables that name object members", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { DOTENV_PUBLIC_KEY: "constructor", DOTENV_PUBLIC_KEY_A: "__proto__", DOTENV_PUBLIC_KEY_B: "7" } });

// ═══════════════════════════ get: headers, names, arguments ═══════════════════════════

const BODY1 = encBody(1, LOCAL);
const head = (name, text, args = ["get", "API_KEY"]) => add(`get: ${name}`, args, { files: { ".env.local.enc": text }, setup: [K1] });
head("a header with a space at its end", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}" \n\n${BODY1}`);
head("a header in upper-case hex", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1).toUpperCase()}"\n\n${BODY1}`);
head("a header with a lower-case suffix", `${BANNER}\nDOTENV_PUBLIC_KEY_local="${pub(1)}"\n\n${BODY1}`);
head("a header after a blank line", `${BANNER}\n\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\n${BODY1}`);
head("a header with one quote only", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}\n\n${BODY1}`);
head("a header in single quotes", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL='${pub(1)}'\n\n${BODY1}`);
head("a header without the blank line after it", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n${BODY1}`);
head("a header with two blank lines after it", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\n\n${BODY1}`);
head("a header behind eight banner lines", `${BANNER}\n${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\n${BODY1}`);
head("a header of another file's name", `${BANNER}\nDOTENV_PUBLIC_KEY_PRODUCTION_EU_2="${pub(1)}"\n\n${BODY1}`);
head("a byte order mark before the banner", `﻿${LOCAL_ENC}`);
head("a byte order mark before a bare header", `﻿DOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n\n${BODY1}`);
head("only CR line endings", LOCAL_ENC.replace(/\n/g, "\r"));
head("CRLF and no final newline", LOCAL_ENC.replace(/\n$/, "").replace(/\n/g, "\r\n"));
head("the name at the end of the file without a newline", LOCAL_ENC.replace(/\n$/, ""), ["get", "NAME"]);
head("a public key that is no point of the curve", `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="02${"0".repeat(64)}"\n\n${BODY1}`);
add("get: a name with a newline at its end", ["get", "API_KEY\n"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a name with a letter beyond ASCII", ["get", "API_KÉY"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a name that is one underscore", ["get", "_"], { files: { ".env.local.enc": encFile(".env.local", 1, "_=under\n__=two\n") }, setup: [K1] });
add("get: valueOf is a name every object has", ["get", "valueOf"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], back: "the TypeScript ends in an uncaught TypeError" });
add("get: a name close to one every object has", ["get", "Constructor"], { files: { ".env.local.enc": encFile(".env.local", 1, "Constructor=c\nprototype=p\nlength=l\nname=n\n") }, setup: [K1] });
add("get: the last of a repeated name is empty", ["get", "L"], { files: { ".env.local.enc": `${HEAD1}L=${seal(1, "first", "L#0")}\nL=\n` }, setup: [K1] });
add("get: the first of a repeated name is damaged, the last is fine", ["get", "L"], { files: { ".env.local.enc": `${HEAD1}L=encrypted:AAAA\nL=${seal(1, "second", "L#1")}\n` }, setup: [K1] });
add("get: an empty file argument", ["get", "API_KEY", ""], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: the directory as the file argument", ["get", "API_KEY", "."], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: the root as the file argument", ["get", "API_KEY", "/"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a file argument ending in a slash", ["get", "API_KEY", ".env.local/"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: an .enc of an .enc", ["get", "API_KEY", ".env.local.enc.enc"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a file argument with a percent sign and a format letter", ["get", "API_KEY", "100%%/%s%d%o.txt"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: a file argument with letters beyond ASCII, a space and a newline", ["get", "API_KEY", "dïr 1/über\nx"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("get: file names in upper case, with dashes and digits", ["get", "V"], {
  files: { ".env.LOCAL.enc": encFile(".env.LOCAL", 1, "V=same\n", "u"), ".env.a-b_c.9.enc": encFile(".env.a-b_c.9", 1, "V=same\n", "d"), ".env.keys.me.enc": encFile(".env.keys.me", 1, "V=same\n", "k") },
  setup: [K1],
});
add("get: a directory with an env name beside the .enc files", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC, ".env.d/keep": "", ".env.conf.enc/keep": "" }, setup: [K1], back: "an .enc that is a directory ends the TypeScript in an uncaught EISDIR" });
add("get: a directory with an env name and no .enc of it", ["get", "API_KEY"], { files: { ".env.local.enc": LOCAL_ENC, ".env.d/keep": "" }, setup: [K1] });
const BIG = "v".repeat(70000) + "é😀\n".repeat(10) + "end";
add("get: a value larger than a pipe's buffer", ["get", "BIG"], { files: { ".env.local.enc": `${HEAD1}BIG="${seal(1, BIG, "big")}"\n` }, setup: [K1], after: [] });
add("get: git is not installed", ["get", "API_KEY"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("get: run from a directory reached through a symlink", ["get", "API_KEY", "../.env.local"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1, "mkdir -p real/sub && ln -s real/sub link"], env: { X_CD: "link" } });

// ═══════════════════════════ status, diff, keys ═══════════════════════════

const KP = keysFile({ _PROD: 1 });
add("status: git is not installed", ["status"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("diff: git is not installed", ["diff"], { files: { ".env.local": "API_KEY=other\n", ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("keys: git is not installed", ["keys"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("status: inside the .git directory", ["status"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_CD: ".git" } });
add("status: in a bare repository", ["status"], { repo: false, setup: ["git init -q --bare ."] });
add("status: a directory with an env name", ["status"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC, ".env.d/keep": "" }, setup: [K1] });
add("diff: a directory with an env name", ["diff"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC, ".env.d/keep": "" }, setup: [K1] });
add("status: the plaintext is a directory, the .enc a file", ["status"], { files: { ".env.prod/keep": "", ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") }, setup: [KP] });
add("status: unmanaged files with spaces, letters beyond ASCII and a percent sign in their paths", ["status"], {
  files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC, "my dir/.env.prod": "A=1\n", "ünï/.env.staging": "A=1\n", "100%%s/.env.qa": "A=1\n", "a\tb/.env.x": "A=1\n" },
  setup: [K1],
});
add("status: an untracked repository inside the repository", ["status"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC, "nested/.env.prod": "A=1\n" }, setup: [K1, "git init -q nested"] });
add("status: names that are numbers come first in the record", ["status"], {
  files: { ".env.prod": "B=1\n10=ten\n9=nine\nA=2\n007=bond\n4294967294=max\n4294967295=over\n0=zero\n-1=minus\n1.5=dot\n", ".env.prod.enc": encFile(".env.prod", 1, "B=1\n10=ten\n9=nine\nA=2\n007=bond\n4294967294=max\n4294967295=over\n0=zero\n-1=minus\n1.5=dot\nEXTRA=1\n", "num") },
  setup: [KP],
});
add("diff: names that are numbers, more than six differ", ["diff"], {
  files: { ".env.prod": "B=x\n10=x\n9=x\nA=x\n007=x\n4294967294=x\n4294967295=x\n0=x\n-1=x\n1.5=x\n", ".env.prod.enc": encFile(".env.prod", 1, "B=1\n10=ten\n9=nine\nA=2\n007=bond\n4294967294=max\n4294967295=over\n0=zero\n-1=minus\n1.5=dot\n", "num") },
  setup: [KP],
});
add("status: file names in upper case, with dashes and digits; examples are passed over", ["status"], {
  files: { ".env.LOCAL": "V=1\n", ".env.a-b_c.9": "V=1\n", ".env.keys.me": "V=1\n", ".env.example": "V=\n", ".env.sample": "V=\n", ".env.template": "V=\n", ".env.vault": "x\n", ".env.me": "x\n", ".env.dede-tmp-1-abcd": "x\n", ".env.": "x\n", ".envrc": "x\n", ".env..x": "x\n", ".env.a b": "x\n" },
});
add("status: --quiet with every other flag, and a file named twice", ["--force", "status", ".env.local", "--all", "-y", "--quiet", "./.env.local.enc", "--yes"], { repo: false, files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("status: DOTENV_KEYS_FILE names a file relative to the directory it is run in", ["status", "../.env.local"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: ["mkdir sub", keysFile({ _X: 1 }, "sub/k")], env: { DOTENV_KEYS_FILE: "k", X_CD: "sub" } });
add("status: --env-keys-file= given twice, the last one counts", ["status", "--env-keys-file=nowhere", "--env-keys-file=k", "-fk", "k2"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [keysFile({ _X: 2 }, "k"), keysFile({ _X: 1 }, "k2")] });
add("status: a sync record with a byte order mark", ["status"], {
  files: { ".env.local": "API_KEY=changed\nNAME=\"hello world\"\n", ".env.local.enc": LOCAL_ENC, "state.fixture": "﻿" + stateText({ ".env.local": [LOCAL, LOCAL_ENC] }) },
  setup: [K1],
});
add("status: a sync record with CRLF line endings and a repeated entry", ["status"], {
  files: { ".env.local": "API_KEY=changed\nNAME=\"hello world\"\n", ".env.local.enc": LOCAL_ENC, "state.fixture": (stateText({ ".env.local": ["X=1\n", "x"] }).replace(/\n\}\n$/, ",\n") + stateText({ ".env.local": [LOCAL, LOCAL_ENC] }).replace(/^\{\n/, "")).replace(/\n/g, "\r\n") },
  setup: [K1],
});
add("status: a sync record whose entry has an empty salt", ["status"], {
  files: { ".env.local": "API_KEY=changed\nNAME=\"hello world\"\n", ".env.local.enc": LOCAL_ENC, "state.fixture": stateText({ ".env.local": [LOCAL, LOCAL_ENC] }).replace(SALT, "") },
  setup: [K1],
});
add("status: a sync record whose entry lacks its hashes", ["status"], { files: { ".env.local": "API_KEY=changed\n", ".env.local.enc": LOCAL_ENC, "state.fixture": '{".env.local":{}}' }, setup: [K1] });
add("status: a sync record with entries under names every object has", ["status"], { files: { ".env.local": "API_KEY=changed\n", ".env.local.enc": LOCAL_ENC, "state.fixture": '{"constructor":{"plain":"x"},"__proto__":{"plain":"y"},"toString":"z"}' }, setup: [K1] });
add("keys: an .enc with CRLF and no blank line after the header", ["keys"], { files: { ".env.local.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n${BODY1}`.replace(/\n/g, "\r\n") }, setup: [K1] });
add("keys: not an env file", ["keys", "README.md"], { files: { ".env.local.enc": LOCAL_ENC, "README.md": "x\n" }, setup: [K1] });
add("keys: the word link among file names", ["keys", ".env.local", "link"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("keys: DOTENV_PUBLIC_KEY variables with odd values", ["keys"], { files: { ".env.local.enc": LOCAL_ENC, ".env.production.enc": encFile(".env.production", 2, "A=1\n") }, env: { DOTENV_PUBLIC_KEY: "constructor", DOTENV_PUBLIC_KEY_A: "__proto__", DOTENV_PUBLIC_KEY_B: "7", DOTENV_PUBLIC_KEY_C: "", DOTENV_PUBLIC_KEY_PRODUCTION: pub(2) } });
add("keys: a private key in the environment with a space in front, and the same one in .env.keys", ["keys"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { DOTENV_PRIVATE_KEY_LOCAL: ` ${K}` } });
add("keys link: more words after the target", ["keys", "link", "../keys", "again", "--force"], { setup: [keysFile({ _LOCAL: 1 }, "../keys"), "chmod 600 ../keys"] });
add("keys link: a target with a percent sign, a space and letters beyond ASCII", ["keys", "link", "../kéys 100%%s"], { setup: [keysFile({ _LOCAL: 1 }, "'../kéys 100%%s'"), "chmod 640 '../kéys 100%%s'"] });
add("keys link: a target that is itself a link", ["keys", "link", "../link-to-keys"], { setup: [keysFile({ _LOCAL: 1 }, "../keys"), "chmod 600 ../keys", "ln -s keys ../link-to-keys"], after: [LS, "readlink .env.keys"] });
add("keys link: git is not installed", ["keys", "link", "../keys"], { setup: [keysFile({ _LOCAL: 1 }, "../keys"), "chmod 600 ../keys"], env: { X_NOGIT: "1" }, nolog: true });

// ═══════════════════════════ enc and dec ═══════════════════════════

const ENC_AFTER = (file = ".env.prod.enc", keys = ".env.keys") => [LS, `${PROBE} enc ${file} ${keys}`, `${PROBE} state`];
const NASTY = [
  "﻿# first line after a byte order mark",
  "  export   SPACED  =  spaced out   # and a comment",
  "\tTABBED\t=\t'single # not a comment'",
  'DQ="double \\"quoted\\" with \\n and \\t and \\\\"',
  "BT=`back 'tick' \"x\"`",
  "EMPTY_DQ=\"\"",
  "EMPTY_SQ=''",
  "EMPTY=",
  "DOLLAR=$HOME ${USER:-x} $(id) \\$",
  "PCT=100%% %s %d",
  "UNI=naïve café ✓ 😀  nbsp　wide",
  "EQ=a=b==c",
  "SAME=1",
  "SAME_TOO=1",
  "ME=x",
  "ME_TOO=x",
  "REGEX=^$.*+?()[]{}|\\/-",
  "LOOKS=encrypted:notreally",
  "COLON: colon value",
  "",
  "",
  "LAST_NO_NEWLINE=end",
].join("\n");
add("enc: a plaintext in every awkward form at once", ["enc"], { files: { ".env.prod": NASTY }, setup: [KP], after: ENC_AFTER() });
add("enc: the same with CRLF line endings", ["enc"], { files: { ".env.prod": NASTY.replace(/\n/g, "\r\n") }, setup: [KP], after: ENC_AFTER() });
add("dec: an .enc in every awkward form at once", ["dec"], { files: { ".env.prod.enc": encFile(".env.prod", 1, NASTY.slice(1), "nasty") }, setup: [KP], after: [LS, "od -c .env.prod | tail -n +1", `${PROBE} state`] });
add("enc: names that are numbers, out of order", ["enc"], { files: { ".env.prod": "B=1\n10=ten\n9=nine\nA=2\n007=bond\n4294967294=max\n4294967295=over\n0=zero\n-1=minus\n1.5=dot\n" }, setup: [KP], after: ENC_AFTER() });
add("enc: a value that starts with encrypted:", ["enc"], { files: { ".env.prod": "A=encrypted:notreally\nB=\"encrypted:\"\n" }, setup: [KP], after: ENC_AFTER() });
add("enc: a value of 200,000 characters", ["enc"], { files: { ".env.local": `SMALL=1\nBIG=${"abcdefghij".repeat(20000)}\nAFTER=2\n` }, setup: [K1], after: [LS, `${PROBE} enc .env.local.enc .env.keys | wc -c`, `${PROBE} enc .env.local.enc .env.keys | cut -c1-80`, `${PROBE} state`], timeout: 300, back: BEYOND });
add("enc: three hundred names", ["enc"], { files: { ".env.local": Array.from({ length: 300 }, (_, i) => `NAME_${i}=value ${i}\n`).join("") }, setup: [K1], after: [LS, `${PROBE} enc .env.local.enc .env.keys | tail -n 3`, `${PROBE} state | cut -c1-200`], timeout: 300 });
add("enc: the sync record's place is a directory", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1, "mkdir -p .git/dotenvdotenc/state.json"], after: [LS, "ls .git/dotenvdotenc | sed 's/tmp-.*/tmp-<pid>-<random>/'", `${PROBE} enc .env.local.enc .env.keys`] });
add("enc: the sync record's directory is a file", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1, "echo x > .git/dotenvdotenc"], after: [LS, "cat .git/dotenvdotenc", `${PROBE} enc .env.local.enc .env.keys`] });
add("dec: the sync record's place is a directory", ["dec"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1, "mkdir -p .git/dotenvdotenc/state.json"], after: [LS, "ls .git/dotenvdotenc | sed 's/tmp-.*/tmp-<pid>-<random>/'", "cat .env.local"] });
add("enc: the plaintext is a directory", ["enc"], { files: { ".env.stage/keep": "", ".env.prod": "A=1\n" }, setup: [KP], after: [LS, `${PROBE} keys .env.keys .env.prod.enc`] });
add("dec: the plaintext is a directory", ["dec", "--force"], { files: { ".env.prod/keep": "", ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") }, setup: [KP] });
add("enc: a keys file named like an env file, without --key", ["enc"], { files: { ".env.keys.me": `# backup\nDOTENV_PRIVATE_KEY_PROD=@3@\nOTHER=x\n` }, after: [LS, `${PROBE} keys .env.keys .env.keys.me.enc`, `${PROBE} enc .env.keys.me.enc .env.keys | sed 's/3\\{64\\}/<the key in it>/'`] });
add("enc: git is not installed", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("dec: git is not installed", ["dec"], { files: { ".env.local.enc": LOCAL_ENC }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
add("enc: with a umask that lets nobody in", ["enc"], { files: { ".env.local": LOCAL }, env: { X_UMASK: "0777" }, after: [LS, "stat -c '%a %n' .git/dotenvdotenc .git/dotenvdotenc/state.json"] });
add("enc: with a umask that lets everybody in", ["enc"], { files: { ".env.local": LOCAL }, env: { X_UMASK: "0000" }, after: [LS, "stat -c '%a %n' .git/dotenvdotenc .git/dotenvdotenc/state.json"] });
add("enc: a key of that name in the environment in upper case, with a second one after a comma", ["enc"], { files: { ".env.local": LOCAL }, env: { DOTENV_PRIVATE_KEY_LOCAL: " @A@ , @b@" }, after: [LS, `${PROBE} enc .env.local.enc a`] });
add("enc: a key of that name in the environment that is too long", ["enc"], { files: { ".env.local": LOCAL }, env: { DOTENV_PRIVATE_KEY_LOCAL: `${K}11` } });
add("enc: a key of that name in the environment that is empty; .env.keys has one", ["enc"], { files: { ".env.local": LOCAL }, setup: [K1], env: { DOTENV_PRIVATE_KEY_LOCAL: "" }, after: ENC_AFTER() });
add("enc: a key of that name in .env.keys that is blank; a new one is made", ["enc"], { files: { ".env.local": LOCAL, ".env.keys": "DOTENV_PRIVATE_KEY_LOCAL=\n" }, after: [LS, `${PROBE} keys .env.keys .env.local.enc`] });
add("enc: a key of that name in .env.keys that is a comma and a key", ["enc"], { files: { ".env.local": LOCAL }, setup: [`printf 'DOTENV_PRIVATE_KEY_LOCAL=",%s"\\n' "${key(1)}" > .env.keys`], after: [LS, `${PROBE} keys .env.keys .env.local.enc`] });
add("enc: --key twice, the last one counts", ["enc", "--key", "NOPE", "--key", "ME", ".env.local"], { files: { ".env.local": LOCAL }, setup: [keysFile({ _ME: 4 })], after: [LS, `${PROBE} enc .env.local.enc .env.keys`] });
add("enc: --key with a name that has every allowed character", ["enc", ".env.local", "--key", "A_9_"], { files: { ".env.local": LOCAL }, keys: "_A_9_=5", after: [LS, `${PROBE} enc .env.local.enc 5`] });
add("enc -y: four files in two directories, from a third", ["enc", "-y", "../a/.env", "../b/.env.x", "../a/.env.y", "../b/.env.z"], {
  files: { "a/.env": "A=1\n", "a/.env.y": "A=2\n", "b/.env.x": "A=3\n", "b/.env.z": "A=4\n", "c/keep": "" },
  setup: [IDENT, "git add .gitignore c && git commit -q -m first"],
  env: { X_CD: "c" },
  after: ["git log --format=%s%n%an -- . && git show --stat --format= HEAD", "git status --short"],
});
add("enc -y: git is not installed", ["enc", "-y"], { files: { ".env.local": LOCAL }, setup: [K1], env: { X_NOGIT: "1" }, nolog: true });
const BASE = "# notes\nA=1\nB=2\nC=3\n";
const BASE_ENC = encFile(".env.local", 1, BASE, "base");
add("enc: both changed, the plaintext has CRLF line endings", ["enc"], {
  files: { ".env.local": "# notes\r\nA=mine\r\nB=2\r\nC=3\r\n", ".env.local.enc": encFile(".env.local", 1, "# notes\nA=1\nB=theirs\nC=3\n", "b2"), "state.fixture": stateText({ ".env.local": [BASE, BASE_ENC] }) },
  setup: [K1],
  after: [LS, "od -c .env.local", `${PROBE} enc .env.local.enc .env.keys`, `${PROBE} state`],
});
add("dec: both changed, a name added there twice", ["dec"], {
  files: { ".env.local": "# notes\nA=mine\nB=2\nC=3\n", ".env.local.enc": encFile(".env.local", 1, "# notes\nA=1\nB=2\nC=3\nD=one\nD=two\n", "dd"), "state.fixture": stateText({ ".env.local": [BASE, BASE_ENC] }) },
  setup: [K1],
  after: [LS, "cat .env.local"],
});
add("dec: both changed, a name over several lines removed there and comments changed here", ["dec"], {
  files: {
    ".env.prod": "# my notes\nA=1\nM=\"l1\nl2\nl3\"\nB=2\nC=mine\n",
    ".env.prod.enc": encFile(".env.prod", 1, "# notes\nA=1\nB=theirs\nC=3\n", "ml"),
    "state.fixture": stateText({ ".env.prod": ["# notes\nA=1\nM=\"l1\nl2\nl3\"\nB=2\nC=3\n", "x"] }).replace(sha("x"), sha(encFile(".env.prod", 1, "# notes\nA=1\nM=\"l1\nl2\nl3\"\nB=2\nC=3\n", "mlb"))),
  },
  setup: [KP],
  after: [LS, "cat .env.prod", `${PROBE} state`],
});

// ═══════════════════════════ guard ═══════════════════════════

const KEYLINE = (sep) => `printf 'DOTENV_PRIVATE_KEY_X${sep}%s\\n' "${key(7)}"`;
add("guard: a private key after white space only JavaScript counts as such", ["guard"], {
  setup: [IDENT, `${KEYLINE("=\\302\\240")} > a.txt`, `${KEYLINE(" :\\343\\200\\200\\357\\273\\277")} > b.txt`, `${KEYLINE("=\\302\\205")} > c.txt`, `${KEYLINE("\\342\\200\\250=\\342\\200\\251")} > d.txt`, "git add a.txt b.txt c.txt d.txt"],
});
add("guard: staged paths with spaces, a newline, a percent sign and letters beyond ASCII", ["guard"], {
  setup: [IDENT, "mkdir 'my dir' 'ünï' && echo A=1 > 'my dir/.env.prod' && echo A=1 > 'ünï/.env' && printf 'A=1\\n' > \"$(printf 'new\\nline.env')\" && echo x > '100%%s' && git add -f ."],
});
add("guard: a staged .enc with CRLF, no blank line after the header and a bad line", ["guard"], {
  files: { ".env.local.enc": `${BANNER}\nDOTENV_PUBLIC_KEY_LOCAL="${pub(1)}"\n${BODY1}OOPS=plain\n`.replace(/\n/g, "\r\n") },
  setup: [IDENT, "git add .env.local.enc"],
});
add("guard: a staged .enc that is empty, one that is only a banner, and an example's .enc", ["guard"], {
  files: { ".env.a.enc": "", ".env.b.enc": `${BANNER}\n`, ".env.example.enc": LOCAL_ENC, ".env.keys.enc": LOCAL_ENC, ".env.enc.enc": LOCAL_ENC },
  setup: [IDENT, "git add -f ."],
});
add("guard: in a repository without a commit, a staged file then removed from disk", ["guard"], { files: { ".env.prod": "A=1\n" }, setup: ["git add -f .env.prod", "rm .env.prod"] });
add("guard: an unmerged path", ["guard"], {
  files: { "f.txt": "base\n" },
  setup: [IDENT, "git add . && git commit -q -m base", "git checkout -q -b other && echo other > f.txt && git commit -q -am other", "git checkout -q main && echo main > f.txt && git commit -q -am main", "git merge other >/dev/null 2>&1 || true"],
});
add("guard: a staged submodule and a staged symlink to a keys file", ["guard"], {
  setup: [IDENT, "git init -q sub && git -C sub commit -q --allow-empty -m x", "git add sub 2>/dev/null", `${KEYLINE("=")} > ../outside-keys`, "ln -s ../outside-keys .env.keys.link && git add -f .env.keys.link"],
});
add("guard: git is not installed", ["guard"], { files: { ".env.prod": "A=1\n" }, env: { X_NOGIT: "1" }, nolog: true });
add("guard: inside the .git directory", ["guard"], { files: { ".env.prod": "A=1\n" }, env: { X_CD: ".git" } });
add("guard: --all with other flags and words", ["guard", "--force", "extra", "--all", "-y"], { repo: "", files: { ".env.prod": "A=1\n", ".env.keys": "x\n" }, setup: [IDENT, "git add -f . && git commit -q -m all"] });

// ═══════════════════════════ health ═══════════════════════════

const AGED = (date) => `GIT_AUTHOR_DATE='${date}T12:00:00Z' GIT_COMMITTER_DATE='${date}T12:00:00Z' git commit -q -m aged`;
const H_ENC = encFile(".env.local", 1, "API_TOKEN=t\nDB_PASSWORD=p\nA=1\nB.C-D=2\n", "h");
const health = (name, yaml, o = {}) =>
  add(`health: ${name}`, o.args || ["health", "--all"], { files: { ".env.local.enc": H_ENC, ".dede.yaml": yaml, ...(o.files || {}) }, setup: [IDENT, "git add -A && " + AGED("2001-02-03")], ...(o.back ? { back: o.back } : {}) });
health("words YAML 1.1 would read as true and false", 'rotate:\n  - keys: yes\n    note: no\n  - keys: [on, off, y, n]\n    files: Yes\n  - keys: "*"\n    every: 1y\n    note: on\n');
health("a note that looks like a date, a duration and a file name", 'rotate:\n  - keys: API_TOKEN\n    every: 1d\n    note: 2027-01-26\n  - keys: DB_PASSWORD\n    every: 2w\n    note: 90d\n  - keys: "*"\n    expires: 1999-12-31\n    note: ./docs/rotate.md (see there)\n');
health("a note with percent signs, an arrow and text beyond ASCII", 'rotate:\n  - keys: "*"\n    every: 1d\n    note: "100%% sure %s %d → ünïcode 😀"\n');
health("globs with a question mark, on names and on file names", 'rotate:\n  - keys: "?"\n    files: "?env.local"\n    every: 1d\n  - keys: "B?C?D"\n    files: ".env*"\n    every: 2d\n  - keys: "*_*"\n    files: "*.local"\n    every: 3d\n  - keys: "*"\n    files: "*env"\n    every: 4d\n');
health("an empty glob and an empty note", 'rotate:\n  - keys: ""\n    every: 1d\n  - keys: "*"\n    every: 5d\n    note: ""\n    warn: "0d"\n');
health("a duration with spaces, leading zeros and a quoted number", 'rotate:\n  - keys: API_TOKEN\n    every: 007d\n  - keys: DB_PASSWORD\n    every: "12 w"\n    warn: 0y\n  - keys: A\n    every: 999999y\n');
health("an expiry in the year 0000 and one in 9999", 'rotate:\n  - keys: API_TOKEN\n    expires: 0000-01-01\n  - keys: "*"\n    expires: "9999-12-31"\n    warn: 999999d\n');
health("an expiry on the day before 1970 and on 1970-01-01", 'rotate:\n  - keys: API_TOKEN\n    expires: 1969-12-31\n  - keys: "*"\n    expires: 1970-01-01\n');
health("an expiry on day 00, month 00 and month 13", "rotate:\n  - keys: A\n    expires: 2027-01-00\n");
health("an expiry on the 29th of February in a year that has none", 'rotate:\n  - keys: "*"\n    expires: 2023-02-29\n');
health("rules at the left margin with comments between the fields", "# rules\nrotate:   # the list\n\n- keys: API_TOKEN   # one\n  # between\n  every: 1d\n\n- files: [ '.env.local' , \".env\" ]   # two\n  every: never\n");
health("a list given for the note", 'rotate:\n  - keys: "*"\n    every: 1d\n    note: [a, b]\n', { back: "a list where one value belongs is turned into text by JavaScript" });
health("a field given twice", 'rotate:\n  - keys: A\n    keys: "*"\n    every: 1d\n', { back: "Bun.YAML decides which of two fields counts" });
health("a document marker", '---\nrotate:\n  - keys: "*"\n    every: 1d\n', { back: "YAML beyond the README shape" });
health("git is not installed", 'rotate:\n  - keys: "*"\n    every: 1d\n', { args: ["health"] });
cases[cases.length - 1].env = { X_NOGIT: "1" };
cases[cases.length - 1].after = [LS];
health("names every object has, and a name given twice", 'rotate:\n  - keys: "*"\n    every: 1d\n', { files: { ".env.local.enc": `${HEAD1}constructor=${seal(1, "c", "hc")}\ntoString=\nA=\n  export   A = ${seal(1, "a", "ha")}\n10=\n2=\n` } });
health("an .enc with CRLF and a last line without a newline", 'rotate:\r\n  - keys: "*"\r\n    every: 1d', { files: { ".env.local.enc": H_ENC.replace(/\n$/, "").replace(/\n/g, "\r\n") } });

// ═══════════════════════════ setup ═══════════════════════════

const SETUP_AFTER = [LS, "cat .gitignore", "for f in .git/hooks/pre-commit .git/hooks/post-merge .git/hooks/post-checkout .husky/pre-commit package.json; do [ -e \"$f\" ] && { stat -c '%a %n' \"$f\"; cat \"$f\"; }; done; true"];
const pkg = (name, text, o = {}) => add(`setup: ${name}`, ["setup"], { repo: "", files: { "package.json": text }, after: SETUP_AFTER, ...o });
pkg("a package.json with CRLF line endings", '{\r\n    "name": "x",\r\n    "version": "1.0.0"\r\n}\r\n');
pkg("a package.json indented by twelve spaces", '{\n            "name": "x"\n}');
pkg("a package.json indented by a space and a tab", '{\n \t"name": "x",\n \t"scripts": {\n \t \t"test": "t"\n \t}\n}\n');
pkg("a package.json that is an empty object", "{}");
pkg("a package.json with space before its brace", '  \n{\n    "name": "x"\n}\n');
pkg("a package.json with escapes, a slash and control characters in its text", '{\n  "name": "\\u00e9\\u0041\\/\\u0001\\u001f\\u007f\\u2028\\b\\f\\n\\r\\t\\"\\\\ é 😀 \\ud83d\\ude00",\n  "a\\u0000b": [],\n  "o": {},\n  "l": [1, [true, false, null], {"k": -5}],\n  "big": 123456789012345\n}\n');
pkg("a package.json with a name given twice and names every object has", '{\n  "name": "first",\n  "scripts": {"a": "1"},\n  "name": "second",\n  "constructor": 1,\n  "toString": {"x": 1},\n  "scripts": {"b": "2"}\n}\n');
pkg("a package.json whose prepare script is empty", '{\n  "scripts": {"prepare": "", "test": "t"},\n  "devDependencies": null,\n  "dependencies": {"husky": ""}\n}\n');
pkg("a package.json whose prepare script mentions husky as part of a word", '{\n  "scripts": {"prepare": "myhusky && husky_x"}\n}\n');
pkg("a package.json whose prepare script runs husky-init", '{\n  "scripts": {"prepare": "npx husky-init"}\n}\n');
pkg("a package.json whose prepare script is false and whose scripts come last", '{\n  "devDependencies": {"a": "1"},\n  "scripts": {"prepare": false}\n}\n');
pkg("a package.json whose prepare script is the number 0", '{\n  "scripts": {"prepare": 0}\n}\n');
pkg("a package.json whose scripts are null", '{\n  "scripts": null,\n  "dependencies": {"husky": "^9.0.0"}\n}\n');
pkg("a package.json with a byte order mark", '﻿{\n  "name": "x"\n}\n', { back: "JSON.parse does not take a byte order mark: an uncaught SyntaxError" });
pkg("a package.json with __proto__ as a name", '{\n  "__proto__": {"husky": "1"},\n  "name": "x"\n}\n');
pkg("a package.json whose prepare script is a list", '{\n  "scripts": {"prepare": ["x"]}\n}\n', { back: "a prepare script that is no text is turned into text by JavaScript" });
pkg("a package.json with a negative zero", '{\n  "n": -0\n}\n', { back: "a number JavaScript writes back in its own form" });
pkg("a package.json nested three hundred deep", `{"a":${"[".repeat(300)}${"]".repeat(300)}}`, { back: "nesting deeper than any real file" });
add("setup: a hook whose first line ends in CRLF, and one with a byte order mark", ["setup"], { repo: "", setup: ["mkdir -p .git/hooks", "printf '#!/bin/sh\\r\\necho hi\\r\\n' > .git/hooks/pre-commit", "printf '\\357\\273\\277#!/bin/sh\\necho hi\\n' > .git/hooks/post-merge", "chmod 700 .git/hooks/pre-commit; chmod 644 .git/hooks/post-merge"], after: [...SETUP_AFTER, "od -c .git/hooks/pre-commit | head -3; od -c .git/hooks/post-merge | head -2"] });
add("setup: hooks for ash, for env -S bash, and an empty one", ["setup"], { repo: "", setup: ["mkdir -p .git/hooks", "printf '#!/bin/ash\\n' > .git/hooks/pre-commit", "printf '#!/usr/bin/env -S bash -e\\nx\\n' > .git/hooks/post-merge", ": > .git/hooks/post-checkout"], after: SETUP_AFTER });
add("setup: a hook for fish after the ignore rules were written", ["setup"], { repo: "", setup: ["mkdir -p .git/hooks", "printf '#!/usr/bin/env fish\\n' > .git/hooks/pre-commit"], after: SETUP_AFTER });
add("setup: core.hooksPath names a file", ["setup"], { repo: "", setup: ["echo x > hooks-file", "git config core.hooksPath hooks-file"], after: SETUP_AFTER, back: "the TypeScript writes .gitignore, then ends in an uncaught EEXIST; seen before the first write" });
add("setup: core.hooksPath names a file, the ignore rules are there already", ["setup"], { setup: ["echo x > hooks-file", "git config core.hooksPath hooks-file"], after: SETUP_AFTER, back: "the TypeScript ends in an uncaught EEXIST; nothing was printed or changed yet" });
add("setup: the post-merge hook is a directory", ["setup"], { repo: "", setup: ["mkdir -p .git/hooks/post-merge"], after: SETUP_AFTER, back: "the TypeScript writes .gitignore and a hook, then ends in an uncaught EISDIR; seen before the first write" });
add("setup: the post-merge hook is a directory, the ignore rules and the first hook are there already", ["setup"], { setup: ["mkdir -p .git/hooks/post-merge", "printf '#!/bin/sh\\ndede guard\\n' > .git/hooks/pre-commit"], after: SETUP_AFTER, back: "the TypeScript ends in an uncaught EISDIR; nothing was printed or changed yet" });
add("setup: .husky is a file", ["setup"], { repo: "", files: { ".husky": "x\n", "package.json": "{}\n" }, after: SETUP_AFTER, back: "the TypeScript writes .gitignore, then ends in an uncaught EEXIST; seen before the first write" });
add("setup: a .gitignore with CRLF rules and a byte order mark", ["setup"], { repo: "﻿.env*\r\n!.env*.enc\r\n", after: [LS, "od -c .gitignore | head -12"] });
add("setup: a .gitignore that is not UTF-8", ["setup"], { repo: "", setup: ["printf 'caf\\351\\n' > .gitignore"], after: [LS, "od -c .gitignore | head -12"] });
add("setup: .gitignore is a directory", ["setup"], { repo: "", setup: ["mkdir .gitignore"], back: "reading a directory ends the TypeScript in an uncaught EISDIR" });
add("setup: git is not installed", ["setup"], { env: { X_NOGIT: "1" }, nolog: true });
add("setup: inside the .git directory", ["setup"], { env: { X_CD: ".git" } });
add("setup: with words and flags after it", ["setup", "--force", "husky", "-y", "--all"], { repo: "", after: SETUP_AFTER });

// ═══════════════════════════ usage and the shared flags ═══════════════════════════

add("usage: HELP in upper case is an unknown command", ["HELP"], { repo: false });
add("usage: --env-keys-file=x in the command's place", ["--env-keys-file=x", "status"], { repo: false });
add("usage: --key with a dash in the name", ["status", "--key", "A-B"], { repo: false });
add("usage: --key with an empty name", ["status", "--key", ""], { repo: false });
add("usage: --key with a name ending in a newline", ["status", "--key", "ME\n"], { repo: false });
add("usage: --key takes the next flag for its name", ["enc", "--key", "--force"], { repo: false });
add("usage: -fk takes the next flag for its path", ["status", "-fk", "--quiet"], { files: { ".env.local": LOCAL, ".env.local.enc": LOCAL_ENC }, setup: [K1] });
add("usage: the first problem among the flags is the one reported", ["frobnicate", "--key", "ok", "-fk"], { repo: false });
add("usage: help with a broken flag before a good one", ["help", "--key", "BAD-NAME", "--key", "GOOD"], { repo: false });

// ═══════════════════════════ what bun does before the program starts ═══════════════════════════

const NO_KEY = { ".env.local.enc": LOCAL_ENC };
const bunEnv = (name, files, o = {}) => add(`bun env: ${name}`, ["get", "API_KEY"], { ...o, files: { ...NO_KEY, ...files } });
const ALL_FILES = { ".env": "DOTENV_KEYS_FILE=from-env-file\n", ".env.development": "DOTENV_KEYS_FILE=from-development\n", ".env.production": "DOTENV_KEYS_FILE=from-production\n", ".env.test": "DOTENV_KEYS_FILE=from-test\n", ".env.local": "DOTENV_KEYS_FILE=from-local\n" };
for (const value of ["Production", "PRODUCTION", "prod", "production ", "TEST", "testing", "dev", "development ", "none"]) bunEnv(`NODE_ENV=${JSON.stringify(value)}`, ALL_FILES, { env: { NODE_ENV: value } });
bunEnv("a variable the environment has, set again in .env", { ".env": "TZ=Asia/Tokyo\nGIT_CONFIG_NOSYSTEM=0\nDOTENV_KEYS_FILE=k\n" });
bunEnv("a # right after the equals sign", { ".env": "DOTENV_KEYS_FILE=#k\n" });
bunEnv("a space and a quoted value after the equals sign", { ".env": 'DOTENV_KEYS_FILE= "my k" \n' });
bunEnv("several spaces inside a bare value", { ".env": "DOTENV_KEYS_FILE=a   b  c\n" });
bunEnv("a bare value with brackets, braces, semicolons and other signs", { ".env": "DOTENV_KEYS_FILE=a[1]{2}(3);&|<>!~^%*?,:@+-/=.\n" });
bunEnv("a name in lower case and one with digits", { ".env": "dotenv_keys_file=lower\nK9_x=1\nDOTENV_KEYS_FILE=upper\n" });
bunEnv("the same name in .env twice and in .env.local once, empty", { ".env": "DOTENV_KEYS_FILE=a\nDOTENV_KEYS_FILE=b\n", ".env.local": "DOTENV_KEYS_FILE=\n" });
bunEnv("a private key list in .env.development", { ".env.development": `DOTENV_PRIVATE_KEY_ANY=@2@,${K}\n` });
bunEnv("a private key in .env.development after a space", { ".env.development": `DOTENV_PRIVATE_KEY_ANY= ${K} # mine\n` });
bunEnv("GIT_DIR in .env.local reaches git", { ".env.local": "GIT_DIR=/nonexistent/x.git\nA=1\n" });
cases[cases.length - 1].args = ["status"];
bunEnv("a bunfig.toml in the parent directory", { "../bunfig.toml": 'preload = ["./nothing-here.ts"]\n', ".env": "DOTENV_KEYS_FILE=k\n" });
bunEnv("a package.json and a tsconfig.json here", { "package.json": '{"name":"x","type":"commonjs","scripts":{"dede":"echo no"}}\n', "tsconfig.json": '{"compilerOptions":{"jsx":"react","paths":{"*":["./nowhere/*"]}}}\n', ".env": "DOTENV_KEYS_FILE=k\n" });
bunEnv("a .env that is a link to nowhere", {}, { setup: ["ln -s nowhere .env"] });
bunEnv("a .env.development that is a link to a directory", {}, { setup: ["mkdir d && ln -s d .env.development"], back: "a file bun cannot read as text" });
bunEnv("lines that are only spaces or a tab", { ".env": "   \n\t\nDOTENV_KEYS_FILE=k\n" });
bunEnv("a name that starts with a digit", { ".env": "9LIVES=1\nDOTENV_KEYS_FILE=k\n" }, { back: "a name bun may read its own way" });
bunEnv("a wide space inside a bare value", { ".env": "DOTENV_KEYS_FILE=a　b\n" }, { back: "white space bun may read its own way" });
bunEnv("a form feed in the file", { ".env": "A=1\f\nDOTENV_KEYS_FILE=k\n" }, { back: "a control character" });
add("bun env: enc with a literal .env beside it, whose values reach the hooks of the commit", ["enc", "-y", ".env.local"], {
  files: { ".env": "HOOK_SEES=from dot env\n", ".env.local": LOCAL },
  setup: [IDENT, "git add .gitignore && git commit -q -m first", "mkdir -p .git/hooks && printf '#!/bin/sh\\nenv | grep -E \"^(HOOK_SEES|API_KEY|NAME)=\" | sort > hook-env.txt\\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit"],
  after: [LS, "cat hook-env.txt", "git log --format=%s"],
});

// ═══════════════════════════ what bun's regular expressions give up on ═══════════════════════════
//
// Under bun 1.4.0 the scanner of @dotenvx/primitives stops at a quoted value
// of more than 442,366 characters (double quotes; 540,669 in single quotes,
// 393,214 in backticks): that value and every assignment after it are not
// seen. And `upsert` cannot build its expression for a value whose escaped
// text is longer than 1,048,537 characters ("regular expression too large").
// The TypeScript therefore refuses such files or reads them short. These
// differed at 24d24a9; the port now hands back what comes within a third of
// the first limit or half of the second (primitives::QUOTED_SPAN_LIMIT).

const NODE_WRITE = (file, expr) => `node -e 'require("fs").writeFileSync(${JSON.stringify(file)}, ${expr})'`;
const BIG_ENC = (expr) =>
  `node -e 'const { encrypt, derive } = require("<REPO>/node_modules/@dotenvx/primitives"); const pub = derive("1".repeat(64)); const e = (v) => encrypt(pub, v); require("fs").writeFileSync(".env.prod.enc", ${JSON.stringify(BANNER + "\nDOTENV_PUBLIC_KEY_PROD=\"")} + pub + "\\"\\n\\n" + ${expr})'`;
const SIZES = [LS, "wc -c .env.prod .env.prod.enc 2>&1 | sed 's/^ *[0-9]* /<bytes> /'", "sed -E 's/encrypted:.*/encrypted:<ciphertext, left in the plaintext file>/' .env.prod | cut -c1-70"];
add("large: enc, a double-quoted value of 450,000 characters", ["enc"], { files: {}, setup: [KP, NODE_WRITE(".env.prod", '"A=1\\nBIG=\\"" + "a".repeat(450000) + "\\"\\nZ=2\\n"')], after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`], timeout: 300, back: BEYOND });
add("large: enc, a value of 300,000 characters in backticks", ["enc"], { files: {}, setup: [KP, NODE_WRITE(".env.prod", '"A=1\\nBIG=`" + "a".repeat(300000) + "`\\nZ=2\\n"')], after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`], timeout: 300, back: BEYOND });
add("large: enc, a bare value of 800,000 characters", ["enc"], { files: {}, setup: [KP, NODE_WRITE(".env.prod", '"A=1\\nBIG=" + "a".repeat(800000) + "\\nZ=2\\n"')], after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`], timeout: 300, back: BEYOND });
add("large: get a name that stands after a quoted ciphertext of 450,000 characters", ["get", "Z"], { files: {}, setup: [KP, BIG_ENC('"A=" + e("1") + "\\nBIG=\\"" + e("a".repeat(337000)) + "\\"\\nZ=" + e("2") + "\\n"')], after: [LS], timeout: 300, back: BEYOND });
add("large: dec an .enc with a quoted ciphertext of 450,000 characters", ["dec"], { files: {}, setup: [KP, BIG_ENC('"A=" + e("1") + "\\nBIG=\\"" + e("a".repeat(337000)) + "\\"\\nZ=" + e("2") + "\\n"')], after: SIZES, timeout: 300, back: BEYOND });
add("large: status of an .enc with a bare ciphertext of over a million characters", ["status"], { files: {}, setup: [KP, NODE_WRITE(".env.prod", '"A=1\\nBIG=" + "a".repeat(800000) + "\\nZ=2\\n"'), BIG_ENC('"A=" + e("1") + "\\nBIG=" + e("a".repeat(800000)) + "\\nZ=" + e("2") + "\\n"')], after: [LS], timeout: 300, back: BEYOND });
add("large: enc, a double-quoted value of 300,000 characters is within every limit", ["enc"], { files: {}, setup: [KP, NODE_WRITE(".env.prod", '"A=1\\nBIG=\\"" + "a".repeat(300000) + "\\"\\nZ=2\\n"')], after: [LS, `${PROBE} enc .env.prod.enc .env.keys | cut -c1-70`, `${PROBE} state`], timeout: 300, back: BEYOND });

// ═══════════════════════════ the line that should be unreachable ═══════════════════════════
//
// `dede: stopped at something this build does not handle…` is printed when
// something not imitated shows after writing began. At 24d24a9 it showed in
// the three setup scenes further up and in the enc scene below; the pre-read
// now finds them, and they go back before anything is written.

add("enc: a damaged sync record that git finds and the pre-read does not (an empty .git directory beside the file)", ["enc", "sub/.env.prod"], {
  files: { "sub/.env.prod": "A=1\n" },
  setup: ["mkdir -p .git/dotenvdotenc sub/.git", "echo '[]' > .git/dotenvdotenc/state.json"],
  after: ["(cd sub && " + LS + ")", "cat .git/dotenvdotenc/state.json"],
  back: "a sync record that is not an object, in the repository git finds past an empty .git",
});
add("enc: the same record without the stray directory goes back", ["enc", "sub/.env.prod"], {
  files: { "sub/.env.prod": "A=1\n" },
  setup: ["mkdir -p .git/dotenvdotenc", "echo '[]' > .git/dotenvdotenc/state.json"],
  after: ["(cd sub && " + LS + ")", "cat .git/dotenvdotenc/state.json"],
  back: "a sync record that is not an object",
});

// ═══════════════════════════ keys files in odd states ═══════════════════════════

const DANGLING = "ln -s nowhere/.env.keys .env.keys";
add("status: .env.keys is a link to nowhere", ["status"], { files: { ".env.prod": LOCAL, ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") }, setup: [DANGLING] });
add("diff: .env.keys is a link to nowhere", ["diff"], { files: { ".env.prod": LOCAL, ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") }, setup: [DANGLING] });
add("dec: .env.keys is a link to nowhere", ["dec"], { files: { ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") }, setup: [DANGLING] });
add("enc: .env.keys is a link to nowhere", ["enc"], { files: { ".env.prod": LOCAL }, setup: [DANGLING] });
add("enc: .env.keys is a link to itself", ["enc"], { files: { ".env.prod": LOCAL }, setup: ["ln -s .env.keys .env.keys"] });
add("status: .env.keys is a directory", ["status"], { files: { ".env.prod": LOCAL, ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p"), ".env.keys/keep": "" } });
add("enc: .env.keys is a directory", ["enc"], { files: { ".env.prod": LOCAL, ".env.keys/keep": "" } });
add("get: .env.keys is a directory", ["get", "API_KEY"], { files: { ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p"), ".env.keys/keep": "" } });
add("enc: .env.keys is empty", ["enc"], { files: { ".env.prod": LOCAL, ".env.keys": "" }, after: [LS, `${PROBE} keys .env.keys .env.prod.enc`] });
add("enc: --env-keys-file= with nothing after it: the new key has nowhere to go", ["enc", "--env-keys-file="], { files: { ".env.prod": LOCAL }, after: ["ls -A | grep -v '^\\.git$' | sed 's/dede-tmp-.*/dede-tmp-<pid>-<random>/' | while read -r f; do echo \"$f\"; done", "stat -c '%a %F' .env.dede-tmp-* 2>&1 | sed 's/.env.dede-tmp-[0-9a-f-]*/<temp file>/'"] });
add("enc: -fk to a file in a directory that is not there", ["enc", "-fk", "nowhere/keys"], { files: { ".env.prod": LOCAL }, after: [LS] });
add("enc: -fk to a directory", ["enc", "-fk", "."], { files: { ".env.prod": LOCAL }, after: [LS] });
add("dec: a key file given by -fk that is the .enc itself", ["dec", "-fk", ".env.prod.enc"], { files: { ".env.prod.enc": encFile(".env.prod", 1, LOCAL, "p") } });

// ═══════════════════════════ arguments once more ═══════════════════════════

add("status: .enc alone as the file argument", ["status", ".enc"], { files: { ".env.prod": LOCAL } });
add("status: a/.enc and x.enc as file arguments", ["status", "a/.enc"], { files: { ".env.prod": LOCAL, "a/keep": "" } });
add("diff: x.enc as the file argument", ["diff", "x.enc"], { files: { ".env.prod": LOCAL } });
add("dec: a path above the root", ["dec", "/../../.env.nowhere"], { files: { ".env.prod": LOCAL } });
add("health: a named file in a subdirectory", ["health", "--all", "sub/.env.local", "sub/../sub/.env.local.enc"], {
  files: { "sub/.env.local.enc": H_ENC, ".dede.yaml": 'rotate:\n  - keys: "*"\n    files: ".env.local"\n    every: 1d\n' },
  setup: [IDENT, "git add -A && " + AGED("2001-02-03")],
});
add("health: run in a subdirectory with a named file one level up", ["health", "../.env.local"], {
  files: { ".env.local.enc": H_ENC, ".dede.yaml": 'rotate:\n  - keys: "*"\n    expires: 2001-01-01\n', "sub/keep": "" },
  setup: [IDENT, "git add -A && " + AGED("2001-02-03")],
  env: { X_CD: "sub" },
});

// ═══════════════════════════ a directory that is not there ═══════════════════════════

for (const command of ["enc", "dec", "status", "diff", "keys", "health"])
  add(`${command}: a named file in a directory that is not there (nowhere)`, [command, "nowhere/.env.prod"], { files: { ".env.prod": LOCAL, ".dede.yaml": 'rotate:\n  - keys: "*"\n    every: 1d\n' } });
add("enc: two named files, the first in a directory that is not there (nowhere)", ["enc", "nowhere/.env.prod", ".env.prod"], { files: { ".env.prod": LOCAL }, after: [LS, `${PROBE} keys .env.keys .env.prod.enc`] });
add("status: the directory it runs in has been removed (nowhere)", ["status"], { files: { "gone/keep": "" }, setup: ["rm gone/keep"], env: { X_CD: "gone", X_GONE: "1" }, back: "no current directory: bun's own error" });

// ═══════════════════════════ red errors without a terminal (FORCE_COLOR) ═══════════════════════════

const RED = { FORCE_COLOR: "1" };
add("colour: FORCE_COLOR=1, the lefthook snippet, which ends in a newline", ["setup"], { files: { "lefthook.yml": "pre-push:\n  commands: {}\n" }, env: RED, after: [LS] });
add("colour: FORCE_COLOR=1, keys link warns and links", ["keys", "link", "../keys"], { setup: [keysFile({ _LOCAL: 1 }, "../keys"), "chmod 644 ../keys"], env: RED, after: [LS] });
add("colour: FORCE_COLOR=1, health: the summary is red, the lines are not", ["health", "--all"], { files: { ".env.local.enc": H_ENC, ".dede.yaml": 'rotate:\n  - keys: "*"\n    every: 1d\n    note: "a → b"\n' }, setup: [IDENT, "git add -A && " + AGED("2001-02-03")], env: RED });
add("colour: FORCE_COLOR=1, enc: every line dede prints", ["enc"], { files: { ".env.prod": LOCAL, ".env.stage": "DOTENV_PUBLIC_KEY=1\n", "elsewhere": "x\n" }, setup: ["chmod 644 .env.prod", "ln -s elsewhere .env.b"], env: RED, after: [LS] });
add("colour: FORCE_COLOR=1 and NO_COLOR=1, status with a file that fails", ["status"], { files: { ".env.prod": LOCAL, ".env.stage": "DOTENV_PUBLIC_KEY=1\n" }, env: { FORCE_COLOR: "1", NO_COLOR: "1" } });
add("colour: FORCE_COLOR=true and TERM=dumb", ["get"], { repo: false, env: { FORCE_COLOR: "true", TERM: "dumb" } });
add("colour: TERM=dumb, CI=true and COLORTERM=truecolor change nothing without a terminal", ["get"], { repo: false, env: { TERM: "dumb", CI: "true", COLORTERM: "truecolor", GITHUB_ACTIONS: "true" } });

if (sealedNew) fs.writeFileSync(FIXTURES_PATH, JSON.stringify(fixtures, null, 1) + "\n");
