#!/usr/bin/env -S bun --no-env-file
// dede — dotenv ⇄ dotenc. Keeps each gitignored plaintext `.env*` file in sync with a committed
// `<file>.enc` twin in dotenvx format. Parsing, rewriting and crypto are @dotenvx/primitives;
// dede only adds the two-file sync, a drift check, a pre-commit guard and `setup`.
import { decrypt, encrypt, keypair, keyringSync, scan, upsert } from "@dotenvx/primitives";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, statSync, symlinkSync, writeSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

const USAGE = `dede — sync gitignored .env* files with committed dotenvx-encrypted .env*.enc files

  dede enc [--force] [file|glob…]   plaintext → .enc   (default: every .env* here)
  dede dec [--force] [file|glob…]   .enc → plaintext   (default: every .env*.enc here)
  dede status [file|glob…]          report sync state, exit 1 unless all in sync
  dede guard [--all]                pre-commit: block staged plaintext env files, keys, unencrypted values
  dede setup                        add .gitignore rules and the pre-commit hook
  dede keys                         which key each .enc here needs, and whether it is held
  dede keys link <path>             make ./.env.keys a symlink to another checkout's .env.keys

  -fk, --env-keys-file <path>       use this keys file instead of ./.env.keys (also DOTENV_KEYS_FILE)
  --key <NAME>                      encrypt a new .enc with the existing DOTENV_PRIVATE_KEY_<NAME>
                                    (e.g. back up a keys file: dede enc .env.keys.myproj --key ME)

Private keys: DOTENV_PRIVATE_KEY_<SUFFIX> in the environment, else ./.env.keys (dotenvx convention).`;

const PREFIX = "encrypted:";
const TMP = ".env.dede-tmp-";
const NAME_RE = /^\.env(\.[A-Za-z0-9_-]+)*$/;
const SKIP = new Set([".env.keys", ".env.vault", ".env.me", ".env.example", ".env.sample", ".env.template"]);
const HEADER_RE = /^DOTENV_PUBLIC_KEY[A-Z0-9_]*="?(0[23][0-9a-f]{64})"?\r?$/;
// An assignment in a committed file: the value is ciphertext (bare or quoted) or empty, then at most a spaced comment.
const SEALED_LINE_RE = /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=\s*(?:"(?:encrypted:[A-Za-z0-9+/=]+)?"|'(?:encrypted:[A-Za-z0-9+/=]+)?'|`(?:encrypted:[A-Za-z0-9+/=]+)?`|(?:encrypted:[A-Za-z0-9+/=]+)?)(?:\s+#.*|\s*)\r?$/;
// A commented-out assignment with a real-looking value, or a URL carrying userinfo, in a comment.
const LEAKY_COMMENT_RE = /^\s*#\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*["'`]?\S{16,}|:\/\/[^/\s:@]+(?::[^@\s]*)?@/;
const PRIVATE_KEY_RE = /DOTENV_PRIVATE_KEY[A-Z0-9_]*["']?\s*[=:]\s*["']?[0-9a-fA-F]{64}/;
const BANNER = [
  "#/-------------------[DOTENV_PUBLIC_KEY]--------------------/",
  "#/            public-key encryption for .env files          /",
  "#/       [how it works](https://dotenvx.com/encryption)     /",
  "#/----------------------------------------------------------/",
];
const KEYS_BANNER = [
  "#/------------------!DOTENV_PRIVATE_KEYS!-------------------/",
  "#/ private decryption keys. DO NOT commit to source control /",
  "#/     [how it works](https://dotenvx.com/encryption)       /",
  "#/----------------------------------------------------------/",
];
const IGNORE_BLOCK = "# dede: plaintext env files and private keys stay local; only .enc is committed\n.env*\n!.env*.enc\n";
const HOOK_MARK = "dede guard";
const HOOK_CMD = '{ if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede guard; else dede guard; fi; } || exit 1';

class DedeError extends Error {
  constructor(message: string, readonly code = 1) {
    super(message);
  }
}
const die = (message: string, code = 1): never => {
  throw new DedeError(message, code);
};

type Values = Record<string, string[]>;
interface Pair {
  plain: string; // absolute
  enc: string; // absolute
  name: string; // plaintext basename, e.g. .env.local
  explicit: boolean;
}

// ---------- names and keys ----------

// dotenvx naming: .env → "", .env.local → "_LOCAL", .env.development.local → "_DEVELOPMENT_LOCAL"
export const suffixOf = (name: string) => (name === ".env" ? "" : "_" + name.slice(5).toUpperCase().replace(/[^A-Z0-9]/g, "_"));

const isEnvName = (name: string) => NAME_RE.test(name) && !name.endsWith(".enc") && !SKIP.has(name) && !name.startsWith(TMP);

// Keys come from the environment, then one keys file: ./.env.keys next to the env file, or an
// explicit -fk / DOTENV_KEYS_FILE. No other place is searched.
let keysOverride: string | undefined;
const keysFileFor = (dir: string) => keysOverride ?? join(dir, ".env.keys");

function ringFor(dir: string): Record<string, string> {
  return keyringSync({ fk: [keysFileFor(dir)], processEnv: process.env });
}

function privateKeyFor(pub: string, pair: Pair): string {
  const priv = ringFor(dirname(pair.plain))[pub];
  if (!priv) die(`${rel(pair.enc)}: no private key (set DOTENV_PRIVATE_KEY${suffixOf(pair.name)}, add it to ${rel(keysFileFor(dirname(pair.plain)))}, or use -fk / \`dede keys link\`)`, 3);
  return priv!;
}

// A keys file inside a git work tree must be gitignored; one outside any repo is the user's business.
function assertKeysFileSafe(path: string): void {
  const inRepo = git(["rev-parse", "--is-inside-work-tree"], dirname(resolve(path))).out.trim() === "true";
  if (inRepo && !isIgnored(path)) die(`${rel(path)} is not gitignored; run \`dede setup\` first`);
}

// `--key NAME`: the key a new .enc is encrypted with, instead of the one named after the file.
let keyChoice: string | undefined;

function keyByName(keyName: string, keysPath: string): string {
  const fromFile = existsSync(keysPath) ? scan(readFileSync(keysPath, "utf8")).parsed[keyName]?.at(-1) : undefined;
  return (process.env[keyName] || fromFile || "").split(",")[0].trim();
}

// Existing key for a new .enc (env or the keys file, by dotenvx name), else a fresh one saved to the keys file.
function obtainKey(pair: Pair): { publicKey: string; privateKey: string } {
  const keysPath = keysFileFor(dirname(pair.plain));
  if (keyChoice) {
    const chosen = keyByName(`DOTENV_PRIVATE_KEY_${keyChoice}`, keysPath);
    if (!chosen) die(`--key ${keyChoice}: DOTENV_PRIVATE_KEY_${keyChoice} not found in the environment or ${rel(keysPath)}`, 3);
    return keypair(chosen);
  }
  const keyName = `DOTENV_PRIVATE_KEY${suffixOf(pair.name)}`;
  const existing = keyByName(keyName, keysPath);
  if (existing) return keypair(existing);
  assertKeysFileSafe(keysPath);
  const kp = keypair();
  const prev = existsSync(keysPath) ? readFileSync(keysPath, "utf8") : `${KEYS_BANNER.join("\n")}\n`;
  // A linked .env.keys (dede keys link) is updated at its target, keeping the link.
  const target = isSymlink(keysPath) ? realpathSync(keysPath) : keysPath;
  writeAtomic(target, `${prev}${prev.endsWith("\n") ? "" : "\n"}\n# ${pair.name}\n${keyName}=${kp.privateKey}\n`, 0o600);
  log(`new key ${keyName} saved to ${rel(keysPath)} — back it up (password manager); teammates need it to decrypt`);
  return kp;
}

// ---------- file format ----------

function splitEnc(text: string, file: string): { publicKey: string; body: string; offset: number } {
  const lines = text.split("\n");
  let i = 0;
  while (i < lines.length && lines[i].startsWith("#/")) i++;
  const m = HEADER_RE.exec(lines[i] ?? "");
  if (!m) die(`${rel(file)}: missing DOTENV_PUBLIC_KEY header`, 4);
  i++;
  if (lines[i] === "" || lines[i] === "\r") i++;
  return { publicKey: m![1], body: lines.slice(i).join("\n"), offset: i };
}

const header = (name: string, publicKey: string) => `${BANNER.join("\n")}\nDOTENV_PUBLIC_KEY${suffixOf(name)}="${publicKey}"\n\n`;

// Keys files (.env.keys, .env.keys.<name>) may hold private keys, e.g. to back one up as .env.keys.<name>.enc.
const isKeysName = (name: string) => name === ".env.keys" || name.startsWith(".env.keys.");

function values(text: string, file: string): Values {
  const { parsed } = scan(text);
  const keysFile = isKeysName(basename(file).replace(/\.enc$/, ""));
  for (const k of Object.keys(parsed))
    if (k.startsWith("DOTENV_PUBLIC_KEY") || (!keysFile && k.startsWith("DOTENV_PRIVATE_KEY"))) die(`${rel(file)}: ${k} does not belong in an env file`, 4);
  return parsed;
}

function rewrite(text: string, vals: Values): string {
  let out = text;
  for (const [k, v] of Object.entries(vals)) out = upsert(out, k, v);
  // upsert drops the final newline after an empty last value (`A=\n` → `A=`); keep the file's ending.
  return text.endsWith("\n") && !out.endsWith("\n") ? `${out}\n` : out;
}

function decryptAll(body: string, priv: string, file: string): { plain: Values; cipher: Values } {
  const cipher = values(body, file);
  const plain: Values = {};
  for (const [k, vs] of Object.entries(cipher))
    plain[k] = vs.map((v) => {
      if (v === "") return "";
      if (!v.startsWith(PREFIX)) die(`${rel(file)}: ${k} is not encrypted`, 4);
      try {
        return decrypt(priv, v);
      } catch {
        return die(`${rel(file)}: cannot decrypt ${k} (wrong key or corrupt value)`, 3);
      }
    });
  return { plain, cipher };
}

// Every committed line must be blank, a comment, or an assignment whose whole value is ciphertext.
// Text glued to a value (`PASSWORD=abc#def`) parses as a comment and would stay plaintext.
// `offset`: lines before `body` in the file (the .enc header), so reported line numbers match the file.
function assertSealed(body: string, file: string, offset = 0): void {
  const hint = 'quote the whole value ("…"), or put a space before a real comment';
  const keyOf = (line: string) => /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=/.exec(line)?.[1];
  const lines = body.split("\n");
  const isComment = (line: string) => line.trim() === "" || line.trimStart().startsWith("#");
  lines.forEach((line, i) => {
    if (isComment(line) && !line.startsWith("#/") && LEAKY_COMMENT_RE.test(line))
      die(`${rel(file)}: line ${i + 1 + offset} is a comment holding a credential-like value (commented-out assignment or URL with userinfo); comments are committed in plaintext, so delete it`, 4);
    if (!isComment(line) && !keyOf(line)) die(`${rel(file)}: line ${i + 1 + offset} is not an assignment or comment and would be committed as plaintext`, 4);
  });
  for (const [k, vs] of Object.entries(values(body, file))) if (vs.some((v) => v !== "" && !v.startsWith(PREFIX))) die(`${rel(file)}: ${k} is not encrypted; ${hint}`, 4);
  lines.forEach((line, i) => {
    if (!isComment(line) && !SEALED_LINE_RE.test(line)) die(`${rel(file)}: line ${i + 1 + offset} (${keyOf(line)}) would commit part of its value as plaintext; ${hint}`, 4);
  });
}

// ---------- git, state, io ----------

function git(args: string[], cwd: string, input?: string) {
  const r = spawnSync("git", args, { cwd, input, encoding: "utf8" });
  return { ok: r.status === 0, out: r.stdout ?? "" };
}
const gitDir = (cwd: string) => git(["rev-parse", "--show-toplevel"], cwd).out.trim() || die("not inside a git repository");
const isIgnored = (path: string) => git(["check-ignore", "-q", "--", basename(path)], dirname(path)).ok;
const isTracked = (path: string) => git(["ls-files", "--error-unmatch", "--", basename(path)], dirname(path)).ok;
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const rel = (path: string) => relative(process.cwd(), path) || ".";
const log = (msg: string) => console.error(msg);

// Last-synced hashes per pair, private to this worktree (never committed, never contains values).
function stateFile(pair: Pair): string {
  const p = git(["rev-parse", "--path-format=absolute", "--git-path", "dotenvdotenc/state.json"], dirname(pair.plain)).out.trim();
  return p || die("not inside a git repository");
}
function loadState(pair: Pair): Record<string, { plain: string; enc: string }> {
  const f = stateFile(pair);
  try {
    return JSON.parse(readFileSync(f, "utf8"));
  } catch {
    return {};
  }
}
function saveState(pair: Pair, plainText: string, encText: string): void {
  const f = stateFile(pair);
  const all = loadState(pair);
  const key = relative(gitDir(dirname(pair.plain)), pair.plain);
  if (all[key]?.plain === sha(plainText) && all[key]?.enc === sha(encText)) return;
  all[key] = { plain: sha(plainText), enc: sha(encText) };
  mkdirSync(dirname(f), { recursive: true });
  writeAtomic(f, JSON.stringify(all, null, 2) + "\n", 0o600);
}
function lastSync(pair: Pair) {
  return loadState(pair)[relative(gitDir(dirname(pair.plain)), pair.plain)];
}

function isSymlink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function read(path: string): string | undefined {
  try {
    if (lstatSync(path).isSymbolicLink()) die(`${rel(path)} is a symlink; refusing`, 4);
  } catch (e) {
    if (e instanceof DedeError) throw e;
    return undefined;
  }
  return readFileSync(path, "utf8");
}

function writeAtomic(path: string, text: string, mode: number): void {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) die(`${rel(path)} is a symlink; refusing`, 4);
  const tmp = join(dirname(path), `${TMP}${process.pid}-${randomBytes(4).toString("hex")}`);
  const fd = openSync(tmp, "wx", mode);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, mode);
  renameSync(tmp, path);
}

// Plaintext secrets are owner-only; fix a group/world-readable file instead of just warning.
function tighten(path: string): void {
  try {
    const st = lstatSync(path);
    if (st.isFile() && (st.mode & 0o077) !== 0) {
      chmodSync(path, 0o600);
      log(`tightened ${rel(path)} to 0600`);
    }
  } catch {}
}

function preflight(pair: Pair): void {
  if (!isIgnored(pair.plain)) die(`${rel(pair.plain)} is not gitignored; run \`dede setup\` (or add \`.env*\` and \`!.env*.enc\` to .gitignore)`);
  if (isTracked(pair.plain)) die(`${rel(pair.plain)} is tracked by git; run \`git rm --cached ${rel(pair.plain)}\` and rotate what it exposed`);
  if (isIgnored(pair.enc)) log(`warning: ${rel(pair.enc)} is gitignored and won't be committed; add \`!.env*.enc\` after your .env ignore rules (or run \`dede setup\`)`);
}

// ---------- sync ----------

interface View {
  P?: string; // plaintext file bytes
  E?: string; // .enc file bytes
  C?: string; // plaintext normalized through the dotenvx writer
  D?: string; // .enc decrypted into the same normalized form
  pub?: string;
  priv?: string;
  old?: { plain: Values; cipher: Values };
}

function view(pair: Pair, needKey: boolean): View {
  const v: View = { P: read(pair.plain), E: read(pair.enc) };
  if (v.P !== undefined) v.C = rewrite(v.P, values(v.P, pair.plain));
  if (v.E !== undefined) {
    const { publicKey, body } = splitEnc(v.E, pair.enc);
    v.pub = publicKey;
    if (!needKey && !ringFor(dirname(pair.plain))[publicKey]) return v;
    v.priv = privateKeyFor(publicKey, pair);
    v.old = decryptAll(body, v.priv, pair.enc);
    v.D = rewrite(body, v.old.plain);
  }
  return v;
}

function buildEnc(pair: Pair, pub: string, priv: string, P: string, C: string, old?: View["old"]): string {
  const vals = values(P, pair.plain);
  const cts: Values = {};
  for (const [k, vs] of Object.entries(vals))
    cts[k] = vs.map((v, i) => (old?.plain[k]?.[i] === v && old.cipher[k][i] !== "" ? old.cipher[k][i] : encrypt(pub, v)));
  const body = rewrite(P, cts);
  assertSealed(body, pair.enc);
  if (rewrite(body, decryptAll(body, priv, pair.enc).plain) !== C) die(`${rel(pair.plain)}: formatting does not survive encryption; quote the value with "…"`, 4);
  return header(pair.name, pub) + body;
}

type Drift = "enc-changed" | "plain-changed" | "both" | "unknown" | "neither";
function drift(pair: Pair, P: string, E: string): Drift {
  const s = lastSync(pair);
  if (!s) return "unknown";
  const pc = sha(P) !== s.plain;
  const ec = sha(E) !== s.enc;
  return pc && ec ? "both" : pc ? "plain-changed" : ec ? "enc-changed" : "neither";
}

function enc(pair: Pair, force: boolean): void {
  preflight(pair);
  tighten(pair.plain);
  const v = view(pair, true);
  if (v.P === undefined) die(`${rel(pair.plain)} not found${v.E !== undefined ? "; run `dede dec`" : ""}`);
  if (v.E === undefined) {
    const kp = obtainKey(pair);
    const text = buildEnc(pair, kp.publicKey, kp.privateKey, v.P!, v.C!);
    writeAtomic(pair.enc, text, 0o644);
    saveState(pair, v.P!, text);
    return log(`created ${rel(pair.enc)}`);
  }
  if (keyChoice) {
    const chosen = keyByName(`DOTENV_PRIVATE_KEY_${keyChoice}`, keysFileFor(dirname(pair.plain)));
    if (chosen && keypair(chosen).publicKey !== v.pub) die(`${rel(pair.enc)} is encrypted with another key; --key only chooses the key for a new .enc`, 4);
  }
  if (v.C === v.D) {
    saveState(pair, v.P!, v.E);
    return log(`${rel(pair.enc)}: in sync`);
  }
  const d = drift(pair, v.P!, v.E);
  if (!force) {
    if (d === "unknown") die(`${rel(pair.enc)}: differs from ${rel(pair.plain)} with no sync record; \`dede dec --force\` takes .enc, \`dede enc --force\` takes plaintext`, 2);
    if (d === "both") die(`${rel(pair.enc)}: both files changed since last sync; resolve by hand, then use --force`, 2);
    if (d === "enc-changed") die(`${rel(pair.enc)}: changed since last sync (pulled?); run \`dede dec\` first`, 1);
  }
  const text = buildEnc(pair, v.pub!, v.priv!, v.P!, v.C!, v.old);
  writeAtomic(pair.enc, text, 0o644);
  saveState(pair, v.P!, text);
  log(`encrypted ${rel(pair.plain)} → ${rel(pair.enc)}`);
}

function dec(pair: Pair, force: boolean): void {
  preflight(pair);
  const v = view(pair, true);
  if (v.E === undefined) die(`${rel(pair.enc)} not found${v.P !== undefined ? "; run `dede enc`" : ""}`);
  if (v.P !== undefined && v.C === v.D) {
    saveState(pair, v.P, v.E!);
    return log(`${rel(pair.plain)}: in sync`);
  }
  if (v.P !== undefined && !force) {
    const d = drift(pair, v.P, v.E!);
    if (d === "unknown") die(`${rel(pair.plain)}: differs from ${rel(pair.enc)} with no sync record; \`dede dec --force\` takes .enc, \`dede enc --force\` takes plaintext`, 2);
    if (d === "both") die(`${rel(pair.plain)}: both files changed since last sync; resolve by hand, then use --force`, 2);
    if (d === "plain-changed") die(`${rel(pair.plain)}: has edits not yet encrypted; run \`dede enc\` first (or \`dede dec --force\` to discard them)`, 1);
  }
  writeAtomic(pair.plain, v.D!, 0o600);
  saveState(pair, v.D!, v.E!);
  log(`decrypted ${rel(pair.enc)} → ${rel(pair.plain)}`);
}

function status(pair: Pair): boolean {
  const v = view(pair, false);
  const say = (s: string, ok = false) => (console.log(`${ok ? "✓" : "✗"} ${rel(pair.plain)}: ${s}`), ok);
  if (v.E === undefined) return say(v.P === undefined ? "missing" : "no .enc yet (run `dede enc`)");
  if (v.P === undefined) return say("no plaintext (run `dede dec`)");
  if (v.D === undefined) return say("no private key; cannot compare");
  if (v.C === v.D) return say("in sync", true);
  const d = drift(pair, v.P, v.E);
  return say(d === "plain-changed" ? "edited (run `dede enc`)" : d === "enc-changed" ? ".enc changed (run `dede dec`)" : d === "both" ? "conflict: both changed" : "differs, no sync record");
}

// ---------- guard ----------

function guard(all: boolean): void {
  const top = gitDir(process.cwd());
  const list = git(all ? ["ls-files", "-z"] : ["diff", "--cached", "--name-only", "-z", "--diff-filter=d"], top).out.split("\0").filter(Boolean);
  const bad: string[] = [];
  for (const f of list) {
    const name = basename(f);
    const blob = git(["cat-file", "blob", `:${f}`], top);
    if (name === ".env.keys" || name.startsWith(TMP)) bad.push(`${f}: private keys / temp file must never be committed`);
    else if (name.endsWith(".enc") && isEnvName(name.slice(0, -4))) {
      try {
        const { body, offset } = splitEnc(blob.out, join(top, f));
        assertSealed(body, join(top, f), offset);
      } catch (e) {
        bad.push(e instanceof DedeError ? e.message : `${f}: unreadable`);
      }
    } else if (NAME_RE.test(name) && !SKIP.has(name)) bad.push(`${f}: plaintext env file; commit ${name}.enc instead (dede enc)`);
    if (blob.ok && PRIVATE_KEY_RE.test(blob.out)) bad.push(`${f}: contains a DOTENV_PRIVATE_KEY`);
  }
  if (bad.length) die(`dede guard: blocked\n  ${bad.join("\n  ")}\n  (unstage with \`git restore --staged <file>\`)`, 1);
}

// ---------- keys ----------

// Prints public-key prefixes and file names only, never a private key.
function keysStatus(ps: Pair[]): boolean {
  let ok = true;
  const envRing = keyringSync({ fk: [], processEnv: process.env });
  for (const p of ps) {
    const E = read(p.enc);
    if (E === undefined) continue;
    const { publicKey } = splitEnc(E, p.enc);
    const file = keysFileFor(dirname(p.plain));
    const fileRing = existsSync(file) ? keyringSync({ fk: [file], processEnv: {} }) : {};
    const link = isSymlink(file) ? ` → ${rel(realpathSync(file))}` : "";
    const from = envRing[publicKey] ? "environment" : fileRing[publicKey] ? `${rel(file)}${link}` : undefined;
    if (!from) ok = false;
    console.log(`${from ? "✓" : "✗"} ${rel(p.enc)}  ${publicKey.slice(0, 10)}…  ${from ?? `missing (DOTENV_PRIVATE_KEY${suffixOf(p.name)})`}`);
  }
  return ok;
}

function keysLink(target: string | undefined): void {
  if (!target) die("usage: dede keys link <path/to/.env.keys>", 4);
  const link = join(process.cwd(), ".env.keys");
  const abs = resolve(process.cwd(), target!);
  if (!existsSync(abs) || !statSync(abs).isFile()) die(`${target}: no such keys file`, 4);
  if (realpathSync(abs) === (existsSync(link) ? realpathSync(link) : "")) return log(`.env.keys already points to ${target}`);
  if (existsSync(link) || isSymlink(link)) die(`.env.keys already exists here; move it away first`, 1);
  assertKeysFileSafe(link);
  if ((statSync(abs).mode & 0o077) !== 0) log(`warning: ${target} is readable by other users; chmod 600 it`);
  symlinkSync(target!, link);
  log(`linked .env.keys → ${target}`);
}

// ---------- setup ----------

function setup(): void {
  const top = gitDir(process.cwd());
  const gi = join(top, ".gitignore");
  const probe = (name: string) => git(["check-ignore", "-q", "--no-index", "--", name], top).ok;
  const ok = () => probe(".env.local") && probe(".env.keys") && probe(".env") && !probe(".env.local.enc") && !probe(".env.enc");
  if (!ok()) {
    const prev = read(gi) ?? "";
    writeAtomic(gi, `${prev}${prev === "" || prev.endsWith("\n") ? "" : "\n"}${prev === "" ? "" : "\n"}${IGNORE_BLOCK}`, 0o644);
    if (!ok()) die(".gitignore still does not ignore .env* while keeping .env*.enc; check for conflicting rules (`git check-ignore -v .env.local.enc`)");
    log("updated .gitignore: .env* ignored, .env*.enc committed");
  } else log(".gitignore: ok");

  const lefthook = ["lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml"].find((f) => existsSync(join(top, f)));
  if (lefthook) {
    const text = readFileSync(join(top, lefthook), "utf8");
    if (text.includes(HOOK_MARK)) return log(`${lefthook}: dede guard already configured`);
    log(`${lefthook} found; add this under pre-commit, then run \`lefthook install\`:\n\npre-commit:\n  commands:\n    dede-guard:\n      run: ${HOOK_CMD}\n`);
    return;
  }
  // --git-path honours core.hooksPath (incl. `~`); husky v9 points it at .husky/_ and runs .husky/<hook>.
  const dir = git(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], top).out.trim().replace(/\/\.husky\/_\/?$/, "/.husky");
  if (!dir) die("cannot locate the git hooks directory");
  const hook = join(dir, "pre-commit");
  const prev = read(hook);
  if (prev?.includes(HOOK_MARK)) return log(`${rel(hook)}: dede guard already installed`);
  if (prev?.startsWith("#!") && !/^#!.*\b(sh|bash|zsh|dash)\b/.test(prev)) die(`${rel(hook)} is not a shell script; add \`${HOOK_CMD}\` to it yourself`);
  mkdirSync(dir, { recursive: true });
  // First thing after the shebang, so a later `exec`/`exit` in an existing hook cannot skip it.
  const nl = prev?.startsWith("#!") ? prev.indexOf("\n") : -1;
  const body =
    prev === undefined ? `#!/bin/sh\n${HOOK_CMD}\n`
    : prev.startsWith("#!") ? (nl === -1 ? `${prev}\n${HOOK_CMD}\n` : `${prev.slice(0, nl + 1)}${HOOK_CMD}\n${prev.slice(nl + 1)}`)
    : `${HOOK_CMD}\n${prev}`;
  writeAtomic(hook, body, prev === undefined ? 0o755 : lstatSync(hook).mode & 0o777);
  log(`${prev === undefined ? "created" : "updated"} ${rel(hook)}: runs dede guard before each commit`);
}

// ---------- args ----------

function pairs(args: string[], mode: "enc" | "dec" | "any"): Pair[] {
  const cwd = process.cwd();
  const found: { path: string; explicit: boolean }[] = [];
  if (args.length === 0) for (const n of readdirSync(cwd)) found.push({ path: join(cwd, n), explicit: false });
  for (const a of args) {
    if (/[*?[{]/.test(a)) {
      for (const f of new Bun.Glob(a).scanSync({ cwd, dot: true, onlyFiles: true }))
        if (!/(^|\/)(node_modules|\.git)\//.test(f)) found.push({ path: join(cwd, f), explicit: false });
    } else found.push({ path: resolve(cwd, a), explicit: true });
  }
  const out = new Map<string, Pair>();
  for (const { path, explicit } of found) {
    const plain = path.endsWith(".enc") ? path.slice(0, -4) : path;
    const name = basename(plain);
    if (!isEnvName(name)) {
      if (explicit && !name.startsWith(".env")) die(`${rel(path)}: not a .env file`, 4);
      continue;
    }
    if (!explicit && isSymlink(plain)) {
      log(`skipping ${rel(plain)}: symlink (dede only syncs regular files)`);
      continue;
    }
    const pair = { plain, enc: `${plain}.enc`, name, explicit };
    const wanted = mode === "enc" ? existsSync(pair.plain) : mode === "dec" ? existsSync(pair.enc) : existsSync(pair.plain) || existsSync(pair.enc);
    if (!wanted && !explicit) continue;
    const prev = out.get(plain);
    if (!prev || explicit) out.set(plain, pair);
  }
  if (out.size === 0 && (args.length > 0 || mode !== "any")) log(`dede ${mode}: no matching env files`);
  return [...out.values()];
}

export function main(argv: string[]): number {
  const [cmd, ...raw] = argv;
  const rest: string[] = [];
  keysOverride = process.env.DOTENV_KEYS_FILE || undefined;
  keyChoice = undefined;
  for (let i = 0; i < raw.length; i++) {
    const a = raw[i];
    if (a === "-fk" || a === "--env-keys-file") {
      if (raw[i + 1] === undefined) return log(`dede: ${a} needs a path`), 4;
      keysOverride = raw[++i];
    } else if (a === "--key") {
      if (!/^[A-Z0-9_]+$/.test(raw[i + 1] ?? "")) return log("dede: --key needs a NAME like TAKU (for DOTENV_PRIVATE_KEY_TAKU)"), 4;
      keyChoice = raw[++i];
    } else if (a.startsWith("--env-keys-file=")) keysOverride = a.slice("--env-keys-file=".length);
    else rest.push(a);
  }
  if (keysOverride) keysOverride = resolve(process.cwd(), keysOverride);
  const force = rest.includes("--force");
  const args = rest.filter((a) => a !== "--force" && a !== "--all");
  let code = 0;
  const each = (ps: Pair[], fn: (p: Pair) => void) => {
    for (const p of ps)
      try {
        fn(p);
      } catch (e) {
        // Library errors (e.g. an invalid private key) fail this file only; their text is not echoed.
        const err = e instanceof DedeError ? e : new DedeError(`${rel(p.enc)}: ${(e as Error).name ?? "error"} (invalid key or file?)`, 3);
        log(`dede: ${err.message}`);
        code = Math.max(code, err.code);
      }
  };
  try {
    switch (cmd) {
      case "enc":
        each(pairs(args, "enc"), (p) => enc(p, force));
        break;
      case "dec":
        each(pairs(args, "dec"), (p) => dec(p, force));
        break;
      case "status":
        each(pairs(args, "any"), (p) => {
          if (!status(p)) code = Math.max(code, 1);
        });
        break;
      case "guard":
        guard(rest.includes("--all"));
        break;
      case "setup":
        setup();
        break;
      case "keys":
        if (args[0] === "link") keysLink(args[1]);
        else if (!keysStatus(pairs(args, "dec"))) code = 1;
        break;
      case undefined:
      case "help":
      case "--help":
      case "-h":
        console.log(USAGE);
        break;
      default:
        log(USAGE);
        return 4;
    }
  } catch (e) {
    if (!(e instanceof DedeError)) throw e;
    log(e.message.startsWith("dede") ? e.message : `dede: ${e.message}`);
    return e.code;
  }
  return code;
}

if (import.meta.main) process.exit(main(process.argv.slice(2)));
