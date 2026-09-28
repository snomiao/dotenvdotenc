#!/usr/bin/env bun
// Plain `env bun` (not `env -S bun --no-env-file`): bun's Windows bin shim cannot parse `-S`.
// dede — dotenv ⇄ dotenc. Keeps each gitignored plaintext `.env*` file in sync with a committed
// `<file>.enc` twin in dotenvx format. Parsing, rewriting and crypto are @dotenvx/primitives;
// dede only adds the two-file sync, a drift check, a pre-commit guard and `setup`.
import { decrypt, encrypt, keypair, keyringSync, remove, scan, upsert } from "@dotenvx/primitives";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, statSync, symlinkSync, writeSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

const USAGE = `dede — sync gitignored .env* files with committed dotenvx-encrypted .env*.enc files

  dede enc [--force] [file|glob…]   plaintext → .enc   (default: every .env* here)
  dede dec [--force] [file|glob…]   .enc → plaintext   (default: every .env*.enc here)
  dede status [--quiet] [file|glob…] report sync state, exit 1 unless all in sync
  dede diff [file|glob…]            which keys differ between plaintext and .enc (names only)
  dede get NAME [file|glob…]        print one value from the .enc files (raw, never expanded);
                                    for piping: KEY=$(dede get KEY) cmd. It prints a secret, so pipe it
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
const IGNORE_BLOCK = "# dede(dotenvdotenc): plaintext env files and private keys stay local; only .enc is committed\n.env*\n!.env*.enc\n";
const WIN = process.platform === "win32";
const HOOK_MARK = "dede guard";
const HOOK_CMD = '{ if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede guard; else dede guard; fi; } || exit 1';
// After a pull or branch switch: say which files need `dede dec` (never blocks).
const NOTICE_MARK = "dede status --quiet";
const NOTICE_CMD = '{ if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede status --quiet; else dede status --quiet; fi; } || true';

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
const sha = (text: string) => createHash("sha256").update(lf(text)).digest("hex");
// Display paths as git does, with `/`, on Windows too.
const rel = (path: string) => (WIN ? relative(process.cwd(), path).replaceAll("\\", "/") : relative(process.cwd(), path)) || ".";
const log = (msg: string) => console.error(msg);
// Contents are compared with LF endings: git's core.autocrlf (default on Windows) checks .enc out
// with CRLF, and Windows editors may save the plaintext that way.
const lf = (text: string) => text.replace(/\r\n/g, "\n");

// Last-synced state per pair, private to this worktree (never committed, never contains values):
// file hashes, plus salted per-key hashes and a comment hash so a two-sided change can be merged per key.
interface SyncState {
  plain: string;
  enc: string;
  salt?: string;
  keys?: Record<string, string>;
  notes?: string;
}
const hmac = (salt: string, text: string) => createHmac("sha256", salt).update(text).digest("hex").slice(0, 24);
const commentsOf = (text: string) => text.split("\n").filter((l) => l.trimStart().startsWith("#")).join("\n");
const stateKey = (pair: Pair) => relative(gitDir(dirname(pair.plain)), pair.plain);

function stateFile(pair: Pair): string {
  const p = git(["rev-parse", "--path-format=absolute", "--git-path", "dotenvdotenc/state.json"], dirname(pair.plain)).out.trim();
  return p || die("not inside a git repository");
}
function loadState(pair: Pair): Record<string, SyncState> {
  try {
    return JSON.parse(readFileSync(stateFile(pair), "utf8"));
  } catch {
    return {};
  }
}
// `plainText` is the plaintext that corresponds to `encText` (in sync).
function saveState(pair: Pair, plainText: string, encText: string): void {
  const f = stateFile(pair);
  const all = loadState(pair);
  const key = stateKey(pair);
  const cur = all[key];
  if (cur?.plain === sha(plainText) && cur?.enc === sha(encText) && cur.keys) return;
  const salt = randomBytes(16).toString("hex");
  const keys = Object.fromEntries(Object.entries(values(plainText, pair.plain)).map(([k, v]) => [k, hmac(salt, JSON.stringify(v))]));
  all[key] = { plain: sha(plainText), enc: sha(encText), salt, keys, notes: hmac(salt, commentsOf(lf(plainText))) };
  mkdirSync(dirname(f), { recursive: true });
  writeAtomic(f, JSON.stringify(all, null, 2) + "\n", 0o600);
}
function lastSync(pair: Pair): SyncState | undefined {
  return loadState(pair)[stateKey(pair)];
}

// ---------- key-level comparison (names only, never values) ----------

const sameVals = (a?: string[], b?: string[]) => JSON.stringify(a) === JSON.stringify(b);
const list = (xs: string[]) => (xs.length > 6 ? `${xs.slice(0, 6).join(", ")} +${xs.length - 6}` : xs.join(", "));

function describeDiff(pair: Pair, L: Values, E: Values): string {
  const keys = [...new Set([...Object.keys(L), ...Object.keys(E)])].sort();
  const differ = keys.filter((k) => k in L && k in E && !sameVals(L[k], E[k]));
  const onlyL = keys.filter((k) => !(k in E));
  const onlyE = keys.filter((k) => !(k in L));
  const parts = [
    differ.length && `different: ${list(differ)}`,
    onlyL.length && `only in ${basename(pair.plain)}: ${list(onlyL)}`,
    onlyE.length && `only in ${basename(pair.enc)}: ${list(onlyE)}`,
  ].filter(Boolean);
  return parts.length ? parts.join(" · ") : "same values, different comments/formatting";
}

// Keys whose value changed since the last sync (added, removed or edited).
function changedSince(st: SyncState | undefined, vals: Values): string[] {
  if (!st?.keys || !st.salt) return [];
  const keys = new Set([...Object.keys(st.keys), ...Object.keys(vals)]);
  return [...keys].filter((k) => (k in vals ? hmac(st.salt!, JSON.stringify(vals[k])) : undefined) !== st.keys![k]).sort();
}
const keysNote = (ks: string[]) => (ks.length ? ` (${list(ks)})` : "");

// Three-way merge per key against the last sync. Each key takes the side that changed it; the same
// key changed on both sides, or comments changed on both sides, is a conflict.
function merge3(pair: Pair, P: string, D: string, st: SyncState | undefined): { text?: string; took: { local: string[]; enc: string[] }; conflicts: string[] } {
  const took = { local: [] as string[], enc: [] as string[] };
  P = lf(P);
  if (!st?.keys || !st.salt) return { took, conflicts: ["(no per-key sync record; sync once with this dede version)"] };
  const L = values(P, pair.plain);
  const E = values(D, pair.enc);
  const h = (v?: string[]) => (v === undefined ? undefined : hmac(st.salt!, JSON.stringify(v)));
  const conflicts: string[] = [];
  for (const k of [...new Set([...Object.keys(L), ...Object.keys(E)])].sort()) {
    const lh = h(L[k]);
    const eh = h(E[k]);
    if (lh === eh) continue;
    if (lh === st.keys[k]) took.enc.push(k);
    else if (eh === st.keys[k]) took.local.push(k);
    else conflicts.push(k);
  }
  const localNotes = hmac(st.salt, commentsOf(P)) !== st.notes;
  const encNotes = hmac(st.salt, commentsOf(D)) !== st.notes;
  if (localNotes && encNotes && commentsOf(P) !== commentsOf(D)) conflicts.push("(comments)");
  if (conflicts.length) return { took, conflicts };
  // Keep the text (comments, order) of the side whose comments changed; apply the other side's keys.
  const [base, apply, from] = localNotes ? [P, took.enc, E] : [D, took.local, L];
  let text = base;
  for (const k of apply) {
    if (!(k in from)) text = remove(text, k);
    else if (k in values(text, pair.plain)) text = upsert(text, k, from[k]);
    else if (from[k].length === 1) text = upsert(text.endsWith("\n") || text === "" ? text : `${text}\n`, k, from[k][0]);
    else return { took, conflicts: [`${k} (repeated assignments)`] };
  }
  const merged = values(text, pair.plain);
  const want = { ...Object.fromEntries(Object.entries(localNotes ? L : E)) } as Values;
  for (const k of apply) (k in from ? (want[k] = from[k]) : delete want[k]);
  for (const k of new Set([...Object.keys(merged), ...Object.keys(want)])) if (!sameVals(merged[k], want[k])) return { took, conflicts: [`${k} (could not merge the text)`] };
  return { text, took, conflicts: [] };
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
// Windows has no such mode bits (access is by ACL), so there is nothing to tighten.
function tighten(path: string): void {
  if (WIN) return;
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
  if (v.P !== undefined) v.C = rewrite(lf(v.P), values(v.P, pair.plain));
  if (v.E !== undefined) {
    const { publicKey, body } = splitEnc(lf(v.E), pair.enc);
    v.pub = publicKey;
    if (!needKey && !ringFor(dirname(pair.plain))[publicKey]) return v;
    v.priv = privateKeyFor(publicKey, pair);
    v.old = decryptAll(body, v.priv, pair.enc);
    v.D = rewrite(body, v.old.plain);
  }
  return v;
}

function buildEnc(pair: Pair, pub: string, priv: string, raw: string, C: string, old?: View["old"]): string {
  const P = lf(raw);
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
function drift(st: SyncState | undefined, P: string, E: string): Drift {
  if (!st) return "unknown";
  const pc = sha(P) !== st.plain;
  const ec = sha(E) !== st.enc;
  return pc && ec ? "both" : pc ? "plain-changed" : ec ? "enc-changed" : "neither";
}

const noRecord = (pair: Pair, v: View) =>
  die(`${rel(pair.plain)} and ${rel(pair.enc)} differ, and this checkout has never synced them — ${describeDiff(pair, values(v.P!, pair.plain), values(v.D!, pair.enc))}. Keep the .enc side: \`dede dec --force\`; keep the plaintext side: \`dede enc --force\``, 2);
const mergeConflict = (pair: Pair, conflicts: string[]) =>
  die(`${rel(pair.plain)}: both sides changed ${list(conflicts)} since the last sync; edit ${rel(pair.plain)} to the value you want, then \`dede enc --force\``, 2);
const mergedNote = (m: { took: { local: string[]; enc: string[] } }) =>
  `merged: from .enc${keysNote(m.took.enc) || " (nothing)"}, kept your edits${keysNote(m.took.local) || " (none)"}`;

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
  const st = lastSync(pair);
  const d = drift(st, v.P!, v.E);
  let P = lf(v.P!);
  let note = `encrypted ${rel(pair.plain)} → ${rel(pair.enc)}`;
  if (!force) {
    if (d === "unknown") noRecord(pair, v);
    if (d === "enc-changed") die(`${rel(pair.enc)} changed since the last sync${keysNote(changedSince(st, values(v.D!, pair.enc)))} (pulled?); run \`dede dec\` first`, 1);
    if (d === "both") {
      const m = merge3(pair, v.P!, v.D!, st);
      if (m.conflicts.length) mergeConflict(pair, m.conflicts);
      P = m.text!;
      writeAtomic(pair.plain, P, 0o600);
      note = `${rel(pair.enc)}: ${mergedNote(m)}; wrote both files`;
    }
  }
  const text = buildEnc(pair, v.pub!, v.priv!, P, rewrite(P, values(P, pair.plain)), v.old);
  writeAtomic(pair.enc, text, 0o644);
  saveState(pair, P, text);
  log(note);
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
    const st = lastSync(pair);
    const d = drift(st, v.P, v.E!);
    if (d === "unknown") noRecord(pair, v);
    if (d === "plain-changed")
      die(`${rel(pair.plain)} has edits not yet encrypted${keysNote(changedSince(st, values(v.P, pair.plain)))}; run \`dede enc\` (or \`dede dec --force\` to discard them)`, 1);
    if (d === "both") {
      const m = merge3(pair, v.P, v.D!, st);
      if (m.conflicts.length) mergeConflict(pair, m.conflicts);
      writeAtomic(pair.plain, m.text!, 0o600);
      saveState(pair, v.D!, v.E!); // synced with the new .enc; your kept edits still need `dede enc`
      return log(`${rel(pair.plain)}: ${mergedNote(m)}${m.took.local.length ? "; run `dede enc` to publish your edits" : ""}`);
    }
  }
  writeAtomic(pair.plain, v.D!, 0o600);
  saveState(pair, v.D!, v.E!);
  log(`decrypted ${rel(pair.enc)} → ${rel(pair.plain)}`);
}

let quiet = false;

function status(pair: Pair): boolean {
  const v = view(pair, false);
  const say = (s: string, ok = false) => ((!ok || !quiet) && console.log(`${ok ? "✓" : "✗"} ${rel(pair.plain)}: ${s}`), ok);
  if (v.E === undefined) return say(v.P === undefined ? "missing" : "no .enc yet (run `dede enc`)");
  if (v.P === undefined) return say("no plaintext (run `dede dec`)");
  if (v.D === undefined) return say("no private key; cannot compare");
  if (v.C === v.D) return say("in sync", true);
  const st = lastSync(pair);
  const d = drift(st, v.P, v.E);
  if (d === "plain-changed") return say(`edited${keysNote(changedSince(st, values(v.P, pair.plain)))} (run \`dede enc\`)`);
  if (d === "enc-changed") return say(`.enc changed${keysNote(changedSince(st, values(v.D, pair.enc)))} (run \`dede dec\`)`);
  if (d === "both") {
    const m = merge3(pair, v.P, v.D, st);
    return say(m.conflicts.length ? `conflict: both changed ${list(m.conflicts)}` : `both changed, mergeable (run \`dede enc\`)`);
  }
  return say(`differs, no sync record — ${describeDiff(pair, values(v.P, pair.plain), values(v.D, pair.enc))}`);
}

// One value, decrypted straight from the .enc (no plaintext needed), written raw: no `$VAR`
// expansion, no `$(…)` evaluation. The last assignment wins, as in dotenv.
function get(name: string, ps: Pair[]): void {
  if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)) die("usage: dede get NAME [file|glob…]", 4);
  const found: { file: string; value: string }[] = [];
  for (const pair of ps) {
    const E = read(pair.enc);
    if (E === undefined) continue;
    const { publicKey, body } = splitEnc(lf(E), pair.enc);
    const cipher = values(body, pair.enc)[name];
    if (!cipher) continue;
    const ct = cipher[cipher.length - 1];
    let value = "";
    if (ct !== "") {
      if (!ct.startsWith(PREFIX)) die(`${rel(pair.enc)}: ${name} is not encrypted`, 4);
      try {
        value = decrypt(privateKeyFor(publicKey, pair), ct);
      } catch (e) {
        if (e instanceof DedeError) throw e;
        die(`${rel(pair.enc)}: cannot decrypt ${name} (wrong key or corrupt value)`, 3);
      }
    }
    found.push({ file: rel(pair.enc), value });
  }
  if (found.length === 0) die(`${name} not found in ${ps.length ? ps.map((p) => rel(p.enc)).join(", ") : "any .env*.enc here"}`, 1);
  if (new Set(found.map((f) => f.value)).size > 1) die(`${name} has different values in ${found.map((f) => f.file).join(", ")}; name the file: dede get ${name} <file>`, 2);
  process.stdout.write(found[0].value + (process.stdout.isTTY ? "\n" : ""));
}

function diff(pair: Pair): boolean {
  const v = view(pair, false);
  const say = (s: string, ok = false) => (console.log(`${ok ? "✓" : "✗"} ${rel(pair.plain)}: ${s}`), ok);
  if (v.E === undefined || v.P === undefined) return say(v.E === undefined ? "no .enc" : "no plaintext");
  if (v.D === undefined) return say("no private key; cannot compare");
  if (v.C === v.D) return say("no differences", true);
  return say(describeDiff(pair, values(v.P, pair.plain), values(v.D, pair.enc)));
}

// ---------- guard ----------

// Staged paths, and whether each is new to git (added, renamed/copied in, or changed type).
// With --all: every tracked path, none of them new.
function guardList(top: string, all: boolean): { path: string; added: boolean }[] {
  if (all) return git(["ls-files", "-z"], top).out.split("\0").filter(Boolean).map((path) => ({ path, added: false }));
  const parts = git(["diff", "--cached", "--name-status", "-z", "--diff-filter=d"], top).out.split("\0");
  const out: { path: string; added: boolean }[] = [];
  for (let i = 0; i < parts.length && parts[i]; ) {
    const st = parts[i++];
    if (st[0] === "R" || st[0] === "C") i++; // skip the old path
    out.push({ path: parts[i++], added: "ARCT".includes(st[0]) });
  }
  return out;
}

// Untracked plaintext env files that nobody manages: not *.local (machine-local by convention),
// not committed (public config), and without an .enc twin. Ignored directories such as
// node_modules are listed collapsed, so they are not walked.
function unmanagedEnvFiles(top: string): string[] {
  const list = [
    ...git(["ls-files", "--others", "--exclude-standard", "-z"], top).out.split("\0"),
    ...git(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"], top).out.split("\0"),
  ].filter((p) => p && !p.endsWith("/") && !/(^|\/)node_modules\//.test(p));
  return [...new Set(list)].filter((p) => {
    const name = basename(p);
    return isEnvName(name) && !name.endsWith(".local") && !existsSync(`${join(top, p)}.enc`);
  });
}
const UNMANAGED_HINT = "unmanaged plaintext env file (not committed, no .enc, not *.local): `dede enc` it and commit the .enc, or rename it to *.local";

// Plaintext files with an .enc twin whose edits have not been encrypted yet. Uses the sync record,
// so no key is needed; without a record it decrypts when the key is held.
function unencryptedEdits(top: string): string[] {
  const list0 = [
    ...git(["ls-files", "--others", "--exclude-standard", "-z"], top).out.split("\0"),
    ...git(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"], top).out.split("\0"),
  ].filter((p) => p && !p.endsWith("/") && !/(^|\/)node_modules\//.test(p));
  const bad: string[] = [];
  for (const f of [...new Set(list0)]) {
    const name = basename(f);
    const plain = join(top, f);
    if (!isEnvName(name) || !existsSync(`${plain}.enc`) || isSymlink(plain)) continue;
    const pair: Pair = { plain, enc: `${plain}.enc`, name, explicit: false };
    const P = read(plain)!;
    const E = read(pair.enc)!;
    const st = lastSync(pair);
    if (st) {
      if (sha(P) !== st.plain) bad.push(`${f}: edits not encrypted yet${keysNote(changedSince(st, values(P, plain)))}; run \`dede enc\` and commit ${name}.enc`);
      continue;
    }
    const v = view(pair, false);
    if (v.D !== undefined && v.C !== v.D) bad.push(`${f}: differs from ${name}.enc and has never been synced here (${describeDiff(pair, values(P, plain), values(v.D, pair.enc))}); see \`dede diff\``);
  }
  return bad;
}

function guard(all: boolean): void {
  const top = gitDir(process.cwd());
  const bad: string[] = [];
  for (const f of unmanagedEnvFiles(top)) bad.push(`${f}: ${UNMANAGED_HINT}`);
  bad.push(...unencryptedEdits(top));
  for (const { path: f, added } of guardList(top, all)) {
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
    } else if (added && NAME_RE.test(name) && !SKIP.has(name))
      // Already-tracked plaintext env files are public config on purpose; only new ones are blocked.
      bad.push(`${f}: new plaintext env file; commit ${name}.enc instead (dede enc), or --no-verify if it is public config`);
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
  if (!WIN && (statSync(abs).mode & 0o077) !== 0) log(`warning: ${target} is readable by other users; chmod 600 it`);
  try {
    symlinkSync(target!, link, "file");
  } catch (e) {
    if (WIN && (e as NodeJS.ErrnoException).code === "EPERM") die("Windows needs Developer Mode (or an elevated shell) to create symlinks; or use -fk / DOTENV_KEYS_FILE instead", 1);
    throw e;
  }
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
    log(`${lefthook} found; add this, then run \`lefthook install\`:\n\npre-commit:\n  commands:\n    dede-guard:\n      run: ${HOOK_CMD}\npost-merge:\n  commands:\n    dede-status:\n      run: ${NOTICE_CMD}\npost-checkout:\n  commands:\n    dede-status:\n      run: ${NOTICE_CMD}\n`);
    return;
  }
  // A JS repo with no hook manager yet gets husky (v9) as the default.
  const pkgPath = join(top, "package.json");
  const hooksPathSet = git(["config", "core.hooksPath"], top).out.trim() !== "";
  if (!hooksPathSet && !existsSync(join(top, ".husky")) && existsSync(pkgPath)) return setupHusky(top, pkgPath);
  // --git-path honours core.hooksPath (incl. `~`); husky v9 points it at .husky/_ and runs .husky/<hook>.
  // A .husky/ dir whose `husky` has not run yet (no core.hooksPath) is still where the hook belongs.
  const dir = !hooksPathSet && existsSync(join(top, ".husky"))
    ? join(top, ".husky")
    : git(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], top).out.trim().replace(/\/\.husky\/_\/?$/, "/.husky");
  if (!dir) die("cannot locate the git hooks directory");
  installHook(dir, "pre-commit", HOOK_CMD, HOOK_MARK, "runs dede guard before each commit");
  for (const h of ["post-merge", "post-checkout"]) installHook(dir, h, NOTICE_CMD, NOTICE_MARK, "reports env files to decrypt after a pull or checkout", true);
}

function installHook(dir: string, name: string, cmd: string, mark: string, what: string, quietIfPresent = false): void {
  const hook = join(dir, name);
  const prev = read(hook);
  if (prev?.includes(mark)) return quietIfPresent ? undefined : log(`${rel(hook)}: dede guard already installed`);
  if (prev?.startsWith("#!") && !/^#!.*\b(sh|bash|zsh|dash)\b/.test(prev)) die(`${rel(hook)} is not a shell script; add \`${cmd}\` to it yourself`);
  mkdirSync(dir, { recursive: true });
  // First thing after the shebang, so a later `exec`/`exit` in an existing hook cannot skip it.
  const nl = prev?.startsWith("#!") ? prev.indexOf("\n") : -1;
  const body =
    prev === undefined ? `#!/bin/sh\n${cmd}\n`
    : prev.startsWith("#!") ? (nl === -1 ? `${prev}\n${cmd}\n` : `${prev.slice(0, nl + 1)}${cmd}\n${prev.slice(nl + 1)}`)
    : `${cmd}\n${prev}`;
  writeAtomic(hook, body, prev === undefined ? 0o755 : lstatSync(hook).mode & 0o777);
  log(`${prev === undefined ? "created" : "updated"} ${rel(hook)}: ${what}`);
}

function setupHusky(top: string, pkgPath: string): void {
  const raw = readFileSync(pkgPath, "utf8");
  const pkg = JSON.parse(raw);
  const indent = /^\{\r?\n([ \t]+)"/.exec(raw)?.[1] ?? "  ";
  pkg.scripts ??= {};
  const prep: string | undefined = pkg.scripts.prepare;
  if (!prep) pkg.scripts.prepare = "husky";
  else if (!/\bhusky\b/.test(prep)) pkg.scripts.prepare = `husky && ${prep}`;
  if (!pkg.devDependencies?.husky && !pkg.dependencies?.husky) pkg.devDependencies = { ...pkg.devDependencies, husky: "^9.1.7" };
  writeAtomic(pkgPath, `${JSON.stringify(pkg, null, indent)}\n`, lstatSync(pkgPath).mode & 0o777);
  mkdirSync(join(top, ".husky"), { recursive: true });
  writeAtomic(join(top, ".husky", "pre-commit"), `${HOOK_CMD}\n`, 0o644);
  for (const h of ["post-merge", "post-checkout"]) if (!existsSync(join(top, ".husky", h))) writeAtomic(join(top, ".husky", h), `${NOTICE_CMD}\n`, 0o644);
  const husky = join(top, "node_modules", ".bin", "husky");
  if (existsSync(husky) && spawnSync(husky, [], { cwd: top, stdio: "ignore" }).status === 0)
    return log("set up husky: .husky/pre-commit runs dede guard before each commit");
  log("set up husky in package.json and .husky/pre-commit; run `bun install` (or npm/pnpm install) to activate it");
}

// ---------- args ----------

function pairs(args: string[], mode: "enc" | "dec" | "any"): Pair[] {
  const cwd = process.cwd();
  const found: { path: string; explicit: boolean }[] = [];
  if (args.length === 0) for (const n of readdirSync(cwd)) found.push({ path: join(cwd, n), explicit: false });
  for (const a of args) {
    if (/[*?[{]/.test(a)) {
      for (const f of new Bun.Glob(a).scanSync({ cwd, dot: true, onlyFiles: true }))
        if (!/(^|[\\/])(node_modules|\.git)[\\/]/.test(f)) found.push({ path: join(cwd, f), explicit: false });
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
    if (existsSync(plain) && isTracked(plain)) {
      log(`skipping ${rel(plain)}: committed in plaintext, so treated as public config (if it holds secrets: git rm --cached it and rotate them)`);
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
  quiet = rest.includes("--quiet");
  const args = rest.filter((a) => a !== "--force" && a !== "--all" && a !== "--quiet");
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
      case "status": {
        const ps = pairs(args, "any");
        each(ps, (p) => {
          if (!status(p)) code = Math.max(code, 1);
        });
        const top = gitDir(process.cwd());
        const shown = new Set(ps.map((p) => p.plain));
        for (const f of unmanagedEnvFiles(top)) {
          if (shown.has(join(top, f))) continue;
          console.log(`✗ ${rel(join(top, f))}: ${UNMANAGED_HINT}`);
          code = Math.max(code, 1);
        }
        break;
      }
      case "get":
        if (!args[0]) die("usage: dede get NAME [file|glob…]", 4);
        get(args[0], pairs(args.slice(1), "dec"));
        break;
      case "diff":
        each(pairs(args, "any"), (p) => {
          if (!diff(p)) code = Math.max(code, 1);
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
