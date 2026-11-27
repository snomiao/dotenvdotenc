#!/usr/bin/env node
// What a parity case looks at after the command has run, where the files
// themselves cannot be compared: ciphertext, generated keys and the salted
// sync record differ on every run. Each probe prints what must be the same
// for both implementations and checks the rest against @dotenvx/primitives
// and node:crypto, so "the TypeScript side reads what Rust wrote" is part of
// every case that writes.
//
//   node rs/parity/probe.mjs enc <file.enc> [keys file | digit]
//       the .enc with every ciphertext replaced by ⟦its plaintext⟧, after
//       checking that it is exactly what dotenvx's encrypt writes
//   node rs/parity/probe.mjs keys <keys file> [file.enc…]
//       the keys file with every private key replaced by a number, and for
//       each .enc whether the file holds the key of its header
//   node rs/parity/probe.mjs state [file…]
//       the sync record: for each entry whether its hashes are those of the
//       files now in the work tree (as dede.ts computes them)
//
// It reads only the files of the case it is run in.

import { spawnSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, join } from "node:path";

const { decrypt, derive, scan } = createRequire(import.meta.url)("@dotenvx/primitives");
const [what, ...args] = process.argv.slice(2);
const lf = (text) => text.replace(/\r\n/g, "\n");
const read = (file) => readFileSync(file, "utf8");
const privateKeysOf = (text) =>
  Object.entries(scan(text).parsed)
    .filter(([name]) => name.startsWith("DOTENV_PRIVATE_KEY"))
    .flatMap(([, values]) => values.flatMap((v) => v.split(",").map((s) => s.trim())));

function enc(file, keySource = ".env.keys") {
  const text = read(file);
  const header = /^(?:#\/.*\r?\n)*DOTENV_PUBLIC_KEY[A-Z0-9_]*="(0[23][0-9a-f]{64})"\r?\n/.exec(text);
  if (!header) return console.log(`${file}: NO HEADER\n${text}`);
  const candidates = /^[0-9a-f]$/.test(keySource) ? [keySource.repeat(64)] : existsSync(keySource) ? privateKeysOf(read(keySource)) : [];
  const key = candidates.find((k) => {
    try {
      return derive(k) === header[1];
    } catch {
      return false;
    }
  });
  if (!key) return console.log(`${file}: NO KEY FOR ITS HEADER in ${keySource}\n${text}`);
  // Each ciphertext must be canonical base64 of 65 + 16 + 16 + n bytes, starting with an uncompressed point.
  const shown = text.replace(/encrypted:[A-Za-z0-9+/=]*/g, (ciphertext) => {
    const raw = Buffer.from(ciphertext.slice(10), "base64");
    if (raw.toString("base64") !== ciphertext.slice(10)) return "⟦NOT CANONICAL BASE64⟧";
    if (raw.length < 97 || raw[0] !== 4) return "⟦NOT THE ECIES LAYOUT⟧";
    try {
      const plain = decrypt(key, ciphertext);
      if (Buffer.byteLength(plain) !== raw.length - 97) return "⟦LENGTH DOES NOT FIT⟧";
      return `⟦${JSON.stringify(plain)}⟧`;
    } catch (e) {
      return `⟦DOES NOT DECRYPT: ${e.code}⟧`;
    }
  });
  console.log(shown.replace(header[1], candidates.length === 1 && /^[0-9a-f]$/.test(keySource) ? header[1] : "<the public key of a key in the keys file>"));
}

function keys(file, ...encFiles) {
  const text = read(file);
  const found = privateKeysOf(text);
  let n = 0;
  console.log(text.replace(/[0-9a-f]{64}/g, (k) => (found.includes(k) ? `<private key ${(n = found.indexOf(k) + 1)}>` : k)));
  void n;
  for (const encFile of encFiles) {
    const header = /DOTENV_PUBLIC_KEY[A-Z0-9_]*="(0[23][0-9a-f]{64})"/.exec(read(encFile));
    const at = found.findIndex((k) => {
      try {
        return derive(k) === header?.[1];
      } catch {
        return false;
      }
    });
    console.log(`${encFile}: ${at === -1 ? "NOT encrypted for a key in this file" : `encrypted for private key ${at + 1}`}`);
  }
}

function state(...only) {
  const git = (...a) => spawnSync("git", a, { encoding: "utf8" }).stdout.trim();
  const file = git("rev-parse", "--path-format=absolute", "--git-path", "dotenvdotenc/state.json");
  const top = git("rev-parse", "--show-toplevel");
  if (!existsSync(file)) return console.log("no sync record");
  const text = read(file);
  let all;
  try {
    all = JSON.parse(text);
  } catch {
    return console.log(`sync record is not JSON:\n${text}`);
  }
  console.log(`sync record: ${text === JSON.stringify(all, null, 2) + "\n" ? "written as JSON.stringify(…, null, 2) and a newline" : "NOT in the form dede writes"}, mode ${(spawnSync("stat", ["-c", "%a", file], { encoding: "utf8" }).stdout || "").trim()}`);
  const sha = (t) => createHash("sha256").update(lf(t)).digest("hex");
  const hmac = (salt, t) => createHmac("sha256", salt).update(t).digest("hex").slice(0, 24);
  const commentsOf = (t) => t.split("\n").filter((l) => l.trimStart().startsWith("#")).join("\n");
  for (const [key, entry] of Object.entries(all)) {
    if (only.length && !only.includes(key)) continue;
    const say = (verdict) => console.log(`  ${key}: ${verdict}`);
    if (!entry || typeof entry !== "object") {
      say(`not an entry: ${JSON.stringify(entry)}`);
      continue;
    }
    const fields = Object.keys(entry).join(",");
    if (fields !== "plain,enc,salt,keys,notes" || !/^[0-9a-f]{32}$/.test(entry.salt)) {
      say(`fields ${fields}, salt ${JSON.stringify(entry.salt)}`);
      continue;
    }
    const plain = existsSync(join(top, key)) ? read(join(top, key)) : undefined;
    const encText = existsSync(join(top, key) + ".enc") ? read(join(top, key) + ".enc") : undefined;
    const parts = [
      `plaintext ${plain === undefined ? "gone" : sha(plain) === entry.plain ? "as recorded" : "CHANGED since"}`,
      `.enc ${encText === undefined ? "gone" : sha(encText) === entry.enc ? "as recorded" : "CHANGED since"}`,
    ];
    if (plain !== undefined) {
      const parsed = scan(plain).parsed;
      const names = [...new Set([...Object.keys(parsed), ...Object.keys(entry.keys)])];
      const off = names.filter((k) => (k in parsed ? hmac(entry.salt, JSON.stringify(parsed[k])) : undefined) !== entry.keys[k]);
      parts.push(`keys [${Object.keys(entry.keys).join(",")}]${off.length ? ` of which CHANGED since: ${off.join(",")}` : ""}`);
      parts.push(`comments ${hmac(entry.salt, commentsOf(lf(plain))) === entry.notes ? "as recorded" : "CHANGED since"}`);
    } else parts.push(`keys [${Object.keys(entry.keys).join(",")}]`);
    say(parts.join("; "));
  }
}

if (what === "enc") enc(...args);
else if (what === "keys") keys(...args);
else if (what === "state") state(...args);
else {
  console.error(`usage: probe.mjs enc|keys|state … (got ${what}; this is ${basename(import.meta.url)})`);
  process.exit(2);
}
