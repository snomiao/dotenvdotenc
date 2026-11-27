#!/usr/bin/env bun
// Records what bun and @dotenvx/primitives make of a fixed set of inputs, for
// `cargo test` to hold the Rust against:
//
//   bun rs/vectors.gen.mjs            writes rs/src/testdata/*.json
//   bun rs/vectors.gen.mjs --check    fails if the files are not what it writes
//
// Run it with bun, the runtime the published `dede` runs on. Every key in
// here was made up for these files and protects nothing. path.json is
// written and checked on Linux only: it holds node:path's POSIX rules with
// /tmp as the current directory, which elsewhere it cannot be (on macOS /tmp
// is a link, and the directory is /private/tmp; Windows has neither). The
// rules are the same string functions on every system, and `cargo test`
// holds rs/src/path.rs against the file everywhere, with /tmp given.

import { createCipheriv, hkdfSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { decrypt, derive, keypair, remove, scan, upsert } from "@dotenvx/primitives";

const here = dirname(fileURLToPath(import.meta.url));
const check = process.argv.includes("--check");

// A small deterministic generator, so the files are the same on every run.
let seed = 0x2f6e2b1;
const random = () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return (seed >>> 0) / 0x100000000;
};
const pick = (list) => list[Math.floor(random() * list.length)];

// ───────────────────────── node:path ─────────────────────────

function pathVectors() {
  const cwd = process.cwd();
  process.chdir("/tmp");
  const P = ["", "/", "/a", "/a/", "/a/b", "/a//b", "/a/b/", "/a/b//", "a", "a/", "a/b", "./a", "../a", "/a/../b", "/a/./b", "/..", "//", "//a", "/a/b/../../..", ".env", "/x/.env.enc", "a//b//", ".", "..", "./", "../", "/a/b/c/.env", "/tmp", "/tmp/x", "x/../../y"];
  const out = { dirname: P.map((p) => [p, dirname(p)]), basename: P.map((p) => [p, basename(p)]), resolve: [], join: [], relative: [] };
  for (const a of ["/tmp", "/a/b", "/"]) for (const b of P) out.resolve.push([a, b, resolve(a, b)]);
  for (const a of P) for (const b of ["", ".env.keys", "x/../y", "sub/", "../z", "/abs", "."]) out.join.push([a, b, join(a, b)]);
  for (const a of P) for (const b of P) out.relative.push([a, b, relative(a, b)]);
  process.chdir(cwd);
  return out;
}

// ───────────────────────── scan, upsert, remove ─────────────────────────

const HAND_WRITTEN = [
  "",
  "\n",
  "A=1",
  "A=1\n",
  "A=1\nB=2\n",
  "# c\nexport A=\"x y\" # note\nB='lit $X'\nC=plain\nD=\"multi\nline\"\nE=\nC=dup\n",
  "A=$HOME\nB='$(touch pwned)'\nC=\"he said 'hi'\"\nD='she said \"yo\"'\nE=back\\slash\nF=naïve café ✓\nG=\"l1\\nl2\"\nH=`tick`\nI=a=b=c\n",
  "A=\nB=\n",
  "A=\n\n\nB=2\n",
  "A=\n\n\n",
  "A=1\r\nB=2\r\n",
  "A=1\rB=2\r",
  "A=\r\n\r\nB=\"x\"\r\n",
  "  A = 1  \n\tB\t=\t2\t\n",
  "export A=1\nexport   B=2\n  export C=3\n",
  "A: 1\nB:  two\nC:3\n",
  "A=1 # comment\nB=2#glued\nC=\"3\" # c\nD='4'#c\nE=#only\n",
  "A=\"x\"y\nB='x'y\nC=x\"y\"\n",
  "A=\"one\ntwo\nthree\"\nB=1\n",
  "A='one\ntwo'\nB=`three\nfour`\n",
  "A=\"unterminated\nB=1\n",
  "A='it''s'\nB=\"a\\\"b\"\nC='a\\'b'\nD=`a\\`b`\n",
  "A=\"\"\nB=''\nC=``\n",
  "A=\" spaced \"\nB='  '\n",
  "A=1\nA=2\nA=3\n",
  "A=1\nB=x\nA=1\n",
  "A=x\nAA=x\nA_A=x\nA.A=x\nA-A=x\n",
  "A.B=1\nA-B=2\n1=one\n2=two\n10=ten\nB=b\n01=zero-one\n",
  "a=lower\nA=upper\n",
  "#A=1\n # B=2\nC=3 #D=4\n",
  "not an assignment\nA=1\n",
  "=novalue\nA=1\n",
  "A==\nB= =\nC=a=b\n",
  "A=\"a=b\"\nB='#not a comment'\nC=\"# neither\" # but this is\n",
  "A=encrypted:BObcdefg==\nB=\"encrypted:BObcdefg==\"\nC='encrypted:BObcdefg=='\n",
  "A=encrypted:AAA+/=\nA=encrypted:BBB+/=\n",
  "A=1\n\n\nB=2\n\n",
  "\n\nA=1",
  "A=a|b\\c{d}(e)[f]^g$h+i*j?k.l-m\n",
  "A=\"a|b\\\\c{d}(e)[f]^g$h+i*j?k.l-m\"\n",
  "A=$&\nB=$1\nC=$$\nD=$`\nE=$'\n",
  "A= x \nB=　y\nC=﻿z\n",
  "﻿A=1\nB=2\n",
  "A=1 B=2 C=3\n",
  "A=\u{1f600}\nB=\"\u{1f600} \u{1f600}\"\n",
  "A=\0\nB=x\0y\n",
  "A=1\n\tB=2\n   C=3\n",
  "A=a b c\nB=  leading\nC=trailing  \n",
  "A=\"x\"  \nB=\"y\"\t# c\n",
  "A=\"\\n\\r\\t\\\\n\"\nB='\\n\\r\\t'\nC=\\n\\r\\t\n",
  "A='a\\'b'\nB=\"a\\'b\"\n",
  "DOTENV_PUBLIC_KEY=\"03abc\"\nDOTENV_PRIVATE_KEY_X=one,two , three\nDOTENV_PRIVATE_KEY_X=four\n",
  "constructor=1\n",
  "A=1\ntoString=2\n",
  "__proto__=1\n",
  "hasOwnProperty=1\nA=2\n",
  "A=1\nvalueOf: 2\n",
  "A=x\nB=x\n",
  "A=x\nB=\"x\"\n",
  "AB=1\nA=1\n",
  "A=1\nXA=1\n",
  "A=\nA=\n",
  "A=\nB=x\nA=\n",
  "A='x'\nA=\"x\"\nA=x\n",
  "A=x # one\nA=x # two\n",
  "export A=\n\nexport B=\n",
  "A= \nB=\t\n",
  "A=1\nB",
  "A",
  "A=\"x\ny\"z\nB=1\n",
  "A=`x`\nB=`y` # c\n",
  "A=x\\\nB=y\n",
  "A=\"x\\\"\nB=y\"\n",
  "  # indented comment\nA=1 #\n#\n",
  "A=1;B=2\n",
  "A=[1,2]\nB={\"k\":\"v\"}\nC='{\"k\":\"v\"}'\n",
  "URL=https://user:pass@host.example:8080/p?q=1#frag\n",
  "A=x\n\n# note\n\nB=y\n",
  "A:=1\nB=:2\nC: =3\n",
  "A =\nB = \nC= x\n",
  "A=1\r\nA=2\r\nB=\r\n",
  "A=\"x\ry\"\r\n",
  "A=x\r\n\r\n\r\nB=\r\n\r\n",
];

const TOKENS = ["A", "B", "AB", "A_B", "A.B", "A-B", "1", "=", "=", "=", ": ", " ", " ", "\t", "\n", "\n", "\n", "\r\n", "\r", "\"", "\"", "'", "'", "`", "#", "# ", " #", "\\", "\\n", "\\\"", "\\'", "x", "y", "value", "two words", "export ", "encrypted:QUJD", "$", "$1", "$&", "é", " ", " ", "\u{1f600}", "-", ".", "*", "(", "[", "|", "^", "{", "+", "?"];

function sources() {
  const all = [...HAND_WRITTEN];
  for (let i = 0; i < 260; i++) {
    let text = "";
    const lines = 1 + Math.floor(random() * 5);
    for (let l = 0; l < lines; l++) {
      // Mostly something like an assignment, so that there is something to find.
      if (random() < 0.8) text += pick(["", "", "", " ", "export ", "\t"]) + pick(["A", "B", "AB", "A_B", "A.B", "A-B", "1"]) + pick(["=", "=", "=", " = ", ": ", "= ", " ="]);
      const tokens = Math.floor(random() * 6);
      for (let t = 0; t < tokens; t++) text += pick(TOKENS);
      text += pick(["\n", "\n", "\n", "\r\n", "", "\n\n"]);
    }
    all.push(text);
  }
  return all.map((source) => {
    const attempt = (fn) => {
      try {
        return fn();
      } catch (e) {
        return `throws ${e.name}`;
      }
    };
    const record = { source, scan: attempt(() => JSON.stringify(scan(source).parsed)), scanRaw: attempt(() => JSON.stringify(scan(source, { expandDoubleQuotedNewlines: false, convertWindowsNewlines: false }).parsed)), upsert: [], remove: [] };
    let names = [];
    try {
      names = Object.keys(scan(source).parsed);
    } catch {}
    for (const name of [...names, "MISSING", "A"]) {
      let count = 1;
      try {
        count = scan(source).parsed[name]?.length ?? 1;
      } catch {}
      const each = Array.from({ length: count }, (_, i) => `encrypted:QUJD${i}+/=`);
      for (const value of ["new", "", "a\nb $& $1 #x", each, [...each, "extra"], each.slice(1)]) {
        record.upsert.push({ name, value, result: attempt(() => upsert(source, name, value)) });
      }
      record.remove.push({ name, result: attempt(() => remove(source, name)) });
    }
    return record;
  });
}

// ───────────────────────── keys and ciphertexts ─────────────────────────

// eciesjs's format made by hand (node:crypto for the hash and the cipher, the
// curve arithmetic written out), so that a plaintext can be any bytes, the
// result is the same on every run, and the package's reading of the format
// is checked from outside the package.
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a) => ((a % P) + P) % P;
function inverse(a) {
  let [r0, r1, s0, s1] = [mod(a), P, 1n, 0n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  return mod(s0);
}
function add(a, b) {
  if (!a) return b;
  if (!b) return a;
  const [x1, y1] = a;
  const [x2, y2] = b;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const m = x1 === x2 ? mod(3n * x1 * x1 * inverse(2n * y1)) : mod((y2 - y1) * inverse(x2 - x1));
  const x3 = mod(m * m - x1 - x2);
  return [x3, mod(m * (x1 - x3) - y1)];
}
function multiply(point, k) {
  let result = null;
  for (let base = point; k > 0n; k >>= 1n, base = add(base, base)) if (k & 1n) result = add(result, base);
  return result;
}
function power(b, e) {
  let r = 1n;
  for (b = mod(b); e > 0n; e >>= 1n, b = mod(b * b)) if (e & 1n) r = mod(r * b);
  return r;
}
// A compressed public key (hex) as a point.
function decompress(hex) {
  const x = BigInt("0x" + hex.slice(2));
  let y = power(x ** 3n + 7n, (P + 1n) / 4n);
  if ((y & 1n) !== BigInt(Number(hex.slice(0, 2)) & 1)) y = P - y;
  return [x, y];
}
const uncompressed = ([x, y]) => Buffer.from("04" + x.toString(16).padStart(64, "0") + y.toString(16).padStart(64, "0"), "hex");

function seal(publicKeyHex, plain, { nonce = Buffer.alloc(16, 7), ephemeral = Buffer.alloc(32, 9) } = {}) {
  const k = BigInt("0x" + ephemeral.toString("hex"));
  const ephemeralPublic = uncompressed(multiply(G, k));
  const shared = uncompressed(multiply(decompress(publicKeyHex), k));
  const key = Buffer.from(hkdfSync("sha256", Buffer.concat([ephemeralPublic, shared]), Buffer.alloc(0), Buffer.alloc(0), 32));
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([ephemeralPublic, nonce, cipher.getAuthTag(), body]);
}

function cryptoVectors() {
  const K1 = "1".repeat(64);
  const K2 = "2".repeat(64);
  const P1 = keypair(K1).publicKey;
  const attempt = (fn) => {
    try {
      return fn();
    } catch {
      return "throws";
    }
  };
  // `derive` is what keyringSync calls, and what keypair(key) calls for a key that is not empty.
  const derived = [K1, K2, K1.toUpperCase().replace(/1/g, "A"), "a".repeat(64), "0".repeat(64), "f".repeat(64), "0".repeat(63) + "1", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", K1 + "zz", K1 + "," + K2, K1 + "22", K1.slice(1), "", "xyz", " " + K1, K1 + " ", K1 + "\n", "0x" + K1].map((privateKey) => ({
    privateKey,
    result: attempt(() => derive(privateKey)),
  }));

  const sealed = (bytes, options) => "encrypted:" + seal(P1, bytes, options).toString("base64");
  const fixed = [
    ["", {}],
    ["x", {}],
    ["two words", { nonce: Buffer.alloc(16, 1) }],
    ["line one\nline two\r\n", { ephemeral: Buffer.alloc(32, 3) }],
    ["é→世界😀 naïve", { nonce: Buffer.from("000102030405060708090a0b0c0d0e0f", "hex") }],
    ["long ".repeat(500), {}],
    [Buffer.from([0x41, 0xff, 0x42, 0xe2, 0x82]), {}],
    [Buffer.from([0xef, 0xbb, 0xbf, 0x41]), {}],
    ["$HOME $(id) `x` \\n \"q\" 'q'", {}],
  ].map(([plain, options]) => sealed(Buffer.from(plain), options));
  const one = fixed[1];
  const raw = Buffer.from(one.slice(10), "base64");
  const variant = (change) => {
    const copy = Buffer.from(raw);
    change(copy);
    return "encrypted:" + copy.toString("base64");
  };
  const values = [
    ...fixed,
    // Damaged in one place each.
    variant((b) => (b[0] = 2)),
    variant((b) => (b[0] = 3)),
    variant((b) => (b[5] ^= 1)),
    variant((b) => (b[70] ^= 1)),
    variant((b) => (b[85] ^= 1)),
    variant((b) => (b[b.length - 1] ^= 1)),
    "encrypted:" + raw.subarray(0, 96).toString("base64"),
    "encrypted:" + raw.subarray(0, 64).toString("base64"),
    "encrypted:" + raw.subarray(0, 10).toString("base64"),
    "encrypted:",
    "encrypted:!!!",
    "encrypted:AAAA",
    // The same bytes in other spellings of base64.
    one.replace(/=+$/, ""),
    one.replace(/\+/g, "-").replace(/\//g, "_"),
    one.slice(0, 40) + " " + one.slice(40),
    one.slice(0, 40) + "\n" + one.slice(40),
    one.slice(0, 40) + "!" + one.slice(40),
    one + "=",
    one + "QUJD",
    one.slice(0, -1),
    one.slice(0, -2),
  ];
  const decryptCases = [];
  for (const value of values) {
    for (const privateKey of [K1, K2]) decryptCases.push({ privateKey, value, result: attempt(() => "ok " + decrypt(privateKey, value)) });
  }
  for (const privateKey of [K1.toUpperCase(), K1 + "," + K2, K1 + "zz", K1.slice(2), "0".repeat(64), "f".repeat(64), "nonsense"]) {
    decryptCases.push({ privateKey, value: one, result: attempt(() => "ok " + decrypt(privateKey, one)) });
  }
  return { derive: derived, decrypt: decryptCases };
}

// ───────────────────────── write ─────────────────────────

const files = {
  ...(process.platform === "linux" ? { "path.json": JSON.stringify(pathVectors()) } : {}),
  "primitives.json": JSON.stringify({ sources: sources(), ...cryptoVectors() }),
};

let stale = false;
for (const [name, text] of Object.entries(files)) {
  const path = join(here, "src/testdata", name);
  let current;
  try {
    current = readFileSync(path, "utf8");
  } catch {}
  if (current === text) continue;
  if (check) {
    console.error(`${relative(process.cwd(), path)} is not what rs/vectors.gen.mjs writes`);
    stale = true;
  } else {
    writeFileSync(path, text);
    console.error(`wrote ${relative(process.cwd(), path)}`);
  }
}
process.exit(stale ? 1 : 0);
