import { afterEach, describe, expect, test } from "bun:test";
import { scan } from "@dotenvx/primitives";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CLI = resolve(import.meta.dir, "../src/dede.ts");
const DOTENVX = resolve(import.meta.dir, "../node_modules/.bin/dotenvx");
const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const cleanEnv = () => Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("DOTENV_")));

class Repo {
  readonly dir = mkdtempSync(join(tmpdir(), "dede-test-"));
  constructor(gitignore = ".env*\n!.env*.enc\n") {
    dirs.push(this.dir);
    this.git("init", "-q", "-b", "main");
    this.git("config", "user.email", "t@example.com");
    this.git("config", "user.name", "t");
    this.git("config", "commit.gpgsign", "false");
    if (gitignore) this.write(".gitignore", gitignore);
  }
  git(...args: string[]) {
    const r = spawnSync("git", args, { cwd: this.dir, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout;
  }
  write(name: string, text: string) {
    mkdirSync(join(this.dir, name, ".."), { recursive: true });
    writeFileSync(join(this.dir, name), text);
  }
  read = (name: string) => readFileSync(join(this.dir, name), "utf8");
  exists = (name: string) => existsSync(join(this.dir, name));
  rm = (name: string) => rmSync(join(this.dir, name), { force: true });
  dede(args: string[], env: Record<string, string> = {}) {
    const r = spawnSync("bun", ["--no-env-file", CLI, ...args], { cwd: this.dir, encoding: "utf8", env: { ...cleanEnv(), ...env } });
    return { code: r.status, out: r.stdout, err: r.stderr };
  }
  statePath = () => join(this.dir, ".git/dotenvdotenc/state.json");
}

const vals = (text: string) => scan(text).parsed;
const body = (enc: string) => enc.slice(enc.indexOf("\n\n") + 2);

describe("enc / dec round trip", () => {
  test("first enc creates .enc (dotenvx header) and .env.keys; every value encrypted", () => {
    const r = new Repo();
    r.write(".env.local", "# api\nAPI_KEY=dummy-1\nNAME=\"hello world\"\n");
    const res = r.dede(["enc"]);
    expect(res.code).toBe(0);
    const enc = r.read(".env.local.enc");
    expect(enc).toMatch(/^#\/-+\[DOTENV_PUBLIC_KEY\]/);
    expect(enc).toMatch(/\nDOTENV_PUBLIC_KEY_LOCAL="0[23][0-9a-f]{64}"\n\n# api\nAPI_KEY=encrypted:/);
    expect(enc).toMatch(/\nNAME="encrypted:[^"]+"\n$/);
    expect(enc).not.toContain("dummy-1");
    expect(r.read(".env.keys")).toMatch(/# \.env\.local\nDOTENV_PRIVATE_KEY_LOCAL=[0-9a-f]{64}\n$/);
    expect(statSync(join(r.dir, ".env.keys")).mode & 0o777).toBe(0o600);
    expect(res.err).toContain("back it up");
  });

  test("dec on a fresh checkout reproduces the plaintext", () => {
    const r = new Repo();
    const text = "# c\nexport A=\"x y\" # note\nB='lit $X'\nC=plain\nD=\"multi\nline\"\nE=\nC=dup\n";
    r.write(".env.local", text);
    expect(r.dede(["enc"]).code).toBe(0);
    r.rm(".env.local");
    rmSync(r.statePath());
    expect(r.dede(["dec"]).code).toBe(0);
    expect(r.read(".env.local")).toBe(text);
    expect(statSync(join(r.dir, ".env.local")).mode & 0o777).toBe(0o600);
  });

  test("values survive literally: $VAR, $(cmd), quotes, backslashes, unicode, escaped newlines", () => {
    const r = new Repo();
    const text = [
      "A=$HOME",
      "B='$(touch pwned)'",
      "C=\"he said 'hi'\"",
      "D='she said \"yo\"'",
      "E=back\\slash",
      "F=日本語 ✓",
      'G="l1\\nl2"',
      "H=`tick`",
      "I=a=b=c",
      "",
    ].join("\n");
    r.write(".env.local", text);
    expect(r.dede(["enc"]).code).toBe(0);
    expect(r.exists("pwned")).toBe(false);
    r.rm(".env.local");
    expect(r.dede(["dec", "--force"]).code).toBe(0);
    expect(vals(r.read(".env.local"))).toEqual(vals(text));
    expect(r.exists("pwned")).toBe(false);
  });

  test(".env maps to DOTENV_PUBLIC_KEY; .env.development.local to _DEVELOPMENT_LOCAL", () => {
    const r = new Repo();
    r.write(".env", "A=1\n");
    r.write(".env.development.local", "B=2\n");
    expect(r.dede(["enc"]).code).toBe(0);
    expect(r.read(".env.enc")).toMatch(/\nDOTENV_PUBLIC_KEY="/);
    expect(r.read(".env.development.local.enc")).toMatch(/\nDOTENV_PUBLIC_KEY_DEVELOPMENT_LOCAL="/);
    expect(r.read(".env.keys")).toMatch(/\nDOTENV_PRIVATE_KEY=[0-9a-f]{64}\n[\s\S]*DOTENV_PRIVATE_KEY_DEVELOPMENT_LOCAL=/);
  });

  test("dotenvx itself reads the .enc with .env.keys", () => {
    const r = new Repo();
    r.write(".env.local", "HELLO=\"dummy world\"\n");
    expect(r.dede(["enc"]).code).toBe(0);
    r.rm(".env.local");
    const out = spawnSync(DOTENVX, ["run", "-q", "-f", ".env.local.enc", "--", "sh", "-c", 'printf %s "$HELLO"'], { cwd: r.dir, encoding: "utf8", env: cleanEnv() });
    expect(out.stdout).toBe("dummy world");
  });

  test("a key already in .env.keys (e.g. from dotenvx) is reused", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.write(".env.keys", "DOTENV_PRIVATE_KEY_LOCAL=" + "1".repeat(64) + "\n");
    expect(r.dede(["enc"]).code).toBe(0);
    expect(r.read(".env.keys")).toBe("DOTENV_PRIVATE_KEY_LOCAL=" + "1".repeat(64) + "\n");
    r.rm(".env.local");
    expect(r.dede(["dec", "--force"]).code).toBe(0);
    expect(r.read(".env.local")).toBe("A=1\n");
  });

  test("private key from the environment works without .env.keys", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    expect(r.dede(["enc"]).code).toBe(0);
    const key = /DOTENV_PRIVATE_KEY_LOCAL=([0-9a-f]{64})/.exec(r.read(".env.keys"))![1];
    r.rm(".env.keys");
    r.rm(".env.local");
    expect(r.dede(["dec"]).code).toBe(3);
    expect(r.dede(["dec"], { DOTENV_PRIVATE_KEY_LOCAL: key }).code).toBe(0);
    expect(r.read(".env.local")).toBe("A=1\n");
  });
});

describe("diffs", () => {
  test("re-running enc with no change rewrites nothing", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\nB=2\n");
    r.dede(["enc"]);
    const before = r.read(".env.local.enc");
    expect(r.dede(["enc"]).err).toContain("in sync");
    expect(r.read(".env.local.enc")).toBe(before);
  });

  test("changing one value changes exactly one line", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\nB=2\nC=3\n");
    r.dede(["enc"]);
    const before = r.read(".env.local.enc").split("\n");
    r.write(".env.local", "A=1\nB=changed\nC=3\n");
    expect(r.dede(["enc"]).code).toBe(0);
    const after = r.read(".env.local.enc").split("\n");
    expect(after.length).toBe(before.length);
    expect(after.filter((l, i) => l !== before[i])).toEqual([expect.stringMatching(/^B=encrypted:/)]);
  });
});

describe("drift", () => {
  function twoClones() {
    const a = new Repo();
    a.write(".env.local", "A=1\nB=2\n");
    a.dede(["enc"]);
    a.git("add", ".gitignore", ".env.local.enc");
    a.git("commit", "-qm", "init");
    const b = new Repo(null as unknown as string);
    b.git("pull", "-q", a.dir, "main");
    b.write(".env.keys", a.read(".env.keys"));
    expect(b.dede(["dec"]).code).toBe(0);
    return { a, b };
  }

  test("pulled .enc: enc refuses (exit 1), dec updates", () => {
    const { a, b } = twoClones();
    a.write(".env.local", "A=1\nB=new\n");
    a.dede(["enc"]);
    a.git("commit", "-qam", "b");
    b.git("pull", "-q", a.dir, "main");
    const res = b.dede(["enc"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain("run `dede dec` first");
    expect(b.dede(["dec"]).code).toBe(0);
    expect(b.read(".env.local")).toBe("A=1\nB=new\n");
  });

  test("local edit: dec refuses (exit 1), enc writes", () => {
    const { b } = twoClones();
    b.write(".env.local", "A=edited\nB=2\n");
    expect(b.dede(["dec"]).code).toBe(1);
    expect(b.read(".env.local")).toBe("A=edited\nB=2\n");
    expect(b.dede(["enc"]).code).toBe(0);
  });

  test("both changed: conflict (exit 2) on both commands; --force picks a side", () => {
    const { a, b } = twoClones();
    a.write(".env.local", "A=1\nB=theirs\n");
    a.dede(["enc"]);
    a.git("commit", "-qam", "b");
    b.git("pull", "-q", a.dir, "main");
    b.write(".env.local", "A=mine\nB=2\n");
    expect(b.dede(["enc"]).code).toBe(2);
    expect(b.dede(["dec"]).code).toBe(2);
    expect(b.read(".env.local")).toBe("A=mine\nB=2\n");
    expect(b.dede(["dec", "--force"]).code).toBe(0);
    expect(b.read(".env.local")).toBe("A=1\nB=theirs\n");
  });

  test("identical changes on both sides count as in sync", () => {
    const { a, b } = twoClones();
    a.write(".env.local", "A=1\nB=same\n");
    a.dede(["enc"]);
    a.git("commit", "-qam", "b");
    b.git("pull", "-q", a.dir, "main");
    b.write(".env.local", "A=1\nB=same\n");
    expect(b.dede(["enc"]).code).toBe(0);
    expect(b.dede(["status"]).code).toBe(0);
  });

  test("no sync record and files differ: refuse without --force", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    rmSync(r.statePath());
    r.write(".env.local", "A=2\n");
    expect(r.dede(["enc"]).code).toBe(2);
    expect(r.dede(["dec"]).code).toBe(2);
    expect(r.dede(["enc", "--force"]).code).toBe(0);
  });
});

describe("safety", () => {
  test("wrong key: exit 3, plaintext untouched", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    r.write(".env.keys", "DOTENV_PRIVATE_KEY_LOCAL=" + "2".repeat(64) + "\n");
    r.rm(".env.local");
    expect(r.dede(["dec"]).code).toBe(3);
    expect(r.exists(".env.local")).toBe(false);
  });

  test("tampered ciphertext: exit 3", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    r.write(".env.local.enc", r.read(".env.local.enc").replace(/A=encrypted:(.)/, (_, c) => `A=encrypted:${c === "B" ? "C" : "B"}`));
    r.rm(".env.local");
    expect(r.dede(["dec"]).code).toBe(3);
  });

  test("a line that is not an assignment or comment is refused (it would be committed plaintext)", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\nsecret-without-equals\n");
    const res = r.dede(["enc"]);
    expect(res.code).toBe(4);
    expect(r.exists(".env.local.enc")).toBe(false);
    expect(res.err).not.toContain("secret-without-equals");
  });

  test("plaintext that is not gitignored is refused", () => {
    const r = new Repo("");
    r.write(".env.local", "A=1\n");
    const res = r.dede(["enc"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain("dede setup");
    expect(r.exists(".env.keys")).toBe(false);
  });

  test("plaintext tracked by git is refused", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.git("add", "-f", ".env.local");
    expect(r.dede(["enc"]).code).toBe(1);
  });

  test("symlinked plaintext is refused", () => {
    const r = new Repo();
    r.write("real", "A=1\n");
    symlinkSync("real", join(r.dir, ".env.local"));
    expect(r.dede(["enc"]).code).toBe(4);
  });

  test("DOTENV_* keys inside a plaintext file are refused", () => {
    const r = new Repo();
    r.write(".env.local", "DOTENV_PRIVATE_KEY_X=" + "1".repeat(64) + "\n");
    expect(r.dede(["enc"]).code).toBe(4);
  });
});

describe("arguments", () => {
  test("glob and shell-expanded lists: .env.keys and .enc names map to pairs, nothing else", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.write(".env.prod", "B=2\n");
    r.write(".envrc", "use nix\n");
    expect(r.dede(["enc", ".env.*"]).code).toBe(0);
    expect(r.exists(".env.local.enc") && r.exists(".env.prod.enc")).toBe(true);
    expect(r.exists(".envrc.enc") || r.exists(".env.keys.enc")).toBe(false);
    r.rm(".env.local");
    r.rm(".env.prod");
    expect(r.dede(["dec", ".env.keys", ".envrc", ".env.local.enc", ".env.prod"]).code).toBe(0);
    expect(r.read(".env.local")).toBe("A=1\n");
    expect(r.read(".env.prod")).toBe("B=2\n");
  });

  test("default enc covers every plaintext .env* in the directory", () => {
    const r = new Repo();
    r.write(".env", "A=1\n");
    r.write(".env.local", "B=1\n");
    r.write(".env.example", "A=\n");
    expect(r.dede(["enc"]).code).toBe(0);
    expect([".env.enc", ".env.local.enc"].every(r.exists)).toBe(true);
    expect(r.exists(".env.example.enc")).toBe(false);
  });

  test("a non-env file name is an error", () => {
    const r = new Repo();
    r.write("config.json", "{}");
    expect(r.dede(["enc", "config.json"]).code).toBe(4);
  });

  test("status reports each file and exits 1 when anything is out of sync", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    expect(r.dede(["status"]).code).toBe(0);
    r.write(".env.local", "A=2\n");
    const res = r.dede(["status"]);
    expect(res.code).toBe(1);
    expect(res.out).toContain("edited (run `dede enc`)");
  });
});

describe("guard and setup", () => {
  test("setup writes .gitignore rules and a pre-commit hook, idempotently", () => {
    const r = new Repo("");
    expect(r.dede(["setup"]).code).toBe(0);
    expect(r.read(".gitignore")).toContain(".env*\n!.env*.enc\n");
    const hook = r.read(".git/hooks/pre-commit");
    expect(hook).toContain("dede guard");
    expect(statSync(join(r.dir, ".git/hooks/pre-commit")).mode & 0o111).not.toBe(0);
    expect(r.dede(["setup"]).code).toBe(0);
    expect(r.read(".gitignore").match(/!\.env\*\.enc/g)!.length).toBe(1);
    expect(r.read(".git/hooks/pre-commit")).toBe(hook);
  });

  test("setup appends to an existing hook and keeps existing .gitignore content", () => {
    const r = new Repo("node_modules/\n");
    r.write(".git/hooks/pre-commit", "#!/bin/sh\necho existing\n");
    chmodSync(join(r.dir, ".git/hooks/pre-commit"), 0o755);
    expect(r.dede(["setup"]).code).toBe(0);
    expect(r.read(".git/hooks/pre-commit")).toMatch(/^#!\/bin\/sh\n.*dede guard.*\|\| exit 1\necho existing\n$/);
    expect(r.read(".gitignore")).toMatch(/^node_modules\/\n\n# dede/);
  });

  test("setup uses husky's directory when core.hooksPath is .husky/_", () => {
    const r = new Repo("");
    r.git("config", "core.hooksPath", ".husky/_");
    r.write(".husky/pre-commit", "bun test\n");
    expect(r.dede(["setup"]).code).toBe(0);
    expect(r.read(".husky/pre-commit")).toMatch(/^.*dede guard.*\nbun test\n$/);
  });

  test("setup prints a snippet for lefthook instead of editing YAML", () => {
    const r = new Repo("");
    r.write("lefthook.yml", "pre-commit:\n  commands: {}\n");
    const res = r.dede(["setup"]);
    expect(res.code).toBe(0);
    expect(res.err).toContain("dede-guard:");
    expect(r.read("lefthook.yml")).toBe("pre-commit:\n  commands: {}\n");
  });

  test("guard blocks staged plaintext, .env.keys, unencrypted .enc and private keys; passes a real .enc", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    r.git("add", ".gitignore", ".env.local.enc");
    expect(r.dede(["guard"]).code).toBe(0);

    r.git("add", "-f", ".env.local", ".env.keys");
    const res = r.dede(["guard"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain(".env.local: plaintext env file");
    expect(res.err).toContain(".env.keys: private keys");
    expect(res.err).not.toMatch(/[0-9a-f]{64}/);
    r.git("rm", "-q", "--cached", ".env.local", ".env.keys");

    r.write(".env.local.enc", r.read(".env.local.enc") + "LEAK=plain\n");
    r.git("add", ".env.local.enc");
    expect(r.dede(["guard"]).err).toContain("LEAK is not encrypted");

    r.git("checkout", "--", ".env.local.enc");
    r.write("notes.md", "DOTENV_PRIVATE_KEY_LOCAL=" + "a".repeat(64) + "\n");
    r.git("add", "notes.md");
    expect(r.dede(["guard"]).err).toContain("notes.md: contains a DOTENV_PRIVATE_KEY");
  });

  test("the installed hook really blocks a commit", () => {
    const r = new Repo("");
    const bin = join(r.dir, "node_modules/.bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "dede"), `#!/bin/sh\nexec bun --no-env-file ${CLI} "$@"\n`);
    chmodSync(join(bin, "dede"), 0o755);
    r.write(".gitignore", "node_modules/\n");
    r.dede(["setup"]);
    r.write(".env.local", "A=1\n");
    r.git("add", "-f", ".env.local");
    const c = spawnSync("git", ["commit", "-qm", "x"], { cwd: r.dir, encoding: "utf8", env: cleanEnv() });
    expect(c.status).not.toBe(0);
    expect(c.stderr).toContain("plaintext env file");
  });
});

describe("review 1 regressions", () => {
  const leakCases = ["PASSWORD=hunter#2secretTAIL\n", 'A="x"#SEKRET\n', "A='x'#SEKRET\n", "A=#SEKRET\n"];
  for (const text of leakCases)
    test(`text glued after a value is refused, not committed: ${JSON.stringify(text)}`, () => {
      const r = new Repo();
      r.write(".env.local", text);
      const res = r.dede(["enc"]);
      expect(res.code).toBe(4);
      expect(res.err).toContain("quote the whole value");
      expect(res.err).not.toContain("SEKRET");
      expect(res.err).not.toContain("2secret");
      expect(r.exists(".env.local.enc")).toBe(false);
    });

  test("a spaced comment after a value is still fine", () => {
    const r = new Repo();
    r.write(".env.local", "A=abc # note\nB=\"x y\" # note\n");
    expect(r.dede(["enc"]).code).toBe(0);
  });

  test("guard blocks an .enc with plaintext glued after the ciphertext", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    r.write(".env.local.enc", r.read(".env.local.enc").replace(/(A=encrypted:\S+)/, "$1#SEKRET"));
    r.git("add", ".env.local.enc");
    const res = r.dede(["guard"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain("(A) would commit part of its value");
    expect(res.err).not.toContain("SEKRET");
  });

  test("setup puts the guard before an existing hook's exec, so it still runs", () => {
    const r = new Repo("");
    r.write(".git/hooks/pre-commit", '#!/usr/bin/env bash\nexec true "$@"\n');
    chmodSync(join(r.dir, ".git/hooks/pre-commit"), 0o755);
    const bin = join(r.dir, "node_modules/.bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "dede"), `#!/bin/sh\nexec bun --no-env-file ${CLI} "$@"\n`);
    chmodSync(join(bin, "dede"), 0o755);
    r.write(".gitignore", "node_modules/\n");
    expect(r.dede(["setup"]).code).toBe(0);
    r.write(".env.local", "A=1\n");
    r.git("add", "-f", ".env.local");
    const c = spawnSync("git", ["commit", "-qm", "x"], { cwd: r.dir, encoding: "utf8", env: cleanEnv() });
    expect(c.status).not.toBe(0);
  });

  test("setup refuses a non-shell hook under a custom core.hooksPath", () => {
    const r = new Repo("");
    r.write(".githooks/pre-commit", '#!/usr/bin/env python3\nprint("py")\n');
    r.git("config", "core.hooksPath", ".githooks");
    expect(r.dede(["setup"]).code).toBe(1);
    expect(r.read(".githooks/pre-commit")).toBe('#!/usr/bin/env python3\nprint("py")\n');
  });

  test("setup follows core.hooksPath=~/… to the home directory, not a literal ~ dir", () => {
    const home = mkdtempSync(join(tmpdir(), "dede-home-"));
    dirs.push(home);
    const r = new Repo("");
    r.git("config", "core.hooksPath", "~/hooks");
    const res = spawnSync("bun", ["--no-env-file", CLI, "setup"], { cwd: r.dir, encoding: "utf8", env: { ...cleanEnv(), HOME: home } });
    expect(res.status).toBe(0);
    expect(existsSync(join(home, "hooks/pre-commit"))).toBe(true);
    expect(r.exists("~")).toBe(false);
  });

  test("guard sees a type change (symlink replaced by a file with a key)", () => {
    const r = new Repo();
    symlinkSync("README", join(r.dir, "keys.txt"));
    r.git("add", ".gitignore", "keys.txt");
    r.git("commit", "-qm", "i");
    r.rm("keys.txt");
    r.write("keys.txt", "DOTENV_PRIVATE_KEY_LOCAL=" + "a".repeat(64) + "\n");
    r.git("add", "keys.txt");
    expect(r.dede(["guard"]).err).toContain("keys.txt: contains a DOTENV_PRIVATE_KEY");
  });

  test("guard finds private keys in YAML, JSON and uppercase hex", () => {
    const r = new Repo();
    r.write("ci.yml", "env:\n  DOTENV_PRIVATE_KEY_PRODUCTION: " + "b".repeat(64) + "\n");
    r.write("k.json", '{"DOTENV_PRIVATE_KEY": "' + "c".repeat(64) + '"}\n');
    r.write("up.txt", "DOTENV_PRIVATE_KEY=" + "D".repeat(64) + "\n");
    r.git("add", "ci.yml", "k.json", "up.txt");
    const err = r.dede(["guard"]).err;
    for (const f of ["ci.yml", "k.json", "up.txt"]) expect(err).toContain(`${f}: contains a DOTENV_PRIVATE_KEY`);
  });

  test("an .enc with CRLF line endings still decrypts and passes guard", () => {
    const r = new Repo();
    r.write(".env.local", "A=one\n");
    r.dede(["enc"]);
    r.write(".env.local.enc", r.read(".env.local.enc").replace(/\n/g, "\r\n"));
    r.rm(".env.local");
    expect(r.dede(["dec", "--force"]).code).toBe(0);
    expect(vals(r.read(".env.local")).A).toEqual(["one"]);
    r.git("add", ".env.local.enc");
    expect(r.dede(["guard"]).code).toBe(0);
  });

  test("an empty last value keeps the final newline", () => {
    const r = new Repo();
    r.write(".env.local", "X=1\nA=\n");
    r.dede(["enc"]);
    expect(r.read(".env.local.enc").endsWith("\n")).toBe(true);
    r.rm(".env.local");
    expect(r.dede(["dec", "--force"]).code).toBe(0);
    expect(r.read(".env.local")).toBe("X=1\nA=\n");
  });

  test("a gitignored .enc only warns", () => {
    const r = new Repo(".env*\n");
    r.write(".env.local", "A=1\n");
    const res = r.dede(["enc"]);
    expect(res.code).toBe(0);
    expect(res.err).toContain("warning: .env.local.enc is gitignored");
    expect(r.exists(".env.local.enc")).toBe(true);
  });

  test("an invalid key fails that file only, without a stack trace", () => {
    const r = new Repo();
    r.write(".env.a", "A=1\n");
    r.write(".env.b", "B=1\n");
    r.write(".env.keys", "DOTENV_PRIVATE_KEY_A=" + "0".repeat(64) + "\n");
    const res = r.dede(["enc"]);
    expect(res.code).toBe(3);
    expect(res.err).not.toContain("    at ");
    expect(r.exists(".env.b.enc")).toBe(true);
  });

  test("globs skip node_modules and .git", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.write("node_modules/pkg/.env", "X=1\n");
    expect(r.dede(["enc", "**/.env*"]).code).toBe(0);
    expect(r.exists("node_modules/pkg/.env.enc")).toBe(false);
    expect(r.exists(".env.local.enc")).toBe(true);
  });
});
