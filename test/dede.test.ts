import { afterEach, describe, expect, test } from "bun:test";
import { scan } from "@dotenvx/primitives";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
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
      "F=naïve café ✓",
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

  test("plaintext tracked by git is public config: enc skips it, named or not", () => {
    const r = new Repo();
    r.write(".env.production", "VITE_API_BASE_URL=\n");
    r.git("add", "-f", ".env.production");
    for (const args of [["enc"], ["enc", ".env.production"]]) {
      const res = r.dede(args);
      expect(res.code).toBe(0);
      expect(res.err).toContain("skipping .env.production: committed in plaintext");
    }
    expect(r.exists(".env.production.enc")).toBe(false);
    expect(r.exists(".env.keys")).toBe(false);
  });

  test("symlinked plaintext: refused when named, skipped in a default run", () => {
    const r = new Repo();
    r.write(".env.dev", "A=1\n");
    symlinkSync(".env.dev", join(r.dir, ".env.local"));
    expect(r.dede(["enc", ".env.local"]).code).toBe(4);
    const res = r.dede(["enc"]);
    expect(res.code).toBe(0);
    expect(res.err).toContain("skipping .env.local: symlink");
    expect(r.exists(".env.dev.enc")).toBe(true);
    expect(r.exists(".env.local.enc")).toBe(false);
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
    expect(res.err).toContain(".env.local: new plaintext env file");
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

describe("comments and modes", () => {
  const leaky = [
    "# OLD_TOKEN=" + "f".repeat(40) + "\nA=1\n",
    "# export OLD='" + "g".repeat(20) + "'\nA=1\n",
    "# was: https://user:pw@example.com/x\nA=1\n",
    "# RECHROME_URL=https://abcdEFGH1234@host:1/?token=x\nA=1\n",
  ];
  for (const text of leaky)
    test(`a comment holding a credential is refused: ${JSON.stringify(text.split("\n")[0].slice(0, 30))}`, () => {
      const r = new Repo();
      r.write(".env.local", text);
      const res = r.dede(["enc"]);
      expect(res.code).toBe(4);
      expect(res.err).toContain("comment holding a credential-like value");
      expect(res.err).not.toMatch(/ffff|gggg|pw@|abcdEFGH/);
      expect(r.exists(".env.local.enc")).toBe(false);
    });

  test("ordinary comments, short commented settings and plain URLs are fine", () => {
    const r = new Repo();
    r.write(".env.local", "# NODE_ENV=production\n# docs: https://example.com/a?b=c\n# rotate at https://dash.example.com\nA=1\n");
    expect(r.dede(["enc"]).code).toBe(0);
  });

  test("guard blocks an .enc whose comment holds a credential", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.dede(["enc"]);
    r.write(".env.local.enc", r.read(".env.local.enc") + "# OLD=" + "h".repeat(32) + "\n");
    r.git("add", ".env.local.enc");
    const res = r.dede(["guard"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain("comment holding a credential-like value");
    expect(res.err).not.toContain("hhhh");
  });

  test("enc tightens a group/world-readable plaintext file to 0600", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    chmodSync(join(r.dir, ".env.local"), 0o664);
    const res = r.dede(["enc"]);
    expect(res.code).toBe(0);
    expect(res.err).toContain("tightened .env.local to 0600");
    expect(statSync(join(r.dir, ".env.local")).mode & 0o777).toBe(0o600);
  });

  test("setup keeps an existing hook's file mode (husky files need no +x)", () => {
    const r = new Repo("");
    r.git("config", "core.hooksPath", ".husky/_");
    r.write(".husky/pre-commit", "bun test\n");
    chmodSync(join(r.dir, ".husky/pre-commit"), 0o644);
    expect(r.dede(["setup"]).code).toBe(0);
    expect(statSync(join(r.dir, ".husky/pre-commit")).mode & 0o777).toBe(0o644);
  });
});

describe("keys: -fk, dede keys, dede keys link", () => {
  const keyOf = (r: Repo, name: string) => new RegExp(`${name}=([0-9a-f]{64})`).exec(r.read(".env.keys"))![1];

  test("-fk uses another keys file for dec, and stores a new key there on enc", () => {
    const main = new Repo();
    main.write(".env.local", "A=1\n");
    main.dede(["enc"]);
    const wt = new Repo();
    wt.write(".env.local.enc", main.read(".env.local.enc"));
    expect(wt.dede(["dec"]).code).toBe(3);
    expect(wt.dede(["dec", "-fk", join(main.dir, ".env.keys")]).code).toBe(0);
    expect(wt.read(".env.local")).toBe("A=1\n");
    wt.write(".env.prod", "P=1\n");
    expect(wt.dede(["enc", ".env.prod", "--env-keys-file", join(main.dir, ".env.keys")]).code).toBe(0);
    expect(main.read(".env.keys")).toContain("DOTENV_PRIVATE_KEY_PROD=");
    expect(wt.exists(".env.keys")).toBe(false);
  });

  test("DOTENV_KEYS_FILE works like -fk", () => {
    const main = new Repo();
    main.write(".env.local", "A=1\n");
    main.dede(["enc"]);
    const wt = new Repo();
    wt.write(".env.local.enc", main.read(".env.local.enc"));
    expect(wt.dede(["dec"], { DOTENV_KEYS_FILE: join(main.dir, ".env.keys") }).code).toBe(0);
  });

  test("-fk without a path is a clean error", () => {
    const r = new Repo();
    const res = r.dede(["dec", "-fk"]);
    expect(res.code).toBe(4);
    expect(res.err).not.toContain("    at ");
  });

  test("keys link: a visible symlink, dec works, a new key lands in the target file", () => {
    const main = new Repo();
    main.write(".env.local", "A=1\n");
    main.dede(["enc"]);
    const wt = new Repo();
    wt.write(".env.local.enc", main.read(".env.local.enc"));
    const res = wt.dede(["keys", "link", join(main.dir, ".env.keys")]);
    expect(res.code).toBe(0);
    expect(lstatSync(join(wt.dir, ".env.keys")).isSymbolicLink()).toBe(true);
    expect(wt.dede(["dec"]).code).toBe(0);
    wt.write(".env.test", "T=1\n");
    expect(wt.dede(["enc", ".env.test"]).code).toBe(0);
    expect(lstatSync(join(wt.dir, ".env.keys")).isSymbolicLink()).toBe(true);
    expect(main.read(".env.keys")).toContain("DOTENV_PRIVATE_KEY_TEST=");
    expect(wt.dede(["keys", "link", join(main.dir, ".env.keys")]).code).toBe(0); // idempotent
  });

  test("keys link refuses to replace an existing .env.keys and a missing target", () => {
    const r = new Repo();
    r.write(".env.keys", "DOTENV_PRIVATE_KEY_X=" + "1".repeat(64) + "\n");
    const other = new Repo();
    other.write(".env.keys", "DOTENV_PRIVATE_KEY_Y=" + "2".repeat(64) + "\n");
    expect(r.dede(["keys", "link", join(other.dir, ".env.keys")]).code).toBe(1);
    expect(r.dede(["keys", "link", join(other.dir, "nope")]).code).toBe(4);
  });

  test("dede keys lists each .enc with its source and never prints a private key", () => {
    const r = new Repo();
    r.write(".env.local", "A=1\n");
    r.write(".env.prod", "B=1\n");
    r.dede(["enc"]);
    const priv = keyOf(r, "DOTENV_PRIVATE_KEY_LOCAL");
    let res = r.dede(["keys"]);
    expect(res.code).toBe(0);
    expect(res.out).toMatch(/✓ \.env\.local\.enc  0[23][0-9a-f]{8}…  \.env\.keys/);
    expect(res.out + res.err).not.toContain(priv);
    r.write(".env.keys", r.read(".env.keys").replace(/DOTENV_PRIVATE_KEY_PROD=.*\n/, ""));
    res = r.dede(["keys"], { DOTENV_PRIVATE_KEY_LOCAL: priv });
    expect(res.code).toBe(1);
    expect(res.out).toContain("✓ .env.local.enc");
    expect(res.out).toContain("environment");
    expect(res.out).toContain("✗ .env.prod.enc");
    expect(res.out).toContain("missing (DOTENV_PRIVATE_KEY_PROD)");
  });
});

describe("keys files backed up as .env.keys.<name>.enc with --key", () => {
  const ME = "a".repeat(63) + "1";
  const setup = () => {
    const vault = new Repo();
    vault.write(".env.keys", `DOTENV_PRIVATE_KEY_ME=${ME}\n`);
    const proj = new Repo();
    proj.write(".env.dev", "A=1\n");
    proj.dede(["enc"]);
    vault.write(".env.keys.proj", proj.read(".env.keys"));
    return { vault, proj };
  };

  test("encrypts with the chosen key, adds no new key, and restores exactly", () => {
    const { vault } = setup();
    const plain = vault.read(".env.keys.proj");
    const res = vault.dede(["enc", ".env.keys.proj", "--key", "ME"]);
    expect(res.code).toBe(0);
    expect(vault.read(".env.keys")).toBe(`DOTENV_PRIVATE_KEY_ME=${ME}\n`);
    const enc = vault.read(".env.keys.proj.enc");
    expect(enc).toMatch(/\nDOTENV_PRIVATE_KEY_DEV=encrypted:/);
    expect(enc).not.toMatch(/=[0-9a-f]{64}/);
    const mePub = /DOTENV_PUBLIC_KEY_KEYS_PROJ="(0[23][0-9a-f]{64})"/.exec(enc)![1];
    expect(mePub).toBe(require("@dotenvx/primitives").keypair(ME).publicKey);
    vault.rm(".env.keys.proj");
    expect(vault.dede(["dec", ".env.keys.proj"]).code).toBe(0);
    expect(vault.read(".env.keys.proj")).toBe(plain);
  });

  test("guard passes the .enc and blocks the plaintext keys file", () => {
    const { vault } = setup();
    vault.dede(["enc", ".env.keys.proj", "--key", "ME"]);
    vault.git("add", ".gitignore", ".env.keys.proj.enc");
    expect(vault.dede(["guard"]).code).toBe(0);
    vault.git("add", "-f", ".env.keys.proj");
    const res = vault.dede(["guard"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain(".env.keys.proj: new plaintext env file");
    expect(res.err).toContain(".env.keys.proj: contains a DOTENV_PRIVATE_KEY");
  });

  test("a project checkout linked to the restored keys file decrypts", () => {
    const { vault, proj } = setup();
    vault.dede(["enc", ".env.keys.proj", "--key", "ME"]);
    vault.rm(".env.keys.proj");
    vault.dede(["dec", ".env.keys.proj"]);
    const clone = new Repo();
    clone.write(".env.dev.enc", proj.read(".env.dev.enc"));
    expect(clone.dede(["keys", "link", join(vault.dir, ".env.keys.proj")]).code).toBe(0);
    expect(clone.dede(["dec"]).code).toBe(0);
    expect(clone.read(".env.dev")).toBe("A=1\n");
  });

  test("private keys are still refused in ordinary env files", () => {
    const r = new Repo();
    r.write(".env.local", `DOTENV_PRIVATE_KEY_X=${ME}\n`);
    expect(r.dede(["enc"]).code).toBe(4);
  });

  test("--key errors: unknown key, bad name, existing .enc with another key", () => {
    const { vault } = setup();
    expect(vault.dede(["enc", ".env.keys.proj", "--key", "NOPE"]).code).toBe(3);
    expect(vault.exists(".env.keys.proj.enc")).toBe(false);
    expect(vault.dede(["enc", ".env.keys.proj", "--key", "bad name"]).code).toBe(4);
    vault.dede(["enc", ".env.keys.proj"]); // encrypted with a new KEYS_PROJ key
    vault.write(".env.keys", vault.read(".env.keys") + `DOTENV_PRIVATE_KEY_ME=${ME}\n`);
    expect(vault.dede(["enc", ".env.keys.proj", "--key", "ME"]).code).toBe(4);
  });
});

test("guard reports line numbers of the .enc file itself (header included)", () => {
  const r = new Repo();
  r.write(".env.local", "A=1\n");
  r.dede(["enc"]);
  const enc = r.read(".env.local.enc") + "# OLD=" + "h".repeat(32) + "\n";
  r.write(".env.local.enc", enc);
  r.git("add", ".env.local.enc");
  const line = enc.split("\n").findIndex((l) => l.startsWith("# OLD=")) + 1;
  expect(r.dede(["guard"]).err).toContain(`.env.local.enc: line ${line} is a comment`);
});

describe("committed plaintext env files are public config", () => {
  const withPublic = () => {
    const r = new Repo(".env*\n!.env*.enc\n");
    r.write(".env.production", "VITE_API_BASE_URL=\n");
    r.git("add", "-f", ".gitignore", ".env.production");
    r.git("commit", "-qm", "public config");
    return r;
  };

  test("guard lets an edit to a tracked plaintext env file through, and --all passes", () => {
    const r = withPublic();
    r.write(".env.production", "VITE_API_BASE_URL=https://api.example.com\n");
    r.git("add", ".env.production");
    expect(r.dede(["guard"]).code).toBe(0);
    expect(r.dede(["guard", "--all"]).code).toBe(0);
  });

  test("guard still blocks a new plaintext env file, a rename into one, and keys in tracked ones", () => {
    const r = withPublic();
    r.write(".env.local", "SECRET=x\n");
    r.git("add", "-f", ".env.local");
    expect(r.dede(["guard"]).err).toContain(".env.local: new plaintext env file");
    r.git("rm", "-q", "--cached", ".env.local");
    r.git("mv", ".env.production", ".env.staging");
    expect(r.dede(["guard"]).err).toContain(".env.staging: new plaintext env file");
    r.git("mv", ".env.staging", ".env.production");
    r.write(".env.production", "DOTENV_PRIVATE_KEY_X=" + "e".repeat(64) + "\n");
    r.git("add", ".env.production");
    expect(r.dede(["guard"]).err).toContain(".env.production: contains a DOTENV_PRIVATE_KEY");
  });
});

describe("setup defaults to husky in a JS repo without a hook manager", () => {
  test("adds husky to package.json, writes .husky/pre-commit, asks for an install", () => {
    const r = new Repo("");
    r.write("package.json", JSON.stringify({ name: "x", scripts: { test: "bun test" } }, null, 2) + "\n");
    const res = r.dede(["setup"]);
    expect(res.code).toBe(0);
    expect(res.err).toContain("run `bun install`");
    const pkg = JSON.parse(r.read("package.json"));
    expect(pkg.scripts.prepare).toBe("husky");
    expect(pkg.scripts.test).toBe("bun test");
    expect(pkg.devDependencies.husky).toMatch(/^\^9/);
    expect(r.read(".husky/pre-commit")).toContain("dede guard");
    expect(r.exists(".git/hooks/pre-commit")).toBe(false);
    expect(r.dede(["setup"]).err).toContain("dede guard already installed"); // idempotent via .husky
  });

  test("keeps an existing prepare script and a 4-space package.json", () => {
    const r = new Repo("");
    r.write("package.json", JSON.stringify({ name: "x", scripts: { prepare: "echo hi" } }, null, 4) + "\n");
    r.dede(["setup"]);
    expect(r.read("package.json")).toContain('    "scripts"');
    expect(JSON.parse(r.read("package.json")).scripts.prepare).toBe("husky && echo hi");
  });

  test("a repo without package.json still gets a plain git hook", () => {
    const r = new Repo("");
    r.dede(["setup"]);
    expect(r.read(".git/hooks/pre-commit")).toContain("dede guard");
    expect(r.exists(".husky")).toBe(false);
  });
});

describe("unmanaged plaintext env files fail the pre-commit guard", () => {
  test("untracked .env.foo without .enc blocks the commit; .enc, *.local, committed and examples pass", () => {
    const r = new Repo();
    r.write("README.md", "x\n");
    r.git("add", "README.md", ".gitignore");
    r.write(".env.foo", "A=1\n");
    r.write("app/.env.bar", "B=1\n");
    r.write(".env.local", "C=1\n");
    r.write(".env.development.local", "D=1\n");
    r.write(".env.example", "E=\n");
    r.write("node_modules/pkg/.env", "F=1\n");
    let res = r.dede(["guard"]);
    expect(res.code).toBe(1);
    expect(res.err).toContain(".env.foo: unmanaged plaintext env file");
    expect(res.err).toContain("app/.env.bar: unmanaged plaintext env file");
    for (const ok of [".env.local", ".env.development.local", ".env.example", "node_modules"]) expect(res.err).not.toContain(ok + ":");
    expect(res.err).not.toContain("A=1");
    r.dede(["enc", ".env.foo", "app/.env.bar"]);
    res = r.dede(["guard"]);
    expect(res.code).toBe(0);
  });

  test("a committed plaintext env file is not unmanaged", () => {
    const r = new Repo();
    r.write(".env.production", "VITE_X=\n");
    r.git("add", "-f", ".gitignore", ".env.production");
    r.git("commit", "-qm", "public config");
    r.write("README.md", "x\n");
    r.git("add", "README.md");
    expect(r.dede(["guard"]).code).toBe(0);
  });

  test("status lists unmanaged files anywhere in the repo and exits 1", () => {
    const r = new Repo();
    r.write("app/.env.bar", "B=1\n");
    const res = r.dede(["status"]);
    expect(res.code).toBe(1);
    expect(res.out).toContain("✗ app/.env.bar: unmanaged plaintext env file");
  });

  test("the installed hook blocks a commit while an unmanaged env file exists", () => {
    const r = new Repo("");
    const bin = join(r.dir, "node_modules/.bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "dede"), `#!/bin/sh\nexec bun --no-env-file ${CLI} "$@"\n`);
    chmodSync(join(bin, "dede"), 0o755);
    r.write(".gitignore", "node_modules/\n");
    r.dede(["setup"]);
    r.write(".env.foo", "A=1\n");
    r.write("README.md", "x\n");
    r.git("add", "README.md", ".gitignore");
    const c = spawnSync("git", ["commit", "-qm", "x"], { cwd: r.dir, encoding: "utf8", env: cleanEnv() });
    expect(c.status).not.toBe(0);
    expect(c.stderr).toContain(".env.foo: unmanaged plaintext env file");
  });
});
