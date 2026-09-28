# dotenvdotenc — `dede`

**dotenvx underneath, plus a dead-simple script for the two-file workflow.**

[dotenvx](https://dotenvx.com) encrypts a `.env` file in place, so the file you edit and the file you
commit are the same file. `dede` keeps them apart:

```
.env.local        plaintext, gitignored — you and your framework use this
.env.local.enc    dotenvx-encrypted twin — the only thing committed
.env.keys         private keys, gitignored (dotenvx convention)
```

```sh
dede enc          # .env* → .env*.enc   (after you edit)
dede dec          # .env*.enc → .env*   (after you pull)
```

Everything cryptographic and every parse/rewrite is [`@dotenvx/primitives`](https://www.npmjs.com/package/@dotenvx/primitives)
(dotenvx's own core). `.enc` files are ordinary dotenvx files, so `dotenvx run -f .env.local.enc -- …`
works too. dede adds only what dotenvx lacks for two files: keep them in sync, refuse to clobber.

## Install

```sh
bun add -d github:snomiao/dotenvdotenc#<commit>   # per repo (hooks use this)
bun add -g github:snomiao/dotenvdotenc            # optional: `dede` on your PATH
dede setup                                        # .gitignore rules + pre-commit hook
```

Requires Bun. Without a global install, use `bunx dede …` or `node_modules/.bin/dede …`.

## Commands

```
dede enc [--force] [file|glob…]   plaintext → .enc   (default: every .env* in this directory)
dede dec [--force] [file|glob…]   .enc → plaintext   (default: every .env*.enc in this directory)
dede status [file|glob…]          one line per file; exit 1 unless everything is in sync
dede guard [--all]                pre-commit check (installed by setup)
dede setup                        add `.env*` / `!.env*.enc` to .gitignore, install the hook
```

Files can be named either way — `.env.local` or `.env.local.enc` — and globs work quoted or
shell-expanded: `dede enc '.env.*'`, `dede dec .env*`. `.env.keys`, `.env.example`, `.env.sample`,
`.env.template`, `.env.vault`, `.env.me` and `.envrc` are never paired.

## How sync decides

dede compares the **content** of both files (after decrypting). Equal → nothing is written, so an
unchanged value keeps its exact ciphertext and a one-value edit is a one-line diff.

When they differ, dede checks which side changed since the last `enc`/`dec` in this worktree
(hashes only, in `.git/dotenvdotenc/state.json`):

| Changed since last sync | `dede enc` | `dede dec` |
|---|---|---|
| plaintext only | writes `.enc` | refuses: run `dede enc` |
| `.enc` only (you pulled) | refuses: run `dede dec` | writes plaintext |
| both | refuses (conflict) | refuses (conflict) |
| unknown (no record yet) | refuses | refuses |

`--force` overrides a refusal and takes that command's source side. Nothing is ever merged
automatically. A missing file on the target side is simply created.

## Keys

dotenvx's convention, nothing new:

- `.env.local` ↔ `DOTENV_PUBLIC_KEY_LOCAL` (header of `.env.local.enc`) and `DOTENV_PRIVATE_KEY_LOCAL`
  (`.env` → no suffix, `.env.development.local` → `_DEVELOPMENT_LOCAL`).
- The private key is read from the environment, else from `.env.keys` next to the file. The key
  that matches the `.enc` header is used.
- The first `dede enc` of a file reuses an existing key by that name, or generates one and appends it
  to `.env.keys` (mode 0600). **Back it up in the password manager** — it is the only copy, and
  teammates need it to run `dede dec`.

## Guard (pre-commit)

`dede guard` blocks a commit that stages:

- a plaintext env file (`.env`, `.env.local`, …) — commit its `.enc` instead;
- `.env.keys`, or any file containing a `DOTENV_PRIVATE_KEY…=<64 hex>` assignment;
- an `.enc` file with a value that is not `encrypted:` or a line that is neither assignment nor comment.

`dede guard --all` checks every tracked file (use it in CI). The guard is a local safety net; a
plaintext secret that reaches a remote must be rotated.

## Things to know

- **Comments are committed in plaintext** (inline `# …` too). Don't put secrets in comments.
- Values are taken literally as dotenvx parses them (quotes, `\n` in double quotes). dede never
  expands `$VAR` or runs `$(…)`; your loader (dotenvx, Next.js, Bun) may when it reads the plaintext.
- Formatting survives: quote style, `export`, inline comments, duplicates, multiline values.
  A line that is neither an assignment nor a comment is refused, because it would be committed as-is.
- dede refuses a plaintext file that is not gitignored or is tracked, and warns when an `.enc` is gitignored.
- Exit codes: 0 ok · 1 action needed / blocked · 2 conflict · 3 no key or cannot decrypt · 4 malformed input.

## Develop

```sh
bun install
bun run test        # real CLI against temporary git repos, dummy keys only
bun run typecheck
```

## License

MIT
