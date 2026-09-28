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
                                  (husky in a JS repo without a hook manager; lefthook/husky/plain git otherwise)
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
- The private key is read from the environment, else from `.env.keys` next to the file — nowhere
  else. The key that matches the `.enc` header is used, whatever its name.
- `-fk <path>` / `--env-keys-file <path>` (or `DOTENV_KEYS_FILE`) points one run at another keys file.
- `dede keys` lists every `.enc` here with the public key it needs and where that key was found
  (environment, `.env.keys`, or missing). It never prints a private key.
- The first `dede enc` of a file reuses an existing key by that name, or generates one and appends it
  to `.env.keys` (mode 0600). **Back it up in the password manager** — it is the only copy, and
  teammates need it to run `dede dec`.

### Several checkouts of one repo (worktrees, submodules)

Keep one real `.env.keys` and link the others to it, visibly:

```sh
cd ../feature-worktree
dede keys link ../main/.env.keys     # ./.env.keys -> ../main/.env.keys (a plain symlink)
dede dec
```

dotenvx follows the link too. New keys created from a linked checkout are written to the target file.

Submodules are separate checkouts, so link each one (from the superproject):

```sh
git submodule foreach 'dede keys link /path/to/.env.keys || true'
```

### Backing up keys files

Keys files are `.env.keys` or `.env.keys.<name>`. They may hold `DOTENV_PRIVATE_KEY_*`; any other env
file may not. So a keys file can itself be synced like any env file, encrypted with a key you
choose:

```sh
# in a private repo that holds your personal key ME in ./.env.keys
cp ~/src/myproj/.env.keys .env.keys.myproj
dede enc .env.keys.myproj --key ME       # commits as .env.keys.myproj.enc, encrypted with ME
cd ~/src/myproj && rm .env.keys && dede keys link ~/vault/.env.keys.myproj
```

On a new machine: restore `ME` from the password manager into the vault repo's `.env.keys`, run
`dede dec`, then `dede keys link` from each project. `ME` becomes the one key to protect.

## Guard (pre-commit)

`dede guard` blocks a commit that stages:

- a new plaintext env file (`.env`, `.env.local`, …) — commit its `.enc` instead (already-tracked
  plaintext env files are treated as public config and pass);
- `.env.keys`, or any file containing a `DOTENV_PRIVATE_KEY…=<64 hex>` assignment;
- while any `.env*` file in the repo is **unmanaged**: not committed, no `.enc` twin, and not named
  `*.local` (machine-local by convention). Encrypt it with `dede enc`, or rename it to `*.local`.
  `dede status` lists these files too;
- an `.enc` file with a value that is not `encrypted:` or a line that is neither assignment nor comment.

`dede guard --all` checks every tracked file (use it in CI). The guard is a local safety net; a
plaintext secret that reaches a remote must be rotated.

## Things to know

- **Comments are committed in plaintext** (inline `# …` too). dede refuses comments that look like
  credentials — a commented-out assignment with a long value (`# OLD_TOKEN=…`) or a URL with
  userinfo (`https://user:pw@…`) — but it cannot recognise everything, so keep secrets out of comments.
- Values are taken literally as dotenvx parses them (quotes, `\n` in double quotes). dede never
  expands `$VAR` or runs `$(…)`; your loader (dotenvx, Next.js, Bun) may when it reads the plaintext.
- Formatting survives: quote style, `export`, inline comments, duplicates, multiline values.
  A line that is neither an assignment nor a comment is refused, because it would be committed as-is.
- **A plaintext env file that is already committed is public config on purpose** (e.g. Vite's
  `.env.production` with `VITE_*` values that ship in the bundle anyway): `enc`/`dec` skip it, and
  the guard lets edits to it through. Only *new* plaintext env files are blocked; a new public one
  can be committed with `--no-verify`. If a committed file does hold secrets, `git rm --cached` it
  and rotate them.
- dede refuses a plaintext file that is not gitignored, and warns when an `.enc` is gitignored.
- Plaintext files are kept at mode 0600 (`enc` tightens a group/world-readable one). Symlinked
  plaintext files (e.g. `.env.local -> .env.dev`) are skipped in default and glob runs and refused when named.
- Windows: CRLF from `core.autocrlf` or an editor is not drift; dede compares and writes LF. File modes
  do not apply (access is by ACL), and `dede keys link` needs Developer Mode for symlinks (or use `-fk`).
- Exit codes: 0 ok · 1 action needed / blocked · 2 conflict · 3 no key or cannot decrypt · 4 malformed input.

## Develop

```sh
bun install
bun run test        # real CLI against temporary git repos, dummy keys only
bun run typecheck
```

## License

MIT
