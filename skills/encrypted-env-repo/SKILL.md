---
name: encrypted-env-repo
description: Set up (or extend) a private git repo that stores credentials as dede/dotenvx-encrypted `.env*.enc` files — allowlist .gitignore, dotenvdotenc + husky `dede guard` pre-commit, one file and one key per domain, keys only in `.env.keys`, README table of files. Use when the owner wants a new encrypted secrets repo ("make a .env.enc repo"), or when adding a new secrets file or key to an existing one.
---

# Encrypted env repo (dede)

A private repo whose only secrets are dotenvx-encrypted `.env*.enc` files. Plaintext `.env*` and the
private keys stay on the owner's machines. `dede` (this package) keeps each plaintext file in sync
with its `.enc` twin, and its pre-commit guard blocks plaintext, keys and unencrypted values.

## Hard rules

- Never commit `.env.keys`, `.env.keys.*` plaintext, or any plaintext `.env*`. Only `*.enc`.
- Never print a secret value or a private key. Check files by **key names** (`dede diff`, `dede keys`).
- Never `--no-verify`. If `dede guard` blocks, fix what it names.
- Comments in `.env*` files are committed **in plaintext**. Notes that matter go in values.
- The repo stays private. Do not add collaborators unless the owner asks.

## 1. Create the repo

```sh
mkdir -p <dir> && cd <dir> && git init -b main
```

`.gitignore` is an **allowlist**: ignore everything, then list what may be committed. `!.env*.enc`
comes last, so no earlier rule can re-ignore an encrypted file.

```gitignore
# Plaintext secrets must NEVER land in this repo. Allowlist only.
*
!.gitignore
!README.md
!package.json
!bun.lock
!.husky/
!.husky/pre-commit
!.env*.enc
```

Each new committed path (a doc, a script, a directory) needs its own `!` line, and a directory needs
`!dir/` before `!dir/file`.

`package.json`. Pin dotenvdotenc to a commit (the guard runs this exact code):

```json
{
  "name": "env-enc-<owner>",
  "private": true,
  "scripts": { "prepare": "husky" },
  "devDependencies": {
    "dotenvdotenc": "github:snomiao/dotenvdotenc#<commit>",
    "husky": "9.1.7"
  }
}
```

`.husky/pre-commit` (falls back to a global `dede` when `node_modules` is missing):

```sh
#!/bin/sh
if [ -x node_modules/.bin/dede ]; then node_modules/.bin/dede guard; else dede guard; fi
```

```sh
chmod +x .husky/pre-commit
bun install          # installs dede, runs `husky` via prepare, so the hook is live
```

(`dede setup` writes `.env*` / `!.env*.enc` rules and a hook too. In an allowlist repo, write the
files above by hand instead.)

## 2. One file per domain, one key per file

Split by what would be shared or rotated together, e.g. `.env.payments.<site>`, `.env.aws`,
`.env.github`. dotenvx names the key after the file:

| plaintext | committed | private key (in `.env.keys`) |
|---|---|---|
| `.env.payments.stripe` | `.env.payments.stripe.enc` | `DOTENV_PRIVATE_KEY_PAYMENTS_STRIPE` |
| `.env.aws` | `.env.aws.enc` | `DOTENV_PRIVATE_KEY_AWS` |

Use lowercase letters and digits for `<site>`, no spaces.

A per-file key means one file can be handed to one machine or person without exposing the rest. If
the owner prefers one key to protect, encrypt new files with an existing key instead:
`dede enc .env.payments.stripe --key OWNER` (only for a new `.enc`).

## 3. Encrypt, decrypt, add a key

```sh
umask 077
$EDITOR .env.payments.<site>                # plaintext, gitignored, mode 0600
bunx dede enc .env.payments.<site>          # writes .env.payments.<site>.enc
                                            # first run: generates DOTENV_PRIVATE_KEY_PAYMENTS_<SITE>
                                            # and appends it to .env.keys (0600)
bunx dede status                            # every file "in sync"? exit 0
bunx dede keys                              # each .enc, the key it needs, where it was found
git add .env.payments.<site>.enc README.md && git commit -m "add <site> payments credentials"
```

- After editing an existing file: `bunx dede enc`, commit the `.enc`.
- After a pull or on a new machine: put the private key line(s) in `.env.keys`, then `bunx dede dec`.
- Read one value into a command without a plaintext file: `X=$(bunx dede get NAME .env.foo.enc) cmd`.
- `dede diff` lists which **keys** differ between plaintext and `.enc`, never values.

**A new key exists only in `.env.keys` on this machine.** Tell the owner to back it up (password
manager), naming the key, never its value. Without it the `.enc` cannot be decrypted. Optionally
back up keys inside the repo encrypted with a master key: `dede enc .env.keys.<name> --key OWNER`.

## 4. Push

```sh
gh repo create <owner>/<repo> --private --source . --remote origin
git push -u origin main
```

If the SSH push is denied (`Permission denied (publickey)`, or the key belongs to another account),
switch to HTTPS through gh's credential helper:

```sh
gh auth status                                   # the logged-in account must own/push to <owner>
gh auth setup-git
git remote set-url origin https://github.com/<owner>/<repo>.git
git push -u origin main
```

Confirm it is private: `gh repo view <owner>/<repo> --json visibility -q .visibility` → `PRIVATE`.

## 5. README table

Keep one row per committed file. Describe contents by **field names**, not values. Use no hostnames,
account ids or emails.

```markdown
| file | contents | key |
|---|---|---|
| `.env.payments.<site>.enc` | <site> account: login email, password, account id, API keys (test/live), webhook secret, 2FA recovery | `DOTENV_PRIVATE_KEY_PAYMENTS_<SITE>` |
```

Update the row in the same commit that adds or changes the file.
