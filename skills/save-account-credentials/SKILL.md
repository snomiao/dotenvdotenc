---
name: save-account-credentials
description: Record every credential field of a newly created third-party account (login, password, account id, API keys, webhook secret, 2FA secret and recovery codes, dashboard URL, signup date, status) into a dede-encrypted env file, named `<SITE>_<FIELD>`, without ever printing a value. Use right after signing up for a service, generating an API key or enabling 2FA, or whenever a secret is shown once and must not be lost.
---

# Save account credentials (dede)

Secrets shown once (API keys, recovery codes, TOTP setup keys) are lost if the session ends before
they are saved. Save each one **the moment it appears**, not at the end of the signup.

Storage: the owner's encrypted env repo (see the `encrypted-env-repo` skill), one file per domain,
e.g. `.env.payments.<site>` for a payment provider, `.env.<site>` otherwise.

## Hard rules

- Never print a secret value to the terminal, logs, chat, Slack, a PR or a commit message. No
  `cat`, `echo $VAR`, `dede get` to stdout, or screenshots of key pages in shared channels.
- Write values with a heredoc or a pipe straight into the file. Do not put them in command
  arguments that land in shell history or process lists.
- Values, not comments: comments in `.env*` are committed **in plaintext**.
- Verify by **key names** only.

## Fields

Record every field the service has, and leave out the ones it lacks. Do not invent placeholders for secrets.

| variable | what |
|---|---|
| `<SITE>_LOGIN_EMAIL` | email used to sign up |
| `<SITE>_PASSWORD` | generated password (`openssl rand -base64 24`) |
| `<SITE>_ACCOUNT_ID` | account / merchant / organization id |
| `<SITE>_TEST_PUBLISHABLE_KEY` / `<SITE>_TEST_SECRET_KEY` | test-mode API keys |
| `<SITE>_LIVE_PUBLISHABLE_KEY` / `<SITE>_LIVE_SECRET_KEY` | live-mode API keys (often only after review) |
| `<SITE>_WEBHOOK_SECRET` | webhook signing secret (one per endpoint; suffix `_TEST`/`_LIVE` if both) |
| `<SITE>_TOTP_SECRET` | 2FA authenticator setup key (base32), so an agent can produce codes |
| `<SITE>_RECOVERY_CODES` | 2FA backup codes, space-separated, quoted |
| `<SITE>_DASHBOARD_URL` | dashboard / login URL |
| `<SITE>_SIGNUP_DATE` | ISO date, `2026-10-30` |
| `<SITE>_STATUS` | free-text state, e.g. `"KYC pending; live keys not issued"` |

Naming: `<SITE>_<FIELD>`, uppercase, `[A-Z0-9_]`. `<SITE>` is the service in one word
(`STRIPE`, `PADDLE`, `KOMOJU`). If the owner has two accounts on one service, add a qualifier:
`STRIPE_JP_…`.

## Steps

```sh
cd <encrypted-env-repo>
umask 077
F=.env.payments.<site>          # or .env.<site>
```

1. **Append each field as it appears.** The quoted heredoc stops the shell from expanding anything.
   Use the clipboard or a variable the value was generated into, and print nothing:
   ```sh
   cat >> "$F" <<'EOF'
   SITE_LOGIN_EMAIL=...
   SITE_SIGNUP_DATE=2026-10-30
   SITE_STATUS="signed up; email verified; KYC pending"
   EOF
   # a generated password: generate, save and fill without echoing
   pw=$(openssl rand -base64 24); printf 'SITE_PASSWORD="%s"\n' "$pw" >> "$F"
   # a value on the macOS clipboard (copied from the dashboard's "copy" button)
   printf 'SITE_TEST_SECRET_KEY="%s"\n' "$(pbpaste)" >> "$F"
   ```
   Quote any value with spaces, `#`, `$` or quotes. Keep the last assignment of a name when you
   update it, or edit the line in place.
2. **Encrypt and commit.**
   ```sh
   bunx dede enc "$F"
   bunx dede status "$F"         # must report in sync
   git add "$F.enc" README.md && git commit -m "add <site> credentials"
   git push
   ```
   If `.env.keys` got a new `DOTENV_PRIVATE_KEY_…`, tell the owner to back it up, naming the key only.
3. **Verify by names.**
   ```sh
   grep -oE '^[A-Z0-9_]+=' "$F" | tr -d '='          # names in the plaintext
   bunx dede diff "$F"                               # names that differ from the .enc (none expected)
   ```
   Compare the names with the field list. Report it like this: "saved STRIPE_LOGIN_EMAIL,
   STRIPE_PASSWORD, STRIPE_TEST_SECRET_KEY … to `.env.payments.stripe.enc`; missing:
   STRIPE_LIVE_SECRET_KEY (not issued until review)".
4. **Update `<SITE>_STATUS`** whenever the account state changes (KYC approved, live keys issued,
   account refused), and re-run step 2.

## Using a saved value

Pipe it straight into the command that needs it:

```sh
STRIPE_SECRET_KEY=$(bunx dede get STRIPE_TEST_SECRET_KEY .env.payments.stripe.enc) some-command
```
