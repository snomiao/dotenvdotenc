---
name: agent-signup-via-browser
description: Sign up for a third-party service on the owner's behalf by driving their real Chrome with rechrome (`rech --profile <email> …`), generating a strong password, reading the verification email in the owner's Gmail tab, saving every credential to dede at once, and handing over to the human for identity/KYC, CAPTCHAs and legally binding attestations. Use when the owner asks the agent to "create an account on X", "sign up for X", or "get API keys from X".
---

# Agent signup via browser (rechrome)

You drive the owner's real, logged-in Chrome through `rech` (rechrome). The owner sees the same
window and can take over at any point.

## Hard rules: stop and hand over

Stop, leave the page as it is, and tell the owner exactly what is waiting when the next step is any of these:

- **Identity and KYC.** Legal name, home address, date of birth, phone ownership checks, ID documents
  or selfies, tax ids, **bank account / payout details**. Never fill these in from memory or guess.
- **CAPTCHAs** and "verify you are human" challenges. Do not try to solve or bypass them.
- **Legally binding attestations.** Accepting terms of service, declaring the business type or
  what you sell, sanctions or tax declarations, signing contracts. Do these only when the owner has
  explicitly approved this specific step in this session. A general "sign me up" is not approval.
- Payment of money, plan upgrades, or anything irreversible (deleting, closing accounts).

Hand-over message: one line naming the page and the fields still open, e.g. "Stripe signup is
waiting on the business-details page (legal name, address, DOB, bank); I've filled email and
password. Tell me when it's done and I'll continue with API keys."

Also:

- Never print a password, API key, TOTP secret or code, recovery code or session token. Screenshots
  of key and recovery pages stay local and are never posted.
- `rech snapshot` prints form-field **values**. Redact it before reading:
  `redact() { sed -E 's/(textbox[^:]*:).*/\1 <value hidden>/'; }`.
- Never submit browser-autofilled credentials. Clear the field and fill it with the generated value.

## Steps

```sh
P="--profile <owner-email>"     # the Chrome profile to act as
rech status                     # daemon reachable, right profile
```

1. **Open the signup page in a new tab** (leave the owner's tabs alone):
   ```sh
   rech $P tab-new
   rech $P goto "https://<service>/signup"
   rech $P screenshot              # look before acting; saved under .rechrome/output/
   rech $P snapshot | redact | grep -E 'textbox|button|checkbox'
   ```
2. **Generate the password** and save it **before** submitting, so a crash cannot lose it:
   ```sh
   pw=$(openssl rand -base64 24)                        # 32 chars
   # if the site forbids symbols: pw=$(openssl rand -hex 20)
   printf 'SITE_PASSWORD="%s"\n' "$pw" >> <env-repo>/.env.<site>
   rech $P fill <email-ref> "<owner-email>"
   rech $P fill <password-ref> "$pw"; unset pw
   ```
   Then follow the `save-account-credentials` skill for every field from here on.
3. **Submit** (only if no attestation checkbox needs approval, see the hard rules):
   `rech $P click <submit-ref>`, then screenshot.
4. **Verification email.** Read it in the owner's own Gmail in the same profile:
   ```sh
   rech $P tab-new
   rech $P goto "https://mail.google.com/mail/u/0/#search/from%3A<service-domain>+newer_than%3A1h"
   rech $P snapshot | grep -iE 'verify|confirm|code'
   ```
   Open the message and click the verification link, or read the one-time code and fill it on the
   signup tab. Do not forward, archive or delete the owner's mail. If no mail arrives, check spam
   (`in:spam`) once, then tell the owner.
5. **2FA.** If the service offers authenticator 2FA, choose "can't scan / enter key manually".
   Save the setup key as `<SITE>_TOTP_SECRET` and generate the confirmation code from it locally
   (RFC 6238, SHA1, 6 digits, 30 s). Save recovery codes as `<SITE>_RECOVERY_CODES` before clicking
   "I saved them". SMS 2FA ties the account to the owner's phone, so hand over.
6. **API keys and webhooks.** Create test keys, and a webhook endpoint if the integration needs one.
   Save each secret immediately (copy button, then `pbpaste` into the env file). Live keys usually
   need KYC, so record that in `<SITE>_STATUS`.
7. **Encrypt and commit** (`dede enc`, `dede status`, commit, push) as in `save-account-credentials`.

## Reporting progress

Report steps and **variable names**, never values:

> Signed up for Paddle (sandbox). Email verified. Saved PADDLE_LOGIN_EMAIL, PADDLE_PASSWORD,
> PADDLE_ACCOUNT_ID, PADDLE_TEST_SECRET_KEY, PADDLE_WEBHOOK_SECRET, PADDLE_SIGNUP_DATE,
> PADDLE_STATUS to `.env.payments.paddle.enc`. Waiting on you: business verification (legal name,
> address, bank). Live keys come after that.

When the owner finishes a hand-over step, take a screenshot to confirm the state, update `<SITE>_STATUS`,
and continue.
