#!/bin/sh
# Starts the command under test for one parity case:
#
#   sh rs/parity/run.sh <command> [args…]
#
# What a case cannot say in its JSON, it says through two variables.
#
# PARITY_KEYS="_LOCAL=1 =2 _CI=1,3"
#   puts throwaway private keys into the environment: DOTENV_PRIVATE_KEY_LOCAL
#   is the digit 1 sixty-four times, DOTENV_PRIVATE_KEY the digit 2, and
#   DOTENV_PRIVATE_KEY_CI two such keys with a comma between them. The keys
#   are made here so that no private key stands in the cases file, where
#   `dede guard` (this project's own pre-commit hook) would rightly refuse it.
#
# PARITY_GIT_LOG=<file>
#   puts rs/parity/bin/git in front of git: every `git` the command starts is
#   noted in <file> with its arguments and directory, then run. The case
#   compares the file, so both implementations must ask git the same things in
#   the same order. PARITY_GIT_ENV names variables to note as well.
set -eu
key() { printf '%064d' 0 | tr 0 "$1"; }
for spec in ${PARITY_KEYS-}; do
  value=
  for digit in $(printf '%s' "${spec#*=}" | tr , ' '); do
    value="${value:+$value,}$(key "$digit")"
  done
  export "DOTENV_PRIVATE_KEY${spec%%=*}=$value"
done
unset PARITY_KEYS
if [ -n "${PARITY_GIT_LOG-}" ]; then
  PARITY_REAL_GIT=$(command -v git)
  PATH="$(dirname "$0")/bin:$PATH"
  export PARITY_REAL_GIT PATH
fi
exec "$@"
