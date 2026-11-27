#!/bin/sh
# Starts the command under test for one parity case:
#
#   sh rs/parity/run.sh <command> [args…]
#
# What a case cannot say in its JSON, it says through variables.
#
# PARITY_KEYS="_LOCAL=1 =2 _CI=1,3"
#   puts throwaway private keys into the environment: DOTENV_PRIVATE_KEY_LOCAL
#   is the digit 1 sixty-four times, DOTENV_PRIVATE_KEY the digit 2, and
#   DOTENV_PRIVATE_KEY_CI two such keys with a comma between them. The keys
#   are made here so that no private key stands in the cases file, where
#   `dede guard` (this project's own pre-commit hook) would rightly refuse it.
#
# PARITY_EXPAND="NAME …"
#   in each named variable, @0@ … @9@ become that digit sixty-four times and
#   @N@ the order of secp256k1 (a key that is none): a key with something
#   before or after it, kept out of the cases file for the same reason.
#
# PARITY_GIT_LOG=<file>
#   puts rs/parity/bin/git in front of git: every `git` the command starts is
#   noted in <file> with its arguments and directory, then run. The case
#   compares the file, so both implementations must ask git the same things in
#   the same order. PARITY_GIT_ENV names variables to note as well.
#
# And where the command starts:
#   X_CD=<dir>      in this directory (relative to the case's)
#   X_UMASK=<mask>  with this umask
#   X_GONE=1        in a directory that has been removed (after X_CD)
#   X_NOGIT=1       with a PATH that holds bun, node, env and sh and no git
#
#   sh rs/parity/run.sh --expand <file>…
#
# rewrites files of a case the way PARITY_EXPAND rewrites variables (a keys
# file whose key has something around it), for a `setup` line.
set -eu
key() {
  if [ "$1" = N ]; then
    printf fffffffffffffffffffffffffffffffe
    printf baaedce6af48a03bbfd25e8cd0364141
  else
    printf '%064d' 0 | tr 0 "$1"
  fi
}
# expand <text>: sets $expanded to <text> with every @d@ replaced.
expand() {
  rest=$1
  expanded=
  while :; do
    case $rest in
      *@[0-9N]@*)
        before=${rest%%@[0-9N]@*}
        rest=${rest#"$before"@}
        digit=${rest%%@*}
        rest=${rest#?@}
        expanded=$expanded$before$(key "$digit")
        ;;
      *)
        expanded=$expanded$rest
        return
        ;;
    esac
  done
}
if [ "${1-}" = --expand ]; then
  shift
  for file in "$@"; do
    expand "$(cat "$file"; printf .)"
    printf '%s' "${expanded%.}" > "$file"
  done
  exit 0
fi
for spec in ${PARITY_KEYS-}; do
  value=
  for digit in $(printf '%s' "${spec#*=}" | tr , ' '); do
    value="${value:+$value,}$(key "$digit")"
  done
  export "DOTENV_PRIVATE_KEY${spec%%=*}=$value"
done
for name in ${PARITY_EXPAND-}; do
  eval "expand \"\${$name}\""
  export "$name=$expanded"
done
unset PARITY_KEYS PARITY_EXPAND
if [ -n "${X_CD-}" ]; then cd "$X_CD"; fi
if [ -n "${X_UMASK-}" ]; then umask "$X_UMASK"; fi
if [ -n "${X_GONE-}" ]; then rmdir "$PWD"; fi
if [ -n "${X_NOGIT-}" ]; then
  dir="${TMPDIR:-/tmp}/x-nogit-bin"
  mkdir -p "$dir"
  for tool in bun node env sh; do ln -sf "$(command -v "$tool")" "$dir/$tool"; done
  unset X_CD X_UMASK X_NOGIT X_GONE PARITY_GIT_LOG
  PATH=$dir
  export PATH
  exec "$@"
fi
unset X_CD X_UMASK X_NOGIT X_GONE
if [ -n "${PARITY_GIT_LOG-}" ]; then
  PARITY_REAL_GIT=$(command -v git)
  PATH="$(dirname "$0")/bin:$PATH"
  export PARITY_REAL_GIT PATH
fi
exec "$@"
