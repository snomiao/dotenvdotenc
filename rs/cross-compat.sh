#!/bin/sh
# Both implementations of dede taking turns on the same files: what one
# writes (.enc files, keys, the sync record) the other has to read, in both
# directions, and dotenvx itself has to read what the Rust binary encrypts.
# The parity cases compare the two on equal inputs; this is what a single
# case cannot show.
#
#   sh rs/cross-compat.sh [path/to/the/binary]     (after `bun install`)
#
# Everything happens in a temp directory with its own HOME; the keys are made
# on the spot and thrown away with it. The binary is given no package to hand
# back to, so a step it does not answer itself fails here.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=${1:-$REPO/rs/target/release/dotenvdotenc}
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 2; }
DOTENVX=$REPO/node_modules/.bin/dotenvx

WORK=$(mktemp -d "${TMPDIR:-/tmp}/dede-cross-XXXXXX")
trap 'rm -rf "$WORK"' EXIT
for name in $(env | sed -n 's/^\(DOTENV_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$name"; done
unset NODE_ENV BUN_ENV BUN_OPTIONS NODE_OPTIONS NO_COLOR FORCE_COLOR DOTENVDOTENC_NO_NATIVE
export HOME="$WORK/home" XDG_CONFIG_HOME="$WORK/home/.config" XDG_CACHE_HOME="$WORK/cache" GIT_CONFIG_NOSYSTEM=1 TZ=UTC
mkdir -p "$HOME"
git config --global user.name Cross && git config --global user.email cross@example.com

ts() { bun "$REPO/dede.ts" "$@"; }
rs() { DOTENVDOTENC_PACKAGE_ROOT="$WORK/no-package-here" "$BIN" "$@"; }

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
fail() { echo "FAILED after $n checks: $1" >&2; exit 1; }
same() { [ "$1" = "$2" ] || fail "$3: got '$1', expected '$2'"; }
# edit <sed script> <file>: in place, keeping the file and its mode (GNU and
# BSD sed spell -i differently).
edit() { sed "$1" "$2" > "$WORK/edited" && cat "$WORK/edited" > "$2" && rm "$WORK/edited"; }
# A repository with dede's ignore rules; the name is the directory under $WORK.
repo() {
  mkdir -p "$WORK/$1" && cd "$WORK/$1"
  git init -q -b main
  printf '.env*\n!.env*.enc\n' > .gitignore
}
# A second checkout: the .enc files and the keys of another, nothing else.
checkout() {
  repo "$2"
  cp "$WORK/$1"/.env*.enc "$WORK/$1/.env.keys" .
}

PLAIN='# api
API_KEY=dummy-1
export NAME="hello world" # a note
MULTI="line one
line two"
RAW='"'"'$HOME and $(id)'"'"'
EMPTY=
'

# ── one writes, the other reads ───────────────────────────────────────────
for pair in "ts rs" "rs ts"; do
  writer=${pair% *}
  reader=${pair#* }
  repo "write-$writer"
  printf '%s' "$PLAIN" > .env.prod
  $writer enc 2> /dev/null
  [ -s .env.prod.enc ] && [ -s .env.keys ] || fail "$writer enc wrote no .enc or no key"
  same "$($reader status 2>&1)" "✓ .env.prod: in sync" "$reader status of what $writer encrypted"
  same "$($reader get API_KEY)" "dummy-1" "$reader get API_KEY from $writer's .enc"
  same "$($reader get MULTI)" "line one
line two" "$reader get of a value over two lines"
  same "$($reader get RAW)" '$HOME and $(id)' "$reader get of a raw value"
  same "$($reader diff 2>&1)" "✓ .env.prod: no differences" "$reader diff"
  ok "$reader reads what $writer encrypted: status, get, diff"

  checkout "write-$writer" "read-$reader-from-$writer"
  $reader dec 2> /dev/null
  cmp -s .env.prod "$WORK/write-$writer/.env.prod" || fail "$reader dec of $writer's .enc is not the plaintext"
  same "$(node "$REPO/rs/parity/files.mjs" stat %a .env.prod)" "600" "mode of the plaintext $reader wrote"
  same "$($writer status 2>&1)" "✓ .env.prod: in sync" "$writer status in $reader's checkout (the record $reader wrote)"
  ok "$reader decrypts $writer's .enc to the same bytes, and $writer agrees with the record $reader wrote"

  # The record the writer left is the reader's baseline for "what changed".
  cd "$WORK/write-$writer"
  edit 's/dummy-1/dummy-2/' .env.prod
  same "$($reader status 2>&1 || true)" '✗ .env.prod: edited (API_KEY) (run `dede enc`)' "$reader status after an edit, against $writer's record"
  cp .env.prod.enc before.enc
  $reader enc 2> /dev/null
  same "$(diff before.enc .env.prod.enc | grep -c '^[<>]')" "2" "lines of the .enc that $reader changed for one edited value"
  same "$($writer get API_KEY)" "dummy-2" "$writer get after $reader re-encrypted"
  same "$($writer status 2>&1)" "✓ .env.prod: in sync" "$writer status after $reader re-encrypted"
  rm before.enc
  ok "after an edit $reader re-encrypts that one line of $writer's .enc, and $writer reads it"
done

# ── dotenvx itself ────────────────────────────────────────────────────────
if [ -x "$DOTENVX" ]; then
  repo dotenvx-reads
  printf 'HELLO="dummy world"\nOTHER=x\n' > .env.local
  rs enc 2> /dev/null
  rm .env.local
  printf 'printf %%s "$HELLO"\n' > print.sh
  same "$("$DOTENVX" run -q -f .env.local.enc -- sh print.sh)" "dummy world" "dotenvx run on an .enc the Rust binary wrote"
  ok "dotenvx reads an .enc the Rust binary encrypted, with the key it made"

  repo dotenvx-writes
  printf 'HELLO="dummy world"\nOTHER=x\n' > .env.staging
  "$DOTENVX" encrypt -q -f .env.staging > /dev/null 2>&1 || "$DOTENVX" encrypt -f .env.staging > /dev/null
  mv .env.staging .env.staging.enc
  same "$(rs get HELLO)" "$(ts get HELLO)" "get from a file dotenvx encrypted, Rust against TypeScript"
  same "$(rs get HELLO)" "dummy world" "get from a file dotenvx encrypted"
  ok "the Rust binary reads a file dotenvx encrypted, with the key dotenvx made"
else
  echo "skipped: no dotenvx in node_modules (run bun install)"
fi

# ── two checkouts, one per implementation, merging each other's edits ─────
for pair in "ts rs" "rs ts"; do
  a=${pair% *}
  b=${pair#* }
  repo "merge-$a"
  printf 'ONE=1\nTWO=2\nTHREE=3\n' > .env.prod
  $a enc 2> /dev/null
  checkout "merge-$a" "merge-$a-peer-$b"
  $b dec 2> /dev/null
  # The peer changes TWO and publishes; the first changes ONE meanwhile.
  edit 's/TWO=2/TWO=two/' .env.prod && $b enc 2> /dev/null
  cd "$WORK/merge-$a"
  edit 's/ONE=1/ONE=one/' .env.prod
  cp "$WORK/merge-$a-peer-$b/.env.prod.enc" .
  same "$($a status 2>&1 || true)" '✗ .env.prod: both changed, mergeable (run `dede enc`)' "$a status with its own edit and $b's .enc"
  same "$($a dec 2>&1)" '.env.prod: merged: from .enc (TWO), kept your edits (ONE); run `dede enc` to publish your edits' "$a dec merging $b's change"
  same "$(cat .env.prod)" "ONE=one
TWO=two
THREE=3" "the merged plaintext"
  $a enc 2> /dev/null
  cp .env.prod.enc "$WORK/merge-$a-peer-$b/"
  cd "$WORK/merge-$a-peer-$b"
  same "$($b dec 2>&1)" "decrypted .env.prod.enc → .env.prod" "$b dec of the merged .enc"
  cmp -s .env.prod "$WORK/merge-$a/.env.prod" || fail "the two checkouts differ after merging"
  ok "$a merges an edit $b published into its own, and $b takes the result"

  # The same key on both sides: each refuses in the same words.
  edit 's/THREE=3/THREE=b/' .env.prod && $b enc 2> /dev/null
  cd "$WORK/merge-$a"
  edit 's/THREE=3/THREE=a/' .env.prod
  cp "$WORK/merge-$a-peer-$b/.env.prod.enc" .
  refusal='dede: .env.prod: both sides changed THREE since the last sync; edit .env.prod to the value you want, then `dede enc --force`'
  same "$($a dec 2>&1 || true)" "$refusal" "$a dec on a conflict"
  same "$($b dec 2>&1 || true)" "$refusal" "$b dec on the same files and record"
  same "$(cat .env.prod | tail -1)" "THREE=a" "the plaintext after a refused merge"
  ok "a conflict is refused by both in the same words, the files untouched"
done

# ── the key tree, made by one and climbed by the other ────────────────────
for pair in "ts rs" "rs ts"; do
  maker=${pair% *}
  user=${pair#* }
  repo "tree-$maker"
  printf 'SECRET=in-production\n' > .env.production
  $maker enc 2> /dev/null
  # Keep the production key in a team keys file, encrypted with a root key.
  grep '^DOTENV_PRIVATE_KEY_PRODUCTION=' .env.keys > .env.keys.team
  printf 'ROOT=1\n' > .env.root && $maker enc .env.root 2> /dev/null && rm .env.root .env.root.enc
  grep '^DOTENV_PRIVATE_KEY_ROOT=' .env.keys > root.only && mv root.only .env.keys
  $maker enc .env.keys.team --key ROOT 2> /dev/null
  rm .env.keys.team .env.production
  same "$($user get SECRET)" "in-production" "$user get through the key tree $maker made"
  $user keys | grep -q '\.env\.keys\.team\.enc ← \.env\.keys$' || fail "$user keys does not show the path through $maker's tree: $($user keys)"
  $user dec .env.production 2> /dev/null
  same "$(cat .env.production)" "SECRET=in-production" "$user dec through the key tree"
  ok "$user opens the key tree $maker made (enc --key), and decrypts through it"
done

echo "all $n checks passed"
