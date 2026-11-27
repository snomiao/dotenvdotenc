#!/bin/sh
# Every proof that the binary behaves like dede.ts, in one go, on Linux,
# macOS or Windows (in Git Bash there):
#
#   sh rs/parity/proof.sh <rustify's templates/parity/parity.mjs> <the dotenvdotenc binary>
#
# from the repository root, after `bun install`. The CI workflow's parity job
# runs this on each platform of `parity-platforms`, against the binary it has
# just built for that platform ($RUSTIFY_PLATFORM names it; without it,
# `uname` does).
#
# First rs/parity.json is checked to be what rs/parity.gen.mjs writes, and
# rs/src/testdata what rs/vectors.gen.mjs records from this bun. Then these
# run side by side, each into a log of its own:
#
#   lane<n>   rs/parity.json split into lanes (rs/parity/lanes.mjs), every
#             lane run twice: TypeScript against the binary (the binary may
#             hand back to the real package), then the binary alone against a
#             stand-in package, which fails unless exactly the cases marked
#             "handback" for this system reach the JavaScript. As many lanes
#             as the machine has processors (PARITY_LANES says otherwise).
#   cross     rs/cross-compat.sh: the two taking turns on the same files
#   tty       rs/tty-compat.py: scenes on a pseudo-terminal (python3's pty)
#   pipe      rs/pipe-compat.py: `dede get` into pipes and sockets that are
#             read after it has exited
#   perm      rs/perm-compat.sh: where the file system refuses something (as
#             root, with sudo, or alone; see there)
#   unit      cargo test in rs/, on macOS and Windows (on Linux the workflow
#             has a job of its own for it). It builds the crate again from
#             the same sources and Cargo.lock; it does not run the binary
#             named above.
#
# On Windows the binary hands every invocation back to dede.ts, before it has
# done anything (rs/src/cli.rs platform_is_proven), so only the lanes and the
# unit tests run there: the lanes show that every case reaches the
# JavaScript through the binary and behaves as dede.ts run directly does,
# with the cases that cannot mean the same there skipped (rs/parity.gen.mjs
# says which and why). The others are left out, and the summary says so:
# cross-compat would compare dede.ts with itself; there is no pseudo-terminal
# (python's pty is for Linux and macOS); a pipe's room is never asked there;
# and there are no POSIX modes, owners or sticky directories.
#
# At the end one line is printed for each that passed, and all of what a
# failed one wrote. The exit code is 0 only when all of them passed.
set -u
usage="usage: proof.sh <parity.mjs> <binary>"
# In Git Bash `pwd -W` gives a directory as Windows programs (node, the
# binary) read it.
here=$(pwd -W 2> /dev/null || pwd)
absolute() {
  case "$1" in
    /* | [A-Za-z]:[\\/]*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$here" "$1" ;;
  esac
}
runner=$(absolute "${1:?$usage}")
binary=$(absolute "${2:?$usage}")
# In Git Bash, one spelling (C:/…/x) that node, the binary and the shell all
# read alike, whatever mix of slashes the workflow's variables have.
if command -v cygpath > /dev/null 2>&1; then
  runner=$(cygpath -m "$runner")
  binary=$(cygpath -m "$binary")
fi
cd "$(dirname "$0")/../.." || exit 1
root=$(pwd -W 2> /dev/null || pwd)

platform=${RUSTIFY_PLATFORM:-}
if [ -z "$platform" ]; then
  case "$(uname -s)" in
    Linux) platform=linux ;;
    Darwin) platform=darwin ;;
    MINGW* | MSYS* | CYGWIN*) platform=win32 ;;
    *) platform=$(uname -s) ;;
  esac
fi
lanes=${PARITY_LANES:-$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo "${NUMBER_OF_PROCESSORS:-2}")}
case "$platform" in
  win32*) others="unit" left_out="cross tty pipe perm" ;;
  darwin*) others="cross tty pipe perm unit" left_out="" ;;
  *) others="cross tty pipe perm" left_out="unit" ;;
esac

node rs/parity.gen.mjs --check || exit 1
bun rs/vectors.gen.mjs --check || exit 1

# In $TMPDIR, which macOS's mktemp passes over without a template.
logs=$(mktemp -d "${TMPDIR:-/tmp}/dede-proof.XXXXXX") || exit 1
logs_for_node=$(cygpath -m "$logs" 2> /dev/null || printf '%s' "$logs")
node rs/parity/lanes.mjs rs/parity.json "$lanes" "$logs_for_node" || exit 1

start() {
  name=$1
  shift
  (
    "$@" > "$logs/$name.log" 2>&1
    echo $? > "$logs/$name.exit"
  ) &
}
lane() {
  cases=$logs_for_node/lane-$1.json
  code=0
  node "$runner" --cases "$cases" --ts "sh rs/parity/run.sh bun dede.ts" --rs "env DOTENVDOTENC_PACKAGE_ROOT=$root sh rs/parity/run.sh $binary" || code=1
  node "$runner" --cases "$cases" --rs "sh rs/parity/run.sh $binary" --handback DOTENVDOTENC_PACKAGE_ROOT=dede.ts || code=1
  return $code
}
runs=""
n=0
while [ "$n" -lt "$lanes" ]; do
  start "lane$n" lane "$n"
  runs="$runs lane$n"
  n=$((n + 1))
done
for name in $others; do
  case $name in
    cross) start cross sh rs/cross-compat.sh "$binary" ;;
    tty) start tty python3 rs/tty-compat.py "$binary" ;;
    pipe) start pipe python3 rs/pipe-compat.py "$binary" ;;
    perm) start perm sh rs/perm-compat.sh "$binary" ;;
    unit) start unit cargo test --release --locked --manifest-path rs/Cargo.toml ;;
  esac
  runs="$runs $name"
done
wait

echo "proof on $platform with bun $(bun --version), $lanes lane(s):$runs"
failed=0
same=0 native=0 back=0
for name in $runs; do
  code=$(cat "$logs/$name.exit" 2> /dev/null || echo "no exit code")
  if [ "$code" != 0 ]; then
    echo "$name: FAILED ($code)"
    cat "$logs/$name.log"
    failed=1
    continue
  fi
  case $name in
    lane*)
      count=$(sed -n 's/^all \([0-9]*\) case(s) behave the same$/\1/p' "$logs/$name.log")
      same=$((same + count))
      count=$(sed -n 's/^\([0-9]*\) case(s) answered by the binary, .*/\1/p' "$logs/$name.log")
      native=$((native + count))
      count=$(sed -n 's/^.* answered by the binary, \([0-9]*\) handed back .*/\1/p' "$logs/$name.log")
      back=$((back + count))
      ;;
    unit) grep '^test result' "$logs/$name.log" | sed "s/^/$name: /" ;;
    *) tail -n 1 "$logs/$name.log" | sed "s/^/$name: /" ;;
  esac
done
if [ "$failed" = 0 ]; then
  echo "parity: all $same case(s) behave the same; $native answered by the binary, $back handed back to the JavaScript, as the cases say"
  # Each run of each lane names the cases skipped here, and why (both runs
  # of a lane skip the same ones): the reasons, summed.
  tab=$(printf '\t')
  cat "$logs"/lane*.log | sed -n "s/^ *\([0-9][0-9]*\)  \(.*\)\$/\1$tab\2/p" | sort -t "$tab" -k 2 | awk -F "$tab" '
    $2 != reason { if (reason != "") print total "\t" reason; reason = $2; total = 0 }
    { total += $1 }
    END { if (reason != "") print total "\t" reason }' | while IFS="$tab" read -r total reason; do
    echo "  skipped on $platform: $((total / 2))  $reason"
  done
fi
for name in $left_out; do
  case $name in
    unit) echo "unit: not here (the workflow's cargo test job runs it on Linux)" ;;
    cross) echo "cross: not here (the binary hands every invocation back on Windows: both sides would be dede.ts)" ;;
    tty) echo "tty: not here (no pseudo-terminal on Windows)" ;;
    pipe) echo "pipe: not here (on Windows the binary hands back before it looks at a pipe)" ;;
    perm) echo "perm: not here (no POSIX modes, owners or sticky directories on Windows)" ;;
  esac
done
rm -rf "$logs"
exit $failed
