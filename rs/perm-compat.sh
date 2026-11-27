#!/bin/sh
# Both implementations of dede where the file system refuses something: a
# hooks directory that cannot be written, a hook that cannot be read, a file
# of another user in a sticky directory, a directory that cannot be written.
# The parity runner cannot make these (it runs everything as one user, and
# root may do anything), so each scene is made here, given to a user who may
# not do what it refuses, and run once per implementation in a copy of the
# same directory. Both must exit the same way, print the same, and leave the
# same files with the same modes and owners, temp files included. The scenes
# where dede.ts ends in bun's report of an uncaught error after a first write
# are the ones the binary has to hand back before it writes anything: a third
# run, with a stand-in package whose JavaScript only says it was reached,
# shows that each scene is handed back, or answered by the binary, as it says.
#
#   sh rs/perm-compat.sh [path/to/the/binary]     (after `bun install`)
#
# Run it as root (the commands then run as the user nobody), or as a user who
# may use sudo without a password (CI: the commands run as that user, and
# sudo makes what belongs to root). Everything happens in one temp directory,
# removed at the end.
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=$(cd "$(dirname "${1:-$REPO/rs/target/release/dotenvdotenc}")" && pwd)/$(basename "${1:-dotenvdotenc}")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/dede-perm-XXXXXX")
if [ "$(id -u)" = 0 ]; then
  AS="setpriv --reuid=65534 --regid=65534 --clear-groups"
  SUDO=
  # bun usually lives where nobody may not go.
  mkdir "$WORK/bin"
  cp "$(command -v bun)" "$WORK/bin/bun"
  chmod 755 "$WORK" "$WORK/bin" "$WORK/bin/bun"
  RUN_PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin"
  USER_NAME=nobody
else
  sudo -n true 2>/dev/null || { echo "perm-compat.sh: run it as root, or as a user who may use sudo without a password" >&2; exit 2; }
  AS=
  SUDO="sudo -n"
  RUN_PATH=$PATH
  USER_NAME=$(id -un)
fi
trap '$SUDO rm -rf "$WORK"' EXIT
MARKER=__DEDE_HANDED_BACK__
mkdir "$WORK/stand-in"
printf '{"name": "stand-in", "version": "0.0.0"}\n' > "$WORK/stand-in/package.json"
printf 'process.stdout.write("%s");\n' "$MARKER" > "$WORK/stand-in/dede.ts"
chmod 755 "$WORK" "$WORK/stand-in"
GROUP_NAME=$(id -gn "$USER_NAME")
failed=0
count=0

broken() {
  echo "BROKEN $count - $name: $1 failed"
  sed 's/^/    /' "$S/setup.log"
  exit 1
}

# scene back|native <name> <made in it, as its user> <then, as root> -- <args…>
scene() {
  expected=$1 name=$2 make=$3 restrict=$4
  shift 4
  [ "$1" = -- ] && shift
  count=$((count + 1))
  for impl in ts rs stand-in; do
    S="$WORK/$count-$impl"
    mkdir -p "$S/cwd" "$S/home"
    (cd "$S/cwd" && HOME="$S/home" GIT_CONFIG_NOSYSTEM=1 sh -c "git init -q -b main && printf '.env*\\n!.env*.enc\\n' > .gitignore && $make") > "$S/setup.log" 2>&1 || broken "making the scene"
    # git refuses a repository of another user; this one is shared on purpose.
    printf '[safe]\n\tdirectory = *\n' >> "$S/home/.gitconfig"
    if [ -n "$SUDO$AS" ]; then $SUDO chown -R "$USER_NAME:$GROUP_NAME" "$S"; fi
    chmod 755 "$S"
    (cd "$S/cwd" && $SUDO sh -c "$restrict") >> "$S/setup.log" 2>&1 || broken "restricting it"
    case $impl in
      ts) command="bun $REPO/dede.ts" ;;
      rs) command="env DOTENVDOTENC_PACKAGE_ROOT=$REPO $BIN" ;;
      *) command="env DOTENVDOTENC_PACKAGE_ROOT=$WORK/stand-in $BIN" ;;
    esac
    set +e
    (cd "$S/cwd" && $AS env -i PATH="$RUN_PATH" HOME="$S/home" XDG_CONFIG_HOME="$S/home/.config" GIT_CONFIG_NOSYSTEM=1 TZ=UTC $command "$@") > "$S/out" 2> "$S/err" < /dev/null
    echo "exit $?" > "$S/code"
    set -e
    for part in out err; do
      sed -e "s|$S|<S>|g" -e 's/dede-tmp-[0-9]*-[0-9a-f]*/dede-tmp-<pid>-<random>/g' "$S/$part" > "$S/$part.seen"
    done
    (cd "$S/cwd" && $SUDO find . -path ./.git/objects -prune -o -path ./.git/refs -prune -o -path ./.git/logs -prune -o -print | sort | while read -r f; do
      $SUDO stat -c '%a %U %F' "$f" | tr '\n' ' '
      echo "$f" | sed 's/dede-tmp-[0-9]*-[0-9a-f]*/dede-tmp-<pid>-<random>/'
    done | sed "s/ $USER_NAME / <user> /") > "$S/after" 2>&1
  done
  A="$WORK/$count-ts" B="$WORK/$count-rs"
  if grep -q "$MARKER" "$WORK/$count-stand-in/out"; then answered=back; else answered=native; fi
  if [ $answered = "$expected" ] && cmp -s "$A/code" "$B/code" && cmp -s "$A/out.seen" "$B/out.seen" && cmp -s "$A/err.seen" "$B/err.seen" && cmp -s "$A/after" "$B/after"; then
    echo "ok $count - $name: $(cat "$A/code"), $(wc -l < "$A/err.seen") line(s) on stderr, $([ $answered = back ] && echo "handed back" || echo "answered by the binary")"
  else
    failed=$((failed + 1))
    echo "DIFFER $count - $name"
    [ $answered = "$expected" ] || echo "  the binary's answer: $answered; the scene says: $expected"
    for part in code out.seen err.seen after; do
      cmp -s "$A/$part" "$B/$part" || { echo "  --- $part"; diff "$A/$part" "$B/$part" | sed 's/^/    /' | head -40; }
    done
  fi
}

NO_RULES=': > .gitignore'
HOOK='mkdir -p .git/hooks && printf "#!/bin/sh\necho hi\n" > .git/hooks/pre-commit'

# setup: after its first write the TypeScript ends in an uncaught error; the
# binary sees each of these before that write and hands back.
scene back "setup: the hooks directory belongs to root" "$NO_RULES && mkdir -p .git/hooks" 'chown root:root .git/hooks && chmod 755 .git/hooks' -- setup
scene back "setup: the pre-commit hook cannot be read" "$NO_RULES && $HOOK" 'chmod 000 .git/hooks/pre-commit' -- setup
scene back "setup: the post-checkout hook cannot be read, the others are written first" "$NO_RULES && mkdir -p .git/hooks && echo x > .git/hooks/post-checkout" 'chown root:root .git/hooks/post-checkout && chmod 600 .git/hooks/post-checkout' -- setup
scene back "setup: core.hooksPath names a directory of root's" "$NO_RULES && mkdir hooks && git config core.hooksPath hooks" 'chown root:root hooks && chmod 755 hooks' -- setup
scene back "setup: core.hooksPath in the user's .gitconfig names a directory of root's" "$NO_RULES && mkdir \"\$HOME/hooks\" && git config --global core.hooksPath '~/hooks'" 'chown root:root ../home/hooks && chmod 755 ../home/hooks' -- setup
scene back "setup: core.hooksPath names a directory that cannot be made" "$NO_RULES && mkdir locked && git config core.hooksPath locked/hooks" 'chown root:root locked && chmod 755 locked' -- setup
# The first write fails: the TypeScript ends in an uncaught error with one
# temp file left; the binary hands back without leaving its own.
scene back "setup: .gitignore belongs to root in a sticky directory" "$NO_RULES" 'chown root:root . .gitignore && chmod 1777 .' -- setup
scene back "setup: package.json belongs to root in a sticky directory" 'echo "{}" > package.json' 'chown root:root . package.json && chmod 1777 .' -- setup
scene back "setup: the rules are there, the hooks directory belongs to root" 'mkdir -p .git/hooks' 'chown root:root .git/hooks && chmod 755 .git/hooks' -- setup
scene back "setup: the rules are there, the directory cannot be written (husky)" 'echo "{}" > package.json' 'chown root:root . && chmod 755 .' -- setup
# Answered by both: a refusal of dede's own or a file that fails alone.
scene native "setup: the hooks directory can be written" "$NO_RULES && $HOOK" 'chmod 755 .git/hooks' -- setup
scene native "enc: the directory cannot be written, so no key can be saved" 'printf "A=1\n" > .env.prod' 'chown root:root . && chmod 755 .' -- enc
scene native "enc: the sync record cannot be written" 'printf "A=1\n" > .env.prod && mkdir -p .git/dotenvdotenc' 'chown root:root .git/dotenvdotenc && chmod 755 .git/dotenvdotenc' -- enc
scene native "dec: the plaintext's directory cannot be written" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null && rm .env.prod' 'chown root:root . && chmod 755 .' -- dec
scene native "status: a plaintext that cannot be read" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null' 'chmod 000 .env.prod' -- status
scene back "keys link: the directory cannot be written" 'printf "DOTENV_PRIVATE_KEY_X=1\n" > ../keys && chmod 600 ../keys' 'chown root:root . && chmod 755 .' -- keys link ../keys

if [ "$failed" -gt 0 ]; then
  echo "$failed of $count scenes differ"
  exit 1
fi
echo "all $count scenes are the same"
