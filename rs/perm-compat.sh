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
# Run it as root on Linux (the commands then run as the user nobody), or as
# a user who may use sudo without a password (CI on Linux and macOS: the
# commands run as that user, and sudo makes what belongs to root). As a user
# without sudo (a Mac of one's own) each scene that only needs something the
# user cannot write or read is made by the user itself (`alone` below: the
# user's own file or directory without the permission, where root's would
# be), and the scenes that need a file of another user are not run; the last
# line says how many. Everything happens in one temp directory, removed at
# the end. GNU and BSD tools alike (stat and its modes come from node:
# rs/parity/files.mjs).
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=$(cd "$(dirname "${1:-$REPO/rs/target/release/dotenvdotenc}")" && pwd)/$(basename "${1:-dotenvdotenc}")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/dede-perm-XXXXXX")
NODE=$(command -v node)
ALONE=
if [ "$(id -u)" = 0 ]; then
  command -v setpriv > /dev/null || { echo "perm-compat.sh: as root it needs setpriv (Linux) to run the commands as nobody; run it as a user instead" >&2; exit 2; }
  AS="setpriv --reuid=65534 --regid=65534 --clear-groups"
  SUDO=
  # bun usually lives where nobody may not go.
  mkdir "$WORK/bin"
  cp "$(command -v bun)" "$WORK/bin/bun"
  chmod 755 "$WORK" "$WORK/bin" "$WORK/bin/bun"
  RUN_PATH="$WORK/bin:/usr/local/bin:/usr/bin:/bin"
  USER_NAME=nobody
elif sudo -n true 2>/dev/null; then
  AS=
  SUDO="sudo -n"
  RUN_PATH=$PATH
  USER_NAME=$(id -un)
else
  AS=
  SUDO=
  ALONE=1
  RUN_PATH=$PATH
  USER_NAME=$(id -un)
  echo "# without sudo: what a scene makes root's is the user's own without the permission instead; scenes that need a file of another user are not run"
fi
trap 'if [ -n "$ALONE" ]; then chmod -R u+rwx "$WORK"; fi; $SUDO rm -rf "$WORK"' EXIT
MARKER=__DEDE_HANDED_BACK__
mkdir "$WORK/stand-in"
printf '{"name": "stand-in", "version": "0.0.0"}\n' > "$WORK/stand-in/package.json"
printf 'process.stdout.write("%s");\n' "$MARKER" > "$WORK/stand-in/dede.ts"
chmod 755 "$WORK" "$WORK/stand-in"
GROUP_NAME=$(id -gn "$USER_NAME")
USER_UID=$(id -u "$USER_NAME")
failed=0
count=0
alone_skipped=0

broken() {
  echo "BROKEN $count - $name: $1 failed"
  sed 's/^/    /' "$S/setup.log"
  exit 1
}

# scene back|native <name> <made in it, as its user> <then, as root> <or, without sudo, as the user; - for none> -- <args…>
scene() {
  expected=$1 name=$2 make=$3 restrict=$4 alone=$5
  shift 5
  [ "$1" = -- ] && shift
  count=$((count + 1))
  if [ -n "$ALONE" ]; then
    if [ "$alone" = - ]; then
      alone_skipped=$((alone_skipped + 1))
      echo "skip $count - $name: needs a file of another user (sudo)"
      return
    fi
    restrict=$alone
  fi
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
    (cd "$S/cwd" && $SUDO find . -path ./.git/objects -prune -o -path ./.git/refs -prune -o -path ./.git/logs -prune -o -print | sort \
      | $SUDO "$NODE" "$REPO/rs/parity/files.mjs" stat '%a %u %F %n' \
      | sed -e 's/dede-tmp-[0-9]*-[0-9a-f]*/dede-tmp-<pid>-<random>/' -e "s/^\([0-7]*\) $USER_UID /\1 <user> /" -e 's/^\([0-7]*\) 0 /\1 root /') > "$S/after" 2>&1
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
scene back "setup: the hooks directory belongs to root" "$NO_RULES && mkdir -p .git/hooks" 'chown 0:0 .git/hooks && chmod 755 .git/hooks' 'chmod 555 .git/hooks' -- setup
scene back "setup: the pre-commit hook cannot be read" "$NO_RULES && $HOOK" 'chmod 000 .git/hooks/pre-commit' 'chmod 000 .git/hooks/pre-commit' -- setup
scene back "setup: the post-checkout hook cannot be read, the others are written first" "$NO_RULES && mkdir -p .git/hooks && echo x > .git/hooks/post-checkout" 'chown 0:0 .git/hooks/post-checkout && chmod 600 .git/hooks/post-checkout' 'chmod 000 .git/hooks/post-checkout' -- setup
scene back "setup: core.hooksPath names a directory of root's" "$NO_RULES && mkdir hooks && git config core.hooksPath hooks" 'chown 0:0 hooks && chmod 755 hooks' 'chmod 555 hooks' -- setup
scene back "setup: core.hooksPath in the user's .gitconfig names a directory of root's" "$NO_RULES && mkdir \"\$HOME/hooks\" && git config --global core.hooksPath '~/hooks'" 'chown 0:0 ../home/hooks && chmod 755 ../home/hooks' 'chmod 555 ../home/hooks' -- setup
scene back "setup: core.hooksPath names a directory that cannot be made" "$NO_RULES && mkdir locked && git config core.hooksPath locked/hooks" 'chown 0:0 locked && chmod 755 locked' 'chmod 555 locked' -- setup
# The first write fails: the TypeScript ends in an uncaught error with one
# temp file left; the binary hands back without leaving its own.
scene back "setup: .gitignore belongs to root in a sticky directory" "$NO_RULES" 'chown 0:0 . .gitignore && chmod 1777 .' '-' -- setup
scene back "setup: package.json belongs to root in a sticky directory" 'echo "{}" > package.json' 'chown 0:0 . package.json && chmod 1777 .' '-' -- setup
scene back "setup: the rules are there, the hooks directory belongs to root" 'mkdir -p .git/hooks' 'chown 0:0 .git/hooks && chmod 755 .git/hooks' 'chmod 555 .git/hooks' -- setup
scene back "setup: the rules are there, the directory cannot be written (husky)" 'echo "{}" > package.json' 'chown 0:0 . && chmod 755 .' 'chmod 555 .' -- setup
# git names the hooks directory with its links resolved, and the TypeScript
# decides by that path whether the hooks go into .husky.
scene back "setup: .husky a link to real, core.hooksPath .husky/_, real/_ of root" "$NO_RULES && mkdir -p real/_ && ln -s real .husky && git config core.hooksPath .husky/_" 'chown 0:0 real/_ && chmod 755 real/_' 'chmod 555 real/_' -- setup
scene back "setup: core.hooksPath hooks, a link to .husky/_, .husky of root" "$NO_RULES && mkdir -p .husky/_ && ln -s .husky/_ hooks && git config core.hooksPath hooks" 'chown 0:0 .husky && chmod 755 .husky' 'chmod 555 .husky' -- setup
scene back "setup: core.hooksPath .husky/_, a link to ../hk, hk of root" "$NO_RULES && mkdir -p .husky hk && ln -s ../hk .husky/_ && git config core.hooksPath .husky/_" 'chown 0:0 hk && chmod 755 hk' 'chmod 555 hk' -- setup
scene back "setup: the rules are there; .husky a link to real, core.hooksPath .husky/_, real/_ of root" "mkdir -p real/_ && ln -s real .husky && git config core.hooksPath .husky/_" 'chown 0:0 real/_ && chmod 755 real/_' 'chmod 555 real/_' -- setup
# Answered by both: a refusal of dede's own or a file that fails alone.
scene native "setup: the hooks directory can be written" "$NO_RULES && $HOOK" 'chmod 755 .git/hooks' 'chmod 755 .git/hooks' -- setup
scene native "setup: core.hooksPath .husky/_, a link to ../hk, .husky of root" "$NO_RULES && mkdir -p .husky hk && ln -s ../hk .husky/_ && git config core.hooksPath .husky/_" 'chown 0:0 .husky && chmod 755 .husky' 'chmod 555 .husky' -- setup
scene native "enc: the directory cannot be written, so no key can be saved" 'printf "A=1\n" > .env.prod' 'chown 0:0 . && chmod 755 .' 'chmod 555 .' -- enc
scene native "enc: the sync record cannot be written" 'printf "A=1\n" > .env.prod && mkdir -p .git/dotenvdotenc' 'chown 0:0 .git/dotenvdotenc && chmod 755 .git/dotenvdotenc' 'chmod 555 .git/dotenvdotenc' -- enc
scene native "dec: the plaintext's directory cannot be written" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null && rm .env.prod' 'chown 0:0 . && chmod 755 .' 'chmod 555 .' -- dec
scene native "status: a plaintext that cannot be read" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null' 'chmod 000 .env.prod' 'chmod 000 .env.prod' -- status
scene back "keys link: the directory cannot be written" 'printf "DOTENV_PRIVATE_KEY_X=1\n" > ../keys && chmod 600 ../keys' 'chown 0:0 . && chmod 755 .' 'chmod 555 .' -- keys link ../keys
# Files of root's in a sticky directory: nothing cut short, and temp files as
# the TypeScript leaves them.
scene native "dec: .env.prod of root in a sticky directory" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null && printf "A=2\n" > .env.prod' 'chown 0:0 . .env.prod && chmod 1777 .' '-' -- dec --force
scene native "enc: .env.prod.enc of root in a sticky directory" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null && printf "A=2\n" > .env.prod' 'chown 0:0 . .env.prod.enc && chmod 1777 .' '-' -- enc
scene native "enc: .env.keys of root in a sticky directory, a new key for .env.stage" 'printf "A=1\n" > .env.prod && sh '"$REPO"'/rs/parity/run.sh bun '"$REPO"'/dede.ts enc 2>/dev/null && printf "B=1\n" > .env.stage' 'chown 0:0 . .env.keys && chmod 1777 .' '-' -- enc .env.stage

ran=$((count - alone_skipped))
if [ "$failed" -gt 0 ]; then
  echo "$failed of $ran scenes differ"
  exit 1
fi
if [ "$alone_skipped" -gt 0 ]; then
  echo "all $ran scenes are the same; $alone_skipped not run without sudo"
else
  echo "all $count scenes are the same"
fi
