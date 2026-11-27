#!/usr/bin/env python3
"""Both implementations of dede on a terminal.

The parity runner gives a command pipes, so it cannot show what depends on a
terminal: `dede get` ends its value with a newline only there, `dede enc`
asks "commit …? [y/N]" only there, and only there do standard output and
standard error arrive in one stream, in the order they were written. Each
scene below runs once per implementation in a copy of the same directory, on
a pseudo-terminal, and the two must print the same bytes, exit the same way
and leave the same commits. A third run of the binary, with a stand-in
package whose JavaScript only says it was reached, shows whether the binary
answered the scene itself or handed it back, and that has to be what the
scene says.

Where standard output is a terminal and standard error is not, bun colours
errors by TERM, COLORTERM, CI and more, by a rule that is not imitated: the
binary hands back whatever would print to standard error there, unless
NO_COLOR or FORCE_COLOR decides. Scenes under several TERM values hold that.

    python3 rs/tty-compat.py [path/to/the/binary]     (after `bun install`)

Everything happens in a temp directory with its own HOME; the keys are made
on the spot by dede.ts and thrown away with it.
"""

import os
import pty
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(REPO, "rs/target/release/dotenvdotenc")
WORK = tempfile.mkdtemp(prefix="dede-tty-")

# What decides colours is left out too (CI sets some of these), so that each
# scene says it.
ENV = {k: v for k, v in os.environ.items() if not k.startswith("DOTENV_") and k not in ("NODE_ENV", "BUN_ENV", "BUN_OPTIONS", "NODE_OPTIONS", "NO_COLOR", "FORCE_COLOR", "DOTENVDOTENC_NO_NATIVE", "COLORTERM", "CI", "GITHUB_ACTIONS", "TMUX", "TERM_PROGRAM", "NODE_DISABLE_COLORS")}
ENV.update(HOME=os.path.join(WORK, "home"), XDG_CONFIG_HOME=os.path.join(WORK, "home/.config"), XDG_CACHE_HOME=os.path.join(WORK, "cache"), GIT_CONFIG_NOSYSTEM="1", TZ="UTC", TERM="xterm-256color")
os.makedirs(ENV["HOME"])

IMPLEMENTATIONS = {
    "TypeScript": ["bun", os.path.join(REPO, "dede.ts")],
    # The package root lets the binary hand back what it does not answer (the question of `enc`).
    "Rust": ["env", "DOTENVDOTENC_PACKAGE_ROOT=" + REPO, BIN],
}
MARKER = b"__DEDE_HANDED_BACK__"
STAND_IN = os.path.join(WORK, "stand-in")
os.makedirs(STAND_IN)
open(os.path.join(STAND_IN, "package.json"), "w").write('{"name": "stand-in", "version": "0.0.0"}\n')
open(os.path.join(STAND_IN, "dede.ts"), "w").write(f"process.stdout.write({MARKER.decode()!r});\n")
STAND_IN_RUN = ["env", "DOTENVDOTENC_PACKAGE_ROOT=" + STAND_IN, BIN]


def sh(line, cwd):
    subprocess.run(line, shell=True, cwd=cwd, env=ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def on_a_terminal(command, cwd, answer=None, terminals=("in", "out", "err"), env=None):
    """Runs the command with a pseudo-terminal as the named streams (the others
    are pipes, standard input an empty one). `answer` is typed once the
    question has been printed. Returns the exit code and what each of the
    terminal and the pipes received."""
    master, slave = pty.openpty()
    stream = lambda name: slave if name in terminals else (subprocess.DEVNULL if name == "in" else subprocess.PIPE)
    env = {name: value for name, value in (env or ENV).items() if value is not None}
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=stream("in"), stdout=stream("out"), stderr=stream("err"), start_new_session=True)
    os.close(slave)
    readers = {master: b""}
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            readers[pipe.fileno()] = b""
    typed = answer is None
    open_fds = set(readers)
    deadline = time.time() + 120
    while open_fds and time.time() < deadline:
        ready, _, _ = select.select(list(open_fds), [], [], 0.1)
        if not ready and process.poll() is not None:
            break
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if not data:
                open_fds.discard(fd)
                continue
            readers[fd] += data
            if not typed and b"[y/N] " in readers[master]:
                os.write(master, answer)
                typed = True
    code = process.wait()
    os.close(master)
    clean = lambda data: data.replace(cwd.encode(), b"<DIR>")
    return code, tuple(clean(readers[fd]) for fd in sorted(readers, key=lambda fd: fd != master))


def template():
    """A repository with files in several states, made with dede.ts."""
    base = os.path.join(WORK, "template")
    os.makedirs(base)
    sh("git init -q -b main && git config --global user.name Tty && git config --global user.email tty@example.com", base)
    open(os.path.join(base, ".gitignore"), "w").write(".env*\n!.env*.enc\n")
    open(os.path.join(base, ".env.prod"), "w").write("API_KEY=dummy-1\nNAME=\"hello world\"\n")
    open(os.path.join(base, ".env.stage"), "w").write("A=1\n")
    dede = "bun --no-env-file " + os.path.join(REPO, "dede.ts")
    sh(dede + " enc .env.prod .env.stage", base)
    sh("git add .gitignore .env.prod.enc .env.stage.enc && git commit -q -m init", base)
    # .env.prod edited since; .env.stage's .enc damaged; .env.new not encrypted yet; .env.shared committed in plaintext.
    open(os.path.join(base, ".env.prod"), "a").write("NEW=1\n")
    stage = os.path.join(base, ".env.stage.enc")
    damaged = re.sub(r"^(A=encrypted:.{40}).", r"\1x", open(stage).read(), count=1, flags=re.M)
    open(stage, "w").write(damaged)
    open(os.path.join(base, ".env.new"), "w").write("FRESH=1\n")
    open(os.path.join(base, ".env.shared"), "w").write("PUBLIC=1\n")
    sh("git add -f .env.shared && git commit -q -m public", base)
    return base


ALL = ("in", "out", "err")
NATIVE, BACK = False, True
SCENES = [
    # (what, arguments, what is typed at the question, which streams are a terminal, variables, handed back?)
    ("get ends the value with a newline", ["get", "API_KEY", ".env.prod"], None, ALL, {}, NATIVE),
    ("get into a pipe, errors to the terminal", ["get", "API_KEY", ".env.prod"], None, ("in", "err"), {}, NATIVE),
    ("get of a name that is not there", ["get", "MISSING", ".env.prod"], None, ALL, {}, NATIVE),
    ("get of a name that is not there, into a pipe", ["get", "MISSING", ".env.prod"], None, ("in", "err"), {}, NATIVE),
    ("status: both streams in the order they were written", ["status"], None, ALL, {}, NATIVE),
    ("status: errors to a file, the rest to the terminal", ["status"], None, ("in", "out"), {}, BACK),
    ("status: only standard input is a terminal", ["status"], None, ("in",), {}, NATIVE),
    ("status with NO_COLOR=1", ["status"], None, ALL, {"NO_COLOR": "1"}, NATIVE),
    ("status with FORCE_COLOR=0, errors to the terminal", ["status"], None, ("err",), {"FORCE_COLOR": "0"}, NATIVE),
    ("status with FORCE_COLOR=0, errors to a file", ["status"], None, ("in", "out"), {"FORCE_COLOR": "0"}, NATIVE),
    ("diff", ["diff"], None, ALL, {}, NATIVE),
    ("keys", ["keys"], None, ALL, {}, NATIVE),
    ("the usage", ["help"], None, ALL, {}, NATIVE),
    ("an unknown command", ["frobnicate"], None, ALL, {}, NATIVE),
    ("enc asks before it commits; no", ["enc", ".env.prod", ".env.new"], b"n\n", ALL, {}, BACK),
    ("enc asks before it commits; yes", ["enc", ".env.prod", ".env.new"], b"y\n", ALL, {}, BACK),
    ("enc asks before it commits; YES with spaces around", ["enc", ".env.new"], b"  YES \n", ALL, {}, BACK),
    ("enc asks before it commits; just the return key", ["enc", ".env.new"], b"\n", ALL, {}, BACK),
    ("enc -y does not ask", ["enc", "-y", ".env.prod", ".env.new"], None, ALL, {}, NATIVE),
    ("enc with nothing to write does not ask", ["enc", ".env.shared"], None, ALL, {}, BACK),
    ("enc without a terminal on standard input does not ask", ["enc", ".env.new"], None, ("out", "err"), {}, NATIVE),
    ("dec --force", ["dec", "--force", ".env.prod"], None, ALL, {}, NATIVE),
    ("guard", ["guard"], None, ALL, {}, NATIVE),
    ("setup", ["setup"], None, ALL, {}, NATIVE),
]
# Standard output a terminal, standard error a pipe: bun's colour depends on
# the terminal's name and more, so what prints an error goes back; NO_COLOR
# and FORCE_COLOR decide, and what prints no error stays.
OUT_ONLY = ("in", "out")
for label, variables in [
    ("TERM unset", {"TERM": None}),
    ("TERM empty", {"TERM": ""}),
    ("TERM=dumb", {"TERM": "dumb"}),
    ("TERM=xterm", {"TERM": "xterm"}),
    ("TERM=alacritty", {"TERM": "alacritty"}),
    ("TERM=unknown", {"TERM": "unknown"}),
    ("TERM unset, COLORTERM=truecolor", {"TERM": None, "COLORTERM": "truecolor"}),
    ("TERM=dumb, COLORTERM=truecolor", {"TERM": "dumb", "COLORTERM": "truecolor"}),
    ("TERM unset, CI=true", {"TERM": None, "CI": "true"}),
    ("TERM=dumb, CI=true", {"TERM": "dumb", "CI": "true"}),
    ("TERM unset, GITHUB_ACTIONS=true", {"TERM": None, "GITHUB_ACTIONS": "true"}),
    ("TERM unset, TMUX set", {"TERM": None, "TMUX": "/tmp/tmux-0/default,1,0"}),
    ("TERM=dumb, NO_COLOR empty", {"TERM": "dumb", "NO_COLOR": ""}),
    ("TERM=dumb, NO_COLOR=0", {"TERM": "dumb", "NO_COLOR": "0"}),
]:
    SCENES.append((f"an error, standard error a pipe, {label}", ["get"], None, OUT_ONLY, variables, BACK))
for label, variables in [
    ("TERM=dumb, FORCE_COLOR=1", {"TERM": "dumb", "FORCE_COLOR": "1"}),
    ("TERM unset, FORCE_COLOR=true", {"TERM": None, "FORCE_COLOR": "true"}),
    ("TERM=xterm, FORCE_COLOR=0", {"TERM": "xterm", "FORCE_COLOR": "0"}),
    ("TERM=xterm, NO_COLOR=1", {"TERM": "xterm", "NO_COLOR": "1"}),
    ("TERM unset, NO_COLOR=1, FORCE_COLOR=0", {"TERM": None, "NO_COLOR": "1", "FORCE_COLOR": "0"}),
]:
    SCENES.append((f"an error, standard error a pipe, {label}", ["get"], None, OUT_ONLY, variables, NATIVE))
SCENES += [
    ("get prints its value, standard error a pipe, TERM=dumb", ["get", "API_KEY", ".env.prod"], None, OUT_ONLY, {"TERM": "dumb"}, NATIVE),
    ("get of a name that is not there, standard error a pipe, TERM=dumb", ["get", "MISSING", ".env.prod"], None, OUT_ONLY, {"TERM": "dumb"}, BACK),
    ("the usage, standard error a pipe, TERM unset", ["help"], None, OUT_ONLY, {"TERM": None}, NATIVE),
    ("enc -y, standard error a pipe, TERM unset", ["enc", "-y", ".env.new"], None, OUT_ONLY, {"TERM": None}, BACK),
    ("enc -y, standard error a pipe, TERM unset, FORCE_COLOR=1", ["enc", "-y", ".env.new"], None, OUT_ONLY, {"TERM": None, "FORCE_COLOR": "1"}, NATIVE),
    ("dec --force, standard error a pipe, TERM=xterm", ["dec", "--force", ".env.prod"], None, OUT_ONLY, {"TERM": "xterm"}, BACK),
    ("setup, standard error a pipe, TERM=dumb", ["setup"], None, OUT_ONLY, {"TERM": "dumb"}, BACK),
    ("guard, standard error a pipe, TERM unset", ["guard"], None, OUT_ONLY, {"TERM": None}, BACK),
    ("keys, standard error a pipe, TERM unset: a notice on standard error", ["keys"], None, OUT_ONLY, {"TERM": None}, BACK),
    ("keys of one file, standard error a pipe, TERM unset: nothing on standard error", ["keys", ".env.prod"], None, OUT_ONLY, {"TERM": None}, NATIVE),
]


# On macOS the binary hands back a get that prints into a pipe: it asks
# Linux alone how much room a pipe has (rs/src/out.rs stdout_takes).
BACK_ON_MACOS = {"get into a pipe, errors to the terminal"}


def main():
    base = template()
    failed = 0
    for number, (what, arguments, answer, terminals, variables, handed_back) in enumerate(SCENES, 1):
        if sys.platform == "darwin" and what in BACK_ON_MACOS:
            handed_back = BACK
        seen = {}
        env = {**ENV, **variables}
        for name, command in IMPLEMENTATIONS.items():
            cwd = os.path.join(WORK, f"{number}-{name}")
            shutil.copytree(base, cwd, symlinks=True)
            code, output = on_a_terminal(command + arguments, cwd, answer, terminals, env)
            log = subprocess.run("git log --format=%s && git status --porcelain", shell=True, cwd=cwd, env=ENV, capture_output=True).stdout
            seen[name] = (code, output, log)
        cwd = os.path.join(WORK, f"{number}-stand-in")
        shutil.copytree(base, cwd, symlinks=True)
        reached = any(MARKER in part for part in on_a_terminal(STAND_IN_RUN + arguments, cwd, answer, terminals, env)[1])
        if seen["TypeScript"] == seen["Rust"] and reached == handed_back:
            code, output, _ = seen["Rust"]
            print(f"ok {number} - {what}: exit {code}, {sum(map(len, output))} bytes, {'red' if any(b'[31m' in part for part in output) else 'plain'} errors, {'handed back' if reached else 'answered by the binary'}")
        else:
            failed += 1
            print(f"DIFFER {number} - {what}")
            if reached != handed_back:
                print(f"    the binary {'handed it back' if reached else 'answered it'}; the scene says it {'goes back' if handed_back else 'is answered by the binary'}")
            for name, (code, output, log) in seen.items():
                print(f"    {name}: exit {code}\n      {output!r}\n      {log!r}")
    shutil.rmtree(WORK, ignore_errors=True)
    if failed:
        sys.exit(f"{failed} of {len(SCENES)} scenes differ")
    print(f"all {len(SCENES)} scenes are the same on a terminal, and handed back where they say so")


main()
