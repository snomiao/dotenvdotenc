#!/usr/bin/env python3
"""Both implementations of dede on a terminal.

The parity runner gives a command pipes, so it cannot show what depends on a
terminal: `dede get` ends its value with a newline only there, `dede enc`
asks "commit …? [y/N]" only there, and only there do standard output and
standard error arrive in one stream, in the order they were written. Each
scene below runs once per implementation in a copy of the same directory, on
a pseudo-terminal, and the two must print the same bytes, exit the same way
and leave the same commits.

    python3 rs/tty-compat.py [path/to/the/binary]     (after `bun install`)

Everything happens in a temp directory with its own HOME; the keys are made
on the spot by dede.ts and thrown away with it.
"""

import os
import pty
import select
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(REPO, "rs/target/release/dotenvdotenc")
WORK = tempfile.mkdtemp(prefix="dede-tty-")

ENV = {k: v for k, v in os.environ.items() if not k.startswith("DOTENV_") and k not in ("NODE_ENV", "BUN_ENV", "BUN_OPTIONS", "NODE_OPTIONS", "DOTENVDOTENC_NO_NATIVE")}
ENV.update(HOME=os.path.join(WORK, "home"), XDG_CONFIG_HOME=os.path.join(WORK, "home/.config"), XDG_CACHE_HOME=os.path.join(WORK, "cache"), GIT_CONFIG_NOSYSTEM="1", TZ="UTC", TERM="xterm-256color")
os.makedirs(ENV["HOME"])

IMPLEMENTATIONS = {
    "TypeScript": ["bun", os.path.join(REPO, "dede.ts")],
    # The package root lets the binary hand back what it does not answer (the question of `enc`).
    "Rust": ["env", "DOTENVDOTENC_PACKAGE_ROOT=" + REPO, BIN],
}


def sh(line, cwd):
    subprocess.run(line, shell=True, cwd=cwd, env=ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def on_a_terminal(command, cwd, answer=None, terminals=("in", "out", "err"), env=None):
    """Runs the command with a pseudo-terminal as the named streams (the others
    are pipes, standard input an empty one). `answer` is typed once the
    question has been printed. Returns the exit code and what each of the
    terminal and the pipes received."""
    master, slave = pty.openpty()
    stream = lambda name: slave if name in terminals else (subprocess.DEVNULL if name == "in" else subprocess.PIPE)
    process = subprocess.Popen(command, cwd=cwd, env=env or ENV, stdin=stream("in"), stdout=stream("out"), stderr=stream("err"), start_new_session=True)
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
    sh("sed -i -E 's/^(A=encrypted:.{40})./\\1x/' .env.stage.enc", base)
    open(os.path.join(base, ".env.new"), "w").write("FRESH=1\n")
    open(os.path.join(base, ".env.shared"), "w").write("PUBLIC=1\n")
    sh("git add -f .env.shared && git commit -q -m public", base)
    return base


ALL = ("in", "out", "err")
SCENES = [
    # (what, arguments, what is typed at the question, which streams are a terminal, variables)
    ("get ends the value with a newline", ["get", "API_KEY", ".env.prod"], None, ALL, {}),
    ("get into a pipe, errors to the terminal", ["get", "API_KEY", ".env.prod"], None, ("in", "err"), {}),
    ("get of a name that is not there", ["get", "MISSING", ".env.prod"], None, ALL, {}),
    ("get of a name that is not there, into a pipe", ["get", "MISSING", ".env.prod"], None, ("in", "err"), {}),
    ("status: both streams in the order they were written", ["status"], None, ALL, {}),
    ("status: errors to a file, the rest to the terminal", ["status"], None, ("in", "out"), {}),
    ("status: only standard input is a terminal", ["status"], None, ("in",), {}),
    ("status with NO_COLOR=1", ["status"], None, ALL, {"NO_COLOR": "1"}),
    ("status with FORCE_COLOR=0, errors to the terminal", ["status"], None, ("err",), {"FORCE_COLOR": "0"}),
    ("status with FORCE_COLOR=0, errors to a file", ["status"], None, ("in", "out"), {"FORCE_COLOR": "0"}),
    ("diff", ["diff"], None, ALL, {}),
    ("keys", ["keys"], None, ALL, {}),
    ("the usage", ["help"], None, ALL, {}),
    ("an unknown command", ["frobnicate"], None, ALL, {}),
    ("enc asks before it commits; no", ["enc", ".env.prod", ".env.new"], b"n\n", ALL, {}),
    ("enc asks before it commits; yes", ["enc", ".env.prod", ".env.new"], b"y\n", ALL, {}),
    ("enc asks before it commits; YES with spaces around", ["enc", ".env.new"], b"  YES \n", ALL, {}),
    ("enc asks before it commits; just the return key", ["enc", ".env.new"], b"\n", ALL, {}),
    ("enc -y does not ask", ["enc", "-y", ".env.prod", ".env.new"], None, ALL, {}),
    ("enc with nothing to write does not ask", ["enc", ".env.shared"], None, ALL, {}),
    ("enc without a terminal on standard input does not ask", ["enc", ".env.new"], None, ("out", "err"), {}),
    ("dec --force", ["dec", "--force", ".env.prod"], None, ALL, {}),
    ("guard", ["guard"], None, ALL, {}),
    ("setup", ["setup"], None, ALL, {}),
]


def main():
    base = template()
    failed = 0
    for number, (what, arguments, answer, terminals, variables) in enumerate(SCENES, 1):
        seen = {}
        for name, command in IMPLEMENTATIONS.items():
            cwd = os.path.join(WORK, f"{number}-{name}")
            shutil.copytree(base, cwd, symlinks=True)
            code, output = on_a_terminal(command + arguments, cwd, answer, terminals, {**ENV, **variables})
            log = subprocess.run("git log --format=%s && git status --porcelain", shell=True, cwd=cwd, env=ENV, capture_output=True).stdout
            seen[name] = (code, output, log)
        if seen["TypeScript"] == seen["Rust"]:
            code, output, _ = seen["Rust"]
            print(f"ok {number} - {what}: exit {code}, {sum(map(len, output))} bytes, {'red' if any(b'[31m' in part for part in output) else 'plain'} errors")
        else:
            failed += 1
            print(f"DIFFER {number} - {what}")
            for name, (code, output, log) in seen.items():
                print(f"    {name}: exit {code}\n      {output!r}\n      {log!r}")
    shutil.rmtree(WORK, ignore_errors=True)
    if failed:
        sys.exit(f"{failed} of {len(SCENES)} scenes differ")
    print(f"all {len(SCENES)} scenes are the same on a terminal")


main()
