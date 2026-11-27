#!/usr/bin/env python3
"""Both implementations of `dede get` printing into a pipe or a socket.

`dede get` prints the value with process.stdout.write and the TypeScript
ends with process.exit(). Under bun that write does not wait for a pipe or a
socket: what there is no room for when it is made is lost at the exit (on
bun 1.4.0 and Linux, `dede get BIG | slow-reader` gets 65,536 bytes of a
value of 70,000). The binary answers only where the room is certain and
hands back the rest (rs/src/out.rs stdout_takes).

The parity runner reads its pipes as they fill, so it cannot show this. Each
scene below gives `dede get` a pipe or a socket whose reader waits until the
command has exited before it reads anything (at most 30 seconds: a command
that waits for the reader has nothing to do here, and shows as a
difference). Both implementations must print the same bytes and exit the
same way. A third run of the binary, with a stand-in package whose
JavaScript only says it was reached, shows whether the binary answered the
scene itself or handed it back, and that has to be what the scene says.

    python3 rs/pipe-compat.py [path/to/the/binary]     (after `bun install`; Linux)

Everything happens in a temp directory with its own HOME; the key is a
throwaway (the digit 1 sixty-four times, made here).
"""

import fcntl
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(REPO, "rs/target/release/dotenvdotenc")
WORK = tempfile.mkdtemp(prefix="dede-pipe-")
F_SETPIPE_SZ = getattr(fcntl, "F_SETPIPE_SZ", 1031)

ENV = {k: v for k, v in os.environ.items() if not k.startswith("DOTENV_") and k not in ("NODE_ENV", "BUN_ENV", "BUN_OPTIONS", "NODE_OPTIONS", "NO_COLOR", "FORCE_COLOR", "DOTENVDOTENC_NO_NATIVE")}
ENV.update(HOME=os.path.join(WORK, "home"), XDG_CONFIG_HOME=os.path.join(WORK, "home/.config"), XDG_CACHE_HOME=os.path.join(WORK, "cache"), GIT_CONFIG_NOSYSTEM="1", TZ="UTC")
ENV["DOTENV_PRIVATE_KEY_PROD"] = "1" * 64
os.makedirs(ENV["HOME"])

IMPLEMENTATIONS = {
    "TypeScript": ["bun", os.path.join(REPO, "dede.ts")],
    "Rust": ["env", "DOTENVDOTENC_PACKAGE_ROOT=" + REPO, BIN],
}
MARKER = b"__DEDE_HANDED_BACK__"
STAND_IN = os.path.join(WORK, "stand-in")
os.makedirs(STAND_IN)
open(os.path.join(STAND_IN, "package.json"), "w").write('{"name": "stand-in", "version": "0.0.0"}\n')
open(os.path.join(STAND_IN, "dede.ts"), "w").write(f"process.stdout.write({MARKER.decode()!r});\n")
STAND_IN_RUN = ["env", "DOTENVDOTENC_PACKAGE_ROOT=" + STAND_IN, BIN]

SIZES = [1000, 32768, 32769, 57344, 61809, 65536, 65537, 70000, 200000]


def template():
    """A repository whose .env.prod.enc holds a value of each size, made by
    dede.ts; and a plaintext file committed by mistake, which every `get`
    without file arguments warns about on standard error."""
    base = os.path.join(WORK, "template")
    os.makedirs(base)
    run = lambda line: subprocess.run(line, shell=True, cwd=base, env=ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("git init -q -b main && git config --global user.name Pipe && git config --global user.email pipe@example.com")
    open(os.path.join(base, ".gitignore"), "w").write(".env*\n!.env*.enc\n")
    open(os.path.join(base, ".env.prod"), "w").write("".join(f"V{n}={'v' * n}\n" for n in SIZES))
    run("bun --no-env-file " + os.path.join(REPO, "dede.ts") + " enc .env.prod && rm .env.prod")
    open(os.path.join(base, ".env.shared"), "w").write("PUBLIC=1\n")
    run("git add .gitignore .env.prod.enc && git add -f .env.shared && git commit -q -m init")
    return base


def into(kind, command, cwd, prefill=0, nonblocking=False, both=False, capacity=None):
    """Runs the command with standard output (and standard error too, with
    `both`) into a new pipe or socket that already holds `prefill` bytes,
    and reads only once the command has exited. Returns the exit code, what
    the command wrote there, and its standard error otherwise."""
    if kind == "pipe":
        read_end, write_end = os.pipe()
        if capacity:
            fcntl.fcntl(write_end, F_SETPIPE_SZ, capacity)
    else:
        a, b = socket.socketpair()
        write_end, read_end = a.detach(), b.detach()
    if prefill:
        os.write(write_end, b"p" * prefill)
    if nonblocking:
        fcntl.fcntl(write_end, fcntl.F_SETFL, fcntl.fcntl(write_end, fcntl.F_GETFL) | os.O_NONBLOCK)
    process = subprocess.Popen(command, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL, stdout=write_end, stderr=write_end if both else subprocess.PIPE)
    os.close(write_end)
    deadline = time.time() + 30
    while process.poll() is None and time.time() < deadline:
        time.sleep(0.05)
    data = b""
    while True:
        chunk = os.read(read_end, 1 << 20)
        if not chunk:
            break
        data += chunk
    os.close(read_end)
    err = b"" if both else process.stderr.read()
    code = process.wait()
    return code, data[prefill:], err.replace(cwd.encode(), b"<DIR>")


NATIVE, BACK = False, True
SCENES = [
    # (what, the name it gets, pipe or socket, keyword arguments of `into`, handed back?)
    ("a value of 1,000 bytes into a pipe", 1000, "pipe", {}, NATIVE),
    ("65,536 bytes into an empty pipe: room for all of it", 65536, "pipe", {}, NATIVE),
    ("65,537 bytes into an empty pipe: the TypeScript loses one", 65537, "pipe", {}, BACK),
    ("70,000 bytes into an empty pipe", 70000, "pipe", {}, BACK),
    ("57,344 bytes into a pipe already holding 1,000", 57344, "pipe", {"prefill": 1000}, NATIVE),
    ("61,809 bytes into a pipe already holding 1,000: the TypeScript loses one", 61809, "pipe", {"prefill": 1000}, BACK),
    ("1,000 bytes into a full pipe", 1000, "pipe", {"prefill": 65536, "nonblocking": True}, BACK),
    ("70,000 bytes into a pipe left without waiting", 70000, "pipe", {"nonblocking": True}, BACK),
    ("1,000 bytes into a pipe left without waiting", 1000, "pipe", {"nonblocking": True}, NATIVE),
    ("200,000 bytes into a pipe of 1 MiB", 200000, "pipe", {"capacity": 1 << 20}, NATIVE),
    ("1,000 bytes into a pipe that standard error shares, after the warnings", 1000, "pipe", {"both": True}, NATIVE),
    ("65,536 bytes into a pipe that standard error shares, after the warnings", 65536, "pipe", {"both": True}, BACK),
    ("1,000 bytes into a socket", 1000, "socket", {}, NATIVE),
    ("32,768 bytes into a socket", 32768, "socket", {}, NATIVE),
    ("32,769 bytes into a socket: more than is certain", 32769, "socket", {}, BACK),
    ("200,000 bytes into a socket", 200000, "socket", {}, BACK),
    ("1,000 bytes into a socket already holding some", 1000, "socket", {"prefill": 100}, BACK),
    ("1,000 bytes into a socket that standard error shares, after the warnings", 1000, "socket", {"both": True}, BACK),
]


def main():
    if not sys.platform.startswith("linux"):
        sys.exit("pipe-compat.py: Linux only (pipes and sockets elsewhere are handed back without a look)")
    base = template()
    failed = 0
    for number, (what, size, kind, options, handed_back) in enumerate(SCENES, 1):
        seen = {}
        for name, command in IMPLEMENTATIONS.items():
            cwd = os.path.join(WORK, f"{number}-{name}")
            shutil.copytree(base, cwd, symlinks=True)
            seen[name] = into(kind, command + ["get", f"V{size}"], cwd, **options)
        cwd = os.path.join(WORK, f"{number}-stand-in")
        shutil.copytree(base, cwd, symlinks=True)
        reached = MARKER in into(kind, STAND_IN_RUN + ["get", f"V{size}"], cwd, **options)[1]
        if seen["TypeScript"] == seen["Rust"] and reached == handed_back:
            code, data, _ = seen["Rust"]
            print(f"ok {number} - {what}: exit {code}, {len(data)} bytes, {'handed back' if reached else 'answered by the binary'}")
        else:
            failed += 1
            print(f"DIFFER {number} - {what}")
            if reached != handed_back:
                print(f"    the binary {'handed it back' if reached else 'answered it'}; the scene says it {'goes back' if handed_back else 'is answered by the binary'}")
            for name, (code, data, err) in seen.items():
                print(f"    {name}: exit {code}, {len(data)} bytes ({hashlib.sha256(data).hexdigest()[:16]}), stderr {err[:300]!r}")
    shutil.rmtree(WORK, ignore_errors=True)
    if failed:
        sys.exit(f"{failed} of {len(SCENES)} scenes differ")
    print(f"all {len(SCENES)} scenes print the same into a pipe or a socket, and are handed back where they say so")


main()
