#!/bin/sh
# Build payload.bin from payload.S and verify it contains none of the
# bigrams the guard transformer fires on.
set -e
cd "$(dirname "$0")"

gcc -nostdlib -static -o /tmp/payload.elf payload.S
objcopy -O binary --only-section=.text /tmp/payload.elf payload.bin

python3 - <<'PY'
data = open("payload.bin", "rb").read()
bad = [b for b in (b"\x0f\x05", b"\xcd\x80", b"\x0f\x34") if b in data]
assert not bad, "payload still contains forbidden bigram(s): %r" % bad
print("payload.bin: %d bytes, no forbidden bigrams" % len(data))
PY
