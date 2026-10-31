# filter — neural shellcode firewall (pwn)

## TL;DR

`filter` runs submitted shellcode only if its "guard transformer" scores the
blob `<= 0`. The model is fake: it is an analytical *bigram detector* for
exactly three byte pairs.

```
0f 05   syscall
cd 80   int 0x80
0f 34   sysenter
```

Nothing else is looked at (`gen_model.py`, and the weights in `model.h`, show
one-hot embeddings for `0f/cd/05/80/34` only, identity Q/K/V, and relative
bias favouring the previous token).

So the bypass is trivial and does not depend on the network: submit **any**
code that never contains those byte pairs, gets itself a `syscall`, and runs
it.

## Payload (`payload.S`, 111 bytes)

1. `lea rbx, [rip+stub]` — address of a 3-byte `nop nop nop` tail in our own
   RWX page (the runner `mmap`s `PROT_READ|PROT_WRITE|PROT_EXEC`).
2. Patch it into `0f 05 c3` (`syscall; ret`) with three `mov byte [rbx+k], imm`
   stores — none of those encodings contain a forbidden pair
   (`c6 03 0f`, `c6 43 01 05`, `c6 43 02 c3`).
3. `execve("/bin/sh", NULL, NULL)` through the stub.
4. If `execve` ever fails: `open("/flag.txt")` + `read` + `write(1, ...)`.

Guard verdict on this payload:

```
[*] guard verdict: score = -10.000
[+] looks harmless to me. Executing...
```

(`-10.000` is exactly `GUARD_B2`: no gate ever fires, i.e. the model is
completely blind to the payload.)

## Files

| file         | what                                                   |
|--------------|--------------------------------------------------------|
| `payload.S`  | annotated x86-64 assembly of the bypass                |
| `build.sh`   | assembles it to `payload.bin` and asserts no bigrams   |
| `solve.py`   | sender: remote `HOST PORT` or local binary, grabs flag |

## Usage

```sh
./build.sh
./solve.py local                      # runs the handout binary, hunts ctfcup{...}
./solve.py remote <host> <port>       # same against the challenge service
./solve.py remote <host> <port> --cmd 'ls -la /; cat /flag*'
```

`solve.py` speaks the protocol (`u32 LE length` + bytes), waits for the
"Executing" line, then drives the shell and greps the transcript for
`ctfcup{...}`.

## Why the "AI" part is a red herring

The FFN is three AND gates over `concat(x[i], ctx[i])` with
`ctx = x[i-1]` (attention picks offset 1 because `relbias[1] = +30`,
everything else `-30`). Each gate is `relu(x[a] + ctx[b] - 1)`, which fires
only when the current byte is `a` and the previous is `b`. `w2 = 30`,
`b2 = -10`, so a hit gives `+20` and a miss `-10`. `score = max_i logit[i]`,
and the runner checks `score > 0` — a per-position, per-bigram detector
wearing a transformer costume.

Anything the detector cannot name is "benign": syscalls built at runtime,
`execve`, ORW, whatever. The correct answer to "surely a neural network cannot
be fooled" is "it is not a neural network".
