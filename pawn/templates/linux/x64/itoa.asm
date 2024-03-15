<%doc>
This template requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
</%doc>

<%doc>
Copyright (c) Tomas Globis 2023

Converting int to string on amd64 assembler. Analog of %u in printf().
String is expected to

Modified by Ivan Nikolskiy to make it stack-based (push, pop).
</%doc>

<%page />
itoa:
    push    r14
    pop     rax
    lea     rbx, [rsp+14]
    push    10
    pop     rcx
    xor     rdi, rdi
    push    rax
    pop     rsi

number_len_loop:
    xor     rdx, rdx
    div     rcx
    inc     rdi
    test    rax, rax
    jnz     number_len_loop

    push    rsi
    pop     rax
    dec     rdi

convert_loop:
    xor     dx, dx
    div     rcx
    add     dx, 48
    or      [rbx+rdi], dx
    dec     rdi
    test    rax, rax
    jnz     convert_loop