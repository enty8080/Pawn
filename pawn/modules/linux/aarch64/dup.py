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
            'Name': "linux/aarch64/dup",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer',
            ],
            'Description': "Duplicate file descriptor.",
            'Arch': ARCH_AARCH64,
            'Platform': OS_LINUX,
            'Type': "one_side",
        })

        self.input = Option(
            'x12', 'Register in which the file descriptor located or an integer.', True)
        self.output = Option('x12', 'Register in which place the duplicate.', True)

    def run(self):
        payload = dedent(f"""\
        dup:
            mov x0, {str(self.input.value)}
            mov x8, 0x17
            svc 0

            mov {self.output.value}, x0
        """)

        return self.assemble(
            self.details['Arch'], payload)
