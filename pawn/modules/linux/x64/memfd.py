"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from pex.assembler import Assembler
from pawn.lib.module import *


class PawnModule(Module, Assembler):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "linux/x64/memfd",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer',
                'Tomas Globis (Tomasglgg) - payload developer'
            ],
            'Arch': ARCH_X64,
            'Platform': OS_LINUX,
            'Type': "one_side",
        })

        self.length = IntegerOption(None, 'Length of the implant.', False)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)
        self.obsolete = BooleanOption('no', 'Use obsolete method (no execveat).', True)
        self.sock = Option('rdi', 'Register in which sock is located.', True, True)

    def run(self):
        return self.template
        #return self.assemble(self.details['Arch'], self.template)
