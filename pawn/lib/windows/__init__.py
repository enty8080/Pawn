"""
MIT License

Copyright (c) 2020-2023 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from .reflective_dll import ReflectiveDLL

from .x86 import ReverseTCP as X86ReverseTCP
from .x64 import ReverseTCP as X64ReverseTCP


class Windows(object):
    """ Main class of pawn.windows module.

    This main class of pawn.windows module is intended for
    providing Pawn implementations for Windows.
    """

    def __init__(self) -> None:
        super().__init__()

        self.x64_reverse_tcp = X64ReverseTCP()
        self.x86_reverse_tcp = X86ReverseTCP()

    def get_payload(self, arch: str, type: str = 'reverse_tcp',
                    *args, **kwargs) -> bytes:
        """ Obtain stage payload for the specific platform
        and architecture.

        :param str arch: architecture
        :param str type: stage type
        """

        if arch == 'x86':
            if type == 'reverse_tcp':
                return self.x86_reverse_tcp.get_payload(*args, **kwargs)

            raise RuntimeError(f"Invalid payload type: {type}!")

        elif arch == 'x64':
            if type == 'reverse_tcp':
                return self.x64_reverse_tcp.get_payload(*args, **kwargs)

            raise RuntimeError(f"Invalid payload type: {type}!")

        raise RuntimeError(f"Invalid payload architecture: {arch}!")
