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

from typing import Union, Optional

from pawn.lib.loader import Loader
from pawn.lib.module import Module
from pawn.lib.modules import Modules

from pex.platform.types import Platform
from pex.arch.types import Arch


class Pawn(object):
    """ Main class of pawn module.

    This main class of pawn module is intended to provide
    an implementation of some general Pawn algorithms.
    """

    def __init__(self) -> None:
        super().__init__()

        self.loader = Loader()
        self.modules = Modules(self.loader.load_modules())

    def auto_pawn(self, platform: Union[Arch, str],
                  arch: Union[Arch, str],
                  type: str) -> Union[Module, None]:
        """ Select pawn using only platform, arch and type.

        :param Union[Platform, str] platform: platform
        :param Union[Arch, str] arch: architecture
        :param str type: type
        """

        module = '/'.join((str(platform), str(arch), type))
        return self.get_pawn(module, platform, arch, type)

    def get_pawn(self, module: str,
                 platform: Optional[Union[list, Platform, str]] = None,
                 arch: Optional[Union[list, Arch, str]] = None,
                 type: Optional[Union[list, str]] = None) -> Union[Module, None]:
        """ Get pawn module.

        :param str module: module name
        :param Optional[Union[list, Platform, str]] platform: list of supported platforms
        :param Optional[Union[list, Arch, str]] arch: list of supported architectures
        :param Optional[Union[list, str]] type: list of supported types
        :return Union[Module, None]: module object or None
        """

        if self.modules.check_module(
                module, platform, arch, type):
            return self.modules.get_module(module)

    def run_pawn(self, module: Module) -> bytes:
        """ Run pawn module.

        :param Module module: module object
        :return bytes: module output
        """

        return self.modules.run_module(module)
