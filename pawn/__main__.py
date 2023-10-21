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


class Pawn(object):
    """ Main class of pawn module.

    This main class of pawn module is intended to provide
    an implementation of some general Pawn algorithms.
    """

    def __init__(self) -> None:
        super().__init__()

        self.loader = Loader()
        self.modules = Modules(self.loader.load_modules())

    def get_pawn(self, module: str, platform: Union[list, str], arch: Union[list, str],
                 type: Union[list, str]) -> Union[Module, None]:
        """ Get pawn module.

        :param str module: module name
        :param Union[list, str] platform: list of supported platforms
        :param Union[list, str] arch: list of supported architectures
        :param Union[list, str] type: list of supported types
        :return Union[Module, None]: module object or None
        """

        if self.modules.check_module(
                module, platform, arch, type):
            return self.modules.get_module(module)

    def set_pawn_option(self, module: Module, option: str, value: Optional[str] = None) -> bool:
        """ Set pawn module option value.

        :param Module module: module object
        :param str option: option name
        :param Optional[str] value: value
        :return bool: True if success else False
        """

        return self.modules.set_option_value(module, option, value)

    def run_pawn(self, module: Module) -> bytes:
        """ Run pawn module.

        :param Module module: module object
        :return bytes: module output
        """

        return self.modules.run_module(module)
