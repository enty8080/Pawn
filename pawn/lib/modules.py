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

from pawn.lib.module import Module
from pawn.lib.options import Options


class Modules(object):
    """ Subclass of pawn.lib module.

    This subclass of pawn.lib module is intended for providing
    tools for working with Pawn modules.
    """

    def __init__(self, modules: dict) -> None:
        """ Initialize modules.

        :param dict modules: dictionary containing modules
        :return None: None
        """

        super().__init__()

        self.modules = modules
        self.options = Options()

    def get_module(self, module: str) -> Union[Module, None]:
        """ Get Pawn module object.

        :param str module: module name
        :return Union[Module, None]: module object or None
        """

        if module in self.modules:
            return self.modules[module]

    def check_module_multiple(self, module: str, platforms: list, arches: list, types: list) -> bool:
        """ Check if module met multiple requirements.

        :param str module: module name
        :param list platforms: platforms to check module for
        :param list arches: architectures to check module for
        :param list types: types to check module for
        :return bool: True if compatible else False
        """

        module = self.get_module(module)

        if module:
            if platforms and module.details['Platform'] not in platforms:
                return False

            if arches and module.details['Arch'] not in arches:
                return False

            if types and module.details['Type'] not in types:
                return False

            return True

        return False

    def check_module(self, module: str, platform: str, arch: str, type: str) -> bool:
        """ Check if module met the requirements.

        :param str module: module name
        :param str platform: platform to check module for
        :param str arch: architecture to check module for
        :param str type: type to check module for
        :return bool: True if compatible else False
        """

        module = self.get_module(module)

        if module:
            if platform and module.details['Platform'] != platform:
                return False

            if arch and module.details['Arch'] != arch:
                return False

            if type and module.details['Type'] != type:
                return False

            return True

        return False

    @staticmethod
    def validate_options(module: Module) -> list:
        """ Validate missed module options.

        :param Module module: module object
        :return list: list of missed option names
        """

        missed = []

        if hasattr(module, "options"):
            for option in module.options:
                validate = module.options[option]

                if validate['Value'] is None and validate['Required']:
                    missed.append(option)

        return missed

    def set_option_value(self, module: Module, option: str, value: Optional[str] = None) -> bool:
        """ Set module option value.

        :param Module module: module object
        :param str option: option name
        :param Optional[str] value: option value
        :return bool: True if success else False
        """

        return self.options.set_option(module, option, value)

    def run_module(self, module: Module) -> bytes:
        """ Run module.

        :param Module module: module object
        :return bytes: module output
        :raises RuntimeError: with trailing error message
        """

        missed = self.validate_options(module)

        if missed:
            raise RuntimeError(
                f"These options are failed to validate: {', '.join(missed)}!")

        return module.run()
