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

from typing import Optional, Tuple, Any

from .loader import Loader
from .lib.module import Module


class Pawn(object):
    """ Main class of pawn module.

    This main class of pawn module is intended to provide
    an implementation of some general Pawn algorithms.
    """

    def __init__(self) -> None:
        super().__init__()

        self.loader = Loader()
        self.modules = self.loader.load_modules()

    def get_module(self, module: str, platform: Optional[str] = None,
                   arch: Optional[str] = None) -> Module:
        """ Get Pawn module object.

        :param str module: module name
        :param Optional[str] platform: platform to check compatibility with
        :param Optional[str] arch: architecture to check compatibility with
        :return Module: module object
        :raises RuntimeError: with trailing error message
        """

        if module in self.modules:
            module = self.modules[module]

            if platform and platform != module.details['Platform']:
                raise RuntimeError(f"Platform {platform} is not compatible with {module} module!")

            if arch and arch != module.details['Architecture']:
                raise RuntimeError(f"Architecture {arch} is not compatible with {module} module!")

            return module

        raise RuntimeError("Invalid Pawn module name!")

    def get_pawn(self, module: str, platform: Optional[str] = None,
                 arch: Optional[str] = None, *args, **kwargs) -> Tuple[Any, bool]:
        """ Get Pawn module payload.

        :param str module: module name
        :param Optional[str] platform: platform to check compatibility with
        :param Optional[str] arch: architecture to check compatibility with
        :return Tuple[Any, bool]: payload and True if requires size else False
        :raises RuntimeError: with trailing error message
        """

        try:
            module = self.get_module(
                module=module,
                platform=platform,
                arch=arch
            )

            return module.run(*args, **kwargs), module.details['SendSize']

        except Exception:
            return None, None
