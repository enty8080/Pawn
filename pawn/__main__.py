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

from typing import Optional

from .loader import Loader


class Pawn(object):
    """ Main class of pawn module.

    This main class of pawn module is intended to provide
    an implementation of some general Pawn algorithms.
    """

    def __init__(self) -> None:
        super().__init__()

        self.loader = Loader()
        self.modules = self.loader.load_modules()

    def get_pawn(self, module: str, platform: Optional[str] = None,
                 arch: Optional[str] = None, *args, **kwargs) -> bytes:
        """ Get Pawn module payload.

        :param str module: module name
        :param Optional[str] platform: platform to check compatibility with
        :param Optional[str] arch: architecture to check compatibility with
        :return bytes: payload
        """

        if module in self.modules:
            module = self.modules[module]

            if platform and platform != module.details['Platform']:
                raise RuntimeError(f"Platform {platform} is not compatible with {module} module!")

            if arch and arch != module.details['Architecture']:
                raise RuntimeError(f"Architecture {arch} is not compatible with {module} module!")

            return module.run(*args, **kwargs)

        raise RuntimeError("Invalid Pawn module name!")
