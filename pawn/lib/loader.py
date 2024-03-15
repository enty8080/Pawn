"""
MIT License

Copyright (c) 2020-2024 EntySec

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

import os
import importlib.util

from pawn.lib.options import Options
from pawn.lib.templates import Templates


class Loader(object):
    """ Subclass of pawn module.

    This subclass of pawn is intended for providng
    Pawn loader.
    """

    def __init__(self) -> None:
        super().__init__()

        self.options = Options()

    def import_modules(self, path: str) -> dict:
        """ Import modules.

        :param str path: path to import modules from
        :return dict: dict of modules
        """

        modules = {}

        for dir, _, files in os.walk(path):
            for file in files:
                if file.endswith('.py') and file != '__init__.py':
                    module = dir + '/' + file

                    try:
                        spec = importlib.util.spec_from_file_location(module, module)
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        module = module.PawnModule()

                        self.options.add_options(module)
                        modules[module.details['Name']] = module

                    except BaseException as e:
                        print(str(e))

        return modules

    def load_modules(self) -> dict:
        """ Load modules.

        :return dict: dict of modules
        """

        return self.import_modules(f'{os.path.dirname(os.path.dirname(__file__))}/modules')
