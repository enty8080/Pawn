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

from typing import Union, Optional

from pawn.lib.module import Module
from mako.template import Template as MakoTemplate


class Templates(object):
    """ Subclass of pawn.lib module.

    This subclass of pawn.lib modules is intended for providing interface
    for working with template for the specific module.
    """

    def __init__(self) -> None:
        """ Initialize templates.

        :param Module module: module object
        :return None: None
        """

        self.templates_path = \
            f'{os.path.dirname(os.path.dirname(__file__))}/templates/'

    def get_module_template(self, module: Module) -> Union[str, None]:
        """ Get template by module

        :param Module module: module object
        :return Union[str, None]: template if exists else None
        """

        return self.get_template(path=module.details['Name'],
                                 module=module)

    def get_template(self, path: str, module: Optional[Module] = None, **kwargs) -> Union[str, None]:
        """ Get template by path or module.

        :param str path: get template by string
        :param Optional[Module] module: bind to module if not None
        :return Union[str, None]: template if exists else None
        """

        template_path = self.templates_path + path + '.asm'

        if os.path.exists(template_path):
            options = {}

            if module is not None:
                if hasattr(module, "options"):
                    options.update(
                        {key.lower(): item['Value'] for key, item in module.options.items()})

                if hasattr(module, "advanced"):
                    options.update(
                        {key.lower(): item['Value'] for key, item in module.advanced.items()})

            else:
                options = kwargs

            with open(template_path, 'r') as f:
                template = '<% from pawn.lib.api import include %>\n'
                template += f.read()

                return re.sub(r'\n{2,}', '\n', MakoTemplate(template).render(
                    **options).strip())
