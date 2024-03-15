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

from pex.socket import Socket
from pawn.lib.templates import Templates


def include(path: str, **kwargs) -> bytes:
    """ Include another template.

    :param str path: path to template
    :return str: template (empty if non-existent)
    """

    return Templates().get_template(path, **kwargs) or ''


def pack_ipv4(host: str, endian: str = 'little') -> bytes:
    """ Pack IPv4.

    :param str host: pack host
    :param str endian: little or big
    :return bytes: packed host
    """

    return Socket().pack_host(host, endian)


def pack_port(port: int, endian: str = 'little') -> bytes:
    """ Pack port.

    :param int port: port to pack
    :param str endian: little or big
    :return bytes: packed port
    """

    return Socket().pack_port(port, endian)
