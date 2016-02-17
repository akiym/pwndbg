#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import pwndbg.arch
import pwndbg.arguments
import pwndbg.disasm
import pwndbg.disasm.arm
import pwndbg.disasm.jump
import pwndbg.disasm.mips
import pwndbg.disasm.ppc
import pwndbg.disasm.sparc
import pwndbg.disasm.x86

import pwndbg.vmmap
import pwndbg.dt
import pwndbg.memory
import pwndbg.inthook
import pwndbg.elf
import pwndbg.proc
import pwndbg.regs
import pwndbg.stack
import pwndbg.stdio
import pwndbg.color
import pwndbg.typeinfo
import pwndbg.constants
import pwndbg.argv
import pwndbg.commands
import pwndbg.commands.hexdump
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.commands.vmmap
import pwndbg.commands.dt
import pwndbg.commands.search
import pwndbg.commands.start
import pwndbg.commands.procinfo
import pwndbg.commands.auxv
import pwndbg.commands.windbg
import pwndbg.commands.ida
import pwndbg.commands.reload
import pwndbg.commands.rop
import pwndbg.commands.shell
import pwndbg.commands.aslr
import pwndbg.commands.misc
import pwndbg.commands.next
import pwndbg.commands.dumpargs
import pwndbg.commands.cpsr
import pwndbg.commands.argv
import pwndbg.commands.heap


__all__ = [
'arch',
'auxv',
'chain',
'color',
'compat',
'disasm',
'dt',
'elf',
'enhance',
'events',
'file',
'function',
'hexdump',
'phexdump',
'ida',
'info',
'linkmap',
'malloc',
'memoize',
'memory',
'proc',
'regs',
'remote',
'search',
'stack',
'strings',
'symbol',
'typeinfo',
'ui',
'vmmap'
]

prompt = "pwndbg> "
prompt = "\x01" + prompt + "\x02" # SOH + prompt + STX
prompt = pwndbg.color.red(prompt)
prompt = pwndbg.color.bold(prompt)

pre_commands = """
set confirm off
set verbose off
set output-radix 0x10
set prompt %s
set height 0
set history expansion on
set history save on
set disassembly-flavor intel
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width 0
set print elements 15
set input-radix 16
handle SIGALRM nostop print nopass
handle SIGSEGV stop   print nopass
""".strip() % prompt

for line in pre_commands.strip().splitlines():
	gdb.execute(line)

msg = "Loaded %i commands.  Type pwndbg for a list." % len(pwndbg.commands._Command.commands)
print(pwndbg.color.red(msg))

@pwndbg.memoize.reset_on_stop
def prompt_hook(*a):
    with pwndbg.stdio.stdio:
        pwndbg.commands.context.context()

gdb.prompt_hook = prompt_hook
