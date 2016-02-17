#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import gdb
import pwndbg.commands


@pwndbg.commands.ParsedCommand
#@pwndbg.commands.OnlyWhenRunning
def socat(port=4000, option=''):
    """
    Listen on port using socat ^..^
    """

    gdb.execute('start')

    filename = getfile()
    bits = pwndbg.arch.ptrsize * 8
    ehdr = pwndbg.elf.exe()
    pie = pwndbg.elf.check_pie(ehdr)

    binary = 'socat%d%s' % (bits, '_pie' if pie else '')

    print('%s: listening on :%d' % (binary, port))

    gdb.execute('exec-file %s' % binary)
    try:
        gdb.execute('run tcp-l:%d,reuseaddr exec:"%s"%s' % (port, filename, option))
    except:
        pass
    gdb.execute('exec-file %s' % filename) # put back

@pwndbg.memoize.reset_on_start
def getfile():
    result = None
    files = pwndbg.info.files()
    m = re.search(".*exec file:\s*`(.*)'", files)
    if m:
        result = m.group(1)
    else: # stripped file, get symbol file
        m = re.search("Symbols from \"([^\"]*)", files)
        if m:
            result = m.group(1)
    return result
