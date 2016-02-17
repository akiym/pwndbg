#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Looking up addresses for function names / symbols, and
vice-versa.

Uses IDA when available if there isn't sufficient symbol
information available.
"""
import gdb
import re
import os
import tempfile
import pwndbg.elf
import pwndbg.events
import pwndbg.file
import pwndbg.ida
import pwndbg.hopper
import pwndbg.memoize
import pwndbg.memory
import pwndbg.remote
import pwndbg.stack
import pwndbg.vmmap

def get_directory():
    """
    Retrieve the debug file directory path.

    The debug file directory path ('show debug-file-directory') is a comma-
    separated list of directories which GDB will look in to find the binaries
    currently loaded.
    """
    result = gdb.execute('show debug-file-directory', to_string=True, from_tty=False)
    expr   = r'The directory where separate debug symbols are searched for is "(.*)".\n'

    match = re.search(expr, result)

    if match:
        return match.group(1)
    return ''

def set_directory(d):
    gdb.execute('set debug-file-directory %s' % d, to_string=True, from_tty=False)

def add_directory(d):
    current = get_directory()
    if current:
        set_directory('%s:%s' % (current, d))
    else:
        set_directory(d)

remote_files = {}
remote_files_dir = None

@pwndbg.events.exit
def reset_remote_files():
    global remote_files
    global remote_files_dir
    remote_files = {}
    remote_files_dir = tempfile.mkdtemp()

@pwndbg.events.new_objfile
def autofetch():
    """
    """
    global remote_files_dir
    if not pwndbg.remote.is_remote():
        return

    if not remote_files_dir:
        remote_files_dir = tempfile.mkdtemp()
        add_directory(remote_files_dir)

    searchpath = get_directory()

    for mapping in pwndbg.vmmap.get():
        objfile = mapping.objfile

        # Don't attempt to download things like '[stack]' and '[heap]'
        if not objfile.startswith('/'):
            continue

        # Don't re-download things that we have already downloaded
        if not objfile or objfile in remote_files:
            continue

        print("Downloading %r from the remote server" % objfile)

        data = pwndbg.file.get(objfile)
        filename = os.path.basename(objfile)
        local_path = os.path.join(remote_files_dir, filename)

        with open(local_path, 'w+') as f:
            f.write(data)

        remote_files[objfile] = local_path


@pwndbg.memoize.reset_on_objfile
def get(address, gdb_only=False):
    """
    Retrieve the textual name for a symbol
    """
    # Fast path
    if address < pwndbg.memory.MMAP_MIN_ADDR or address >= (1 << 64):
        return ''

    # Don't look up stack addresses
    if pwndbg.stack.find(address):
        return ''

    # This sucks, but there's not a GDB API for this.
    result = gdb.execute('info symbol %#x' % int(address), to_string=True, from_tty=False)

    if not gdb_only and result.startswith('No symbol'):
        address = int(address)
        exe     = pwndbg.elf.exe()
        if exe:
            exe_map = pwndbg.vmmap.find(exe.address)
            if exe_map and address in exe_map:
                if pwndbg.ida.available():
                    res =  pwndbg.ida.Name(address) or pwndbg.ida.GetFuncOffset(address)
                if pwndbg.hopper.available():
                    res =  pwndbg.hopper.Name(address) or pwndbg.hopper.GetFuncOffset(address)
                return res or ''

    # Expected format looks like this:
    # main in section .text of /bin/bash
    # main + 3 in section .text of /bin/bash
    # system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
    # No symbol matches system-1.
    a, b, c, _ = result.split(None, 3)


    if b == '+':
        return "%s+%s" % (a, c)
    if b == 'in':
        return a

    return ''

@pwndbg.memoize.reset_on_objfile
def address(symbol):
    if isinstance(symbol, (int,long)):
        return symbol

    try:
        return int(symbol, 0)
    except:
        pass

    try:
        result = gdb.execute('info address %s' % symbol, to_string=True, from_tty=False)
        address = re.search('0x[0-9a-fA-F]+', result).group()
        return int(address, 0)
    except gdb.error:
        return None

@pwndbg.events.stop
@pwndbg.memoize.reset_on_start
def add_main_exe_to_symbols():
    if not pwndbg.remote.is_remote():
        return

    exe  = pwndbg.elf.exe()

    if not exe:
        return

    addr = exe.address

    if not addr:
        return

    addr = int(addr)

    mmap = pwndbg.vmmap.find(addr)
    if not mmap:
        return

    path = mmap.objfile
    if path:
        try:
            gdb.execute('add-symbol-file %s %#x' % (path, addr), from_tty=False, to_string=True)
        except gdb.error:
            pass

if '/usr/lib/debug' not in get_directory():
    set_directory(get_directory() + ':/usr/lib/debug')
