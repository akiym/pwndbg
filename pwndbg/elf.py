#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This file declares types and methods useful for enumerating
all of the address spaces and permissions of an ELF file in memory.

This is necessary for when access to /proc is restricted, or when
working on a BSD system which simply does not have /proc.
"""
from __future__ import print_function

import os
import re
import subprocess
import tempfile

import gdb
import pwndbg.auxv
import pwndbg.events
import pwndbg.info
import pwndbg.memoize
import pwndbg.memory
import pwndbg.proc
import pwndbg.stack
import pwndbg.typeinfo

# ELF constants
PF_X, PF_W, PF_R = 1,2,4
ET_EXEC, ET_DYN  = 2,3

# In order for this file to work, we need to have symbols loaded
# in GDB for various ELF header types.
#
# We can simply create an object file and load its symbols (and types!)
# into our address space.  This should not pollute any actual symbols
# since we don't declare any functions, and load the object file at
# address zero.
tempdir = tempfile.gettempdir()
gef_elf = os.path.join(tempdir, 'pwndbg-elf')
with open(gef_elf + '.c', 'w+') as f:
    f.write('''#include <elf.h>
Elf32_Ehdr a;
Elf64_Ehdr b;
Elf32_Phdr e;
Elf64_Phdr f;
''')
    f.flush()

subprocess.check_output('gcc -c -g %s.c -o %s.o' % (gef_elf, gef_elf), shell=True)

@pwndbg.proc.OnlyWhenRunning
@pwndbg.memoize.reset_on_start
def exe():
    """
    Return a loaded ELF header object pointing to the Ehdr of the
    main executable.
    """
    return load(entry())

@pwndbg.proc.OnlyWhenRunning
@pwndbg.memoize.reset_on_start
def entry():
    """
    Return the address of the entry point for the main executable.
    """
    entry = pwndbg.auxv.get().AT_ENTRY
    if entry:
        return entry

    # Looking for this line:
    # Entry point: 0x400090
    for line in pwndbg.info.files().splitlines():
        if "Entry point" in line:
            entry_point = int(line.split()[-1], 16)

            # PIE entry points are sometimes reported as an
            # offset from the module base.
            if entry_point < 0x10000:
                break

            return entry_point

    # Try common names
    for name in ['_start', 'start', '__start', 'main']:
        try:
            return int(gdb.parse_and_eval(name))
        except gdb.error:
            pass

    # Can't find it, give up.
    return 0


def load(pointer):
    return get_ehdr(pointer)[1]

def get_ehdr(pointer):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A tuple containing (ei_class, gdb.Value).
        The gdb.Value object has type of either Elf32_Ehdr or Elf64_Ehdr.

    Example:

        >>> pwndbg.elf.load(gdb.parse_and_eval('$pc'))
        [Page('400000-4ef000 r-xp 0'),
         Page('6ef000-6f0000 r--p ef000'),
         Page('6f0000-6ff000 rw-p f0000')]
        >>> pwndbg.elf.load(0x7ffff77a2000)
        [Page('7ffff75e7000-7ffff77a2000 r-xp 0x1bb000 0'),
         Page('7ffff77a2000-7ffff79a2000 ---p 0x200000 1bb000'),
         Page('7ffff79a2000-7ffff79a6000 r--p 0x4000 1bb000'),
         Page('7ffff79a6000-7ffff79ad000 rw-p 0x7000 1bf000')]
    """
    with pwndbg.events.Pause():
        gdb.execute('add-symbol-file %s.o 0' % gef_elf, from_tty=False, to_string=True)

    Elf32_Ehdr = pwndbg.typeinfo.load('Elf32_Ehdr')
    Elf64_Ehdr = pwndbg.typeinfo.load('Elf64_Ehdr')

    # Align down to a page boundary, and scan until we find
    # the ELF header.
    base = pwndbg.memory.page_align(pointer)

    try:
        data = pwndbg.memory.read(base, 4)

        # Do not search more than 4MB of memory
        for i in range(1024):
            if data == b'\x7FELF':
                break

            base -= pwndbg.memory.PAGE_SIZE
            data = pwndbg.memory.read(base, 4)

        else:
            print("ERROR: Could not find ELF base!")
            return None, None
    except gdb.MemoryError:
        return None, None

    # Determine whether it's 32- or 64-bit
    ei_class = pwndbg.memory.byte(base+4)

    # Find out where the section headers start
    EhdrType = { 1: Elf32_Ehdr, 2: Elf64_Ehdr }[ei_class]
    Elfhdr   = pwndbg.memory.poi(EhdrType, base)
    return ei_class, Elfhdr

def get_phdrs(pointer):
    """
    Returns a tuple containing (phnum, phentsize, gdb.Value),
    where the gdb.Value object is an ELF Program Header with
    the architecture-appropriate structure type.
    """
    ei_class, Elfhdr = get_ehdr(pointer)

    if Elfhdr is None:
        return (0, 0, None)

    Elf32_Phdr = pwndbg.typeinfo.load('Elf32_Phdr')
    Elf64_Phdr = pwndbg.typeinfo.load('Elf64_Phdr')
    PhdrType   = { 1: Elf32_Phdr, 2: Elf64_Phdr }[ei_class]

    phnum     = int(Elfhdr['e_phnum'])
    phoff     = int(Elfhdr['e_phoff'])
    phentsize = int(Elfhdr['e_phentsize'])

    x = (phnum, phentsize, pwndbg.memory.poi(PhdrType, int(Elfhdr.address) + phoff))
    return x

def iter_phdrs(ehdr):
    if not ehdr:
        raise StopIteration

    phnum, phentsize, phdr = get_phdrs(int(ehdr.address))

    if not phdr:
        raise StopIteration

    first_phdr = int(phdr.address)
    PhdrType   = phdr.type

    for i in range(0, phnum):
        p_phdr = int(first_phdr + (i*phentsize))
        p_phdr = pwndbg.memory.poi(PhdrType, p_phdr)
        yield p_phdr

def map(pointer, objfile=''):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A sorted list of pwndbg.memory.Page objects

    Example:

        >>> pwndbg.elf.load(gdb.parse_and_eval('$pc'))
        [Page('400000-4ef000 r-xp 0'),
         Page('6ef000-6f0000 r--p ef000'),
         Page('6f0000-6ff000 rw-p f0000')]
        >>> pwndbg.elf.load(0x7ffff77a2000)
        [Page('7ffff75e7000-7ffff77a2000 r-xp 0x1bb000 0'),
         Page('7ffff77a2000-7ffff79a2000 ---p 0x200000 1bb000'),
         Page('7ffff79a2000-7ffff79a6000 r--p 0x4000 1bb000'),
         Page('7ffff79a6000-7ffff79ad000 rw-p 0x7000 1bf000')]
    """
    ei_class, ehdr         = get_ehdr(pointer)
    return map_inner(ei_class, ehdr, objfile)

@pwndbg.memoize.reset_on_objfile
def map_inner(ei_class, ehdr, objfile):
    if not ehdr:
        return []

    base = int(ehdr.address)

    # For each Program Header which would load data into our
    # address space, create a representation of each individual
    # page and its permissions.
    #
    # Entries are processed in-order so that later entries
    # which change page permissions (e.g. PT_GNU_RELRO) will
    # override their small subset of address space.
    pages = []
    for phdr in iter_phdrs(ehdr):
        memsz   = int(phdr['p_memsz'])

        if not memsz:
            continue

        vaddr   = int(phdr['p_vaddr'])
        offset  = int(phdr['p_offset'])
        flags   = int(phdr['p_flags'])
        ptype   = int(phdr['p_type'])

        memsz += pwndbg.memory.page_offset(vaddr)
        memsz  = pwndbg.memory.page_size_align(memsz)
        vaddr  = pwndbg.memory.page_align(vaddr)
        offset = pwndbg.memory.page_align(offset)

        # For each page described by this program header
        for page_addr in range(vaddr, vaddr+memsz, pwndbg.memory.PAGE_SIZE):
            if page_addr in pages:
                page = pages[pages.index(page_addr)]

                # Don't ever remove the execute flag.
                # Sometimes we'll load a read-only area into .text
                # and the loader doesn't actually *remove* the executable flag.
                if page.flags & PF_X: flags |= PF_X
                page.flags = flags
            else:
                page = pwndbg.memory.Page(page_addr, pwndbg.memory.PAGE_SIZE, flags, offset + (page_addr-vaddr))
                pages.append(page)

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if check_pie(ehdr):
        for page in pages:
            page.vaddr += base

    # Merge contiguous sections of memory together
    pages.sort()
    prev = pages[0]
    for page in list(pages[1:]):
        if (prev.flags & PF_W) == (page.flags & PF_W) and prev.vaddr+prev.memsz == page.vaddr:
            prev.memsz += page.memsz
            pages.remove(page)
        else:
            prev = page

    # Fill in any gaps with no-access pages.
    # This is what the linker does, and what all the '---p' pages are.
    gaps = []
    for i in range(len(pages)-1):
        a, b    = pages[i:i+2]
        a_end   = (a.vaddr + a.memsz)
        b_begin = b.vaddr
        if a_end != b_begin:
            gaps.append(pwndbg.memory.Page(a_end, b_begin-a_end, 0, b.offset))

    pages.extend(gaps)

    for page in pages:
        page.objfile = objfile

    return tuple(sorted(pages))

def check_pie(ehdr):
    return ET_DYN == int(ehdr['e_type'])
