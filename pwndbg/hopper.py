#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Talks to an XMLRPC server running inside of an active Hopper instance,
in order to query it about the database.  Allows symbol resolution and
interactive debugging.
"""
import errno
import functools
import os
import socket
import traceback
from contextlib import closing

import gdb
import pwndbg.arch
import pwndbg.compat
import pwndbg.elf
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory
import pwndbg.regs

try:
    import xmlrpc.client as xmlrpclib
except:
    import xmlrpclib

enabled = False

xmlrpclib.Marshaller.dispatch[int] = lambda _, v, w: w("<value><int>%d</int></value>" % v)
xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><int>%d</int></value>" % v)

if pwndbg.compat.python2:
    xmlrpclib.Marshaller.dispatch[long] = lambda _, v, w: w("<value><int>%d</int></value>" % v)

_hopper = None

def setPort(port):
    global _hopper
    _hopper = xmlrpclib.ServerProxy('http://localhost:%s' % port)
    try:
        _hopper.here()
    except socket.error as e:
        if e.errno != errno.ECONNREFUSED:
            traceback.print_exc()
        _hopper = None

class withHopper(object):
    def __init__(self, fn):
        self.fn = fn
        functools.update_wrapper(self, fn)
    def __call__(self, *args, **kwargs):
        # import pdb
        # pdb.set_trace()
        if enabled:
            if _hopper is None:
                setPort(8889)
            if _hopper is not None:
                return self.fn(*args, **kwargs)
        return None

def takes_address(function):
    @functools.wraps(function)
    def wrapper(address, *args, **kwargs):
        return function(l2r(address), *args, **kwargs)
    return wrapper

def returns_address(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        return r2l(function(*args, **kwargs))
    return wrapper

@withHopper
def available():
    return enabled

def l2r(addr):
    result = (addr - int(pwndbg.elf.exe().address) + base()) & pwndbg.arch.ptrmask
    return result

def r2l(addr):
    result = (addr - base() + int(pwndbg.elf.exe().address)) & pwndbg.arch.ptrmask
    return result

@pwndbg.memoize.reset_on_objfile
def base():
    result =  _hopper.NextSeg_(0) & ~(0xfff)
    if result < 0x100000:
        return 0
    return result

@withHopper
@takes_address
def Comment(addr):
    addr = l2r(addr)
    return _hopper.GetCommentEx_repeatable_(addr, 0) or _hopper.GetCommentEx_repeatable_(addr, 1)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def Name(addr):
    return _hopper.Name_(addr)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFuncOffset(addr):
    rv =  _hopper.GetFuncOffset_(addr)
    return rv

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetType(addr):
    rv =  _hopper.GetType_(addr)
    return rv

@withHopper
@returns_address
def here():
    return _hopper.here()

@withHopper
@takes_address
def Jump(addr):
    return _hopper.Jump_(addr)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def Anterior(addr):
    hexrays_prefix = '\x01\x04; '
    lines = []
    for i in range(10):
        r = _hopper.LineA_num_(addr, i)
        if not r: break
        if r.startswith(hexrays_prefix):
            r = r[len(hexrays_prefix):]
        lines.append(r)
    return '\n'.join(lines)

@withHopper
def GetBreakpoints():
    for i in range(GetBptQty()):
        yield GetBptEA(i)

@withHopper
def GetBptQty():
    return _hopper.GetBptQty()

@withHopper
@returns_address
def GetBptEA(i):
    return _hopper.GetBptEA_(i)

_breakpoints=[]

@pwndbg.events.cont
@pwndbg.events.stop
@withHopper
def UpdateBreakpoints():
    # XXX: Remove breakpoints from Hopper when the user removes them.
    current = set(eval(b.location.lstrip('*')) for b in _breakpoints)
    want    = set(GetBreakpoints())

    # print(want)

    for addr in current-want:
        for bp in _breakpoints:
            if int(bp.location.lstrip('*'), 0) == addr:
                # print("delete", addr)
                bp.delete()
                break
        _breakpoints.remove(bp)

    for bp in want-current:
        if not pwndbg.memory.peek(bp):
            continue

        bp = gdb.Breakpoint('*' + hex(bp))
        _breakpoints.append(bp)
        # print(_breakpoints)


@withHopper
@takes_address
def SetColor(pc, color):
    return _hopper.SetColor_what_color_(pc, 1, color)


colored_pc = None

@pwndbg.events.stop
@withHopper
def Auto_Color_PC():
    global colored_pc
    colored_pc = pwndbg.regs.pc
    SetColor(colored_pc, 0x7f7fff)

@pwndbg.events.cont
@withHopper
def Auto_UnColor_PC():
    global colored_pc
    if colored_pc:
        SetColor(colored_pc, 0xffffff)
    colored_pc = None

@withHopper
@returns_address
@pwndbg.memoize.reset_on_objfile
def LocByName(name):
    return _hopper.LocByName_(str(name))

@withHopper
@takes_address
@returns_address
@pwndbg.memoize.reset_on_objfile
def PrevHead(addr):
    return _hopper.PrevHead_(addr)

@withHopper
@takes_address
@returns_address
@pwndbg.memoize.reset_on_objfile
def NextHead(addr):
    return _hopper.NextHead_(addr)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFunctionName(addr):
    return _hopper.GetFunctionName_(addr)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFlags(addr):
    return _hopper.GetFlags_(addr)

@withHopper
@pwndbg.memoize.reset_on_objfile
def isASCII(flags):
    return _hopper.isASCII_(flags)

@withHopper
@takes_address
@pwndbg.memoize.reset_on_objfile
def ArgCount(address):
    pass
