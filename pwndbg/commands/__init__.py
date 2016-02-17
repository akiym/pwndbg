#!/usr/bin/env python
# -*- coding: utf-8 -*-
import functools
import traceback
import gdb

import pwndbg.chain
import pwndbg.color
import pwndbg.enhance
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs
import pwndbg.stdio
import pwndbg.symbol
import pwndbg.ui

import sys


debug = True

class _Command(gdb.Command):
    """Generic command wrapper"""
    count    = 0
    commands = []

    def __init__(self, function):
        super(_Command, self).__init__(function.__name__, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)
        self.function = function

        self.commands.append(self)
        functools.update_wrapper(self, function)
        self.__doc__ = function.__doc__

    def split_args(self, argument):
        return gdb.string_to_argv(argument)

    def invoke(self, argument, from_tty):
        argv = self.split_args(argument)
        try:
            return self.function(*argv)
        except:
            if debug:
                print(traceback.format_exc())
            raise

    def __call__(self, *args, **kwargs):
        with pwndbg.stdio.stdio:
            return self.function(*args, **kwargs)


class _ParsedCommand(_Command):
    def split_args(self, argument):
        # sys.stdout.write(repr(argument) + '\n')
        argv = super(_ParsedCommand,self).split_args(argument)
        # sys.stdout.write(repr(argv) + '\n')
        return list(filter(lambda x: x is not None, map(fix, argv)))



def fix(arg, sloppy=False):
    try:
        parsed = gdb.parse_and_eval(arg)
        return parsed
    except Exception:
        pass

    try:
        arg = pwndbg.regs.fix(arg)
        return gdb.parse_and_eval(arg)
    except Exception as e:
        print(e)
        pass

    if sloppy:
        return arg

    return None

def OnlyWhenRunning(function):
    @functools.wraps(function)
    def _OnlyWhenRunning(*a, **kw):
        if pwndbg.proc.alive:
            return function(*a, **kw)
        else:
            print("Only available when running")
    return _OnlyWhenRunning

def Command(func):
    class C(_Command):
        __doc__ = func.__doc__
        __name__ = func.__name__
    return C(func)

def ParsedCommand(func):
    class C(_ParsedCommand):
        __doc__ = func.__doc__
        __name__ = func.__name__
    return C(func)
