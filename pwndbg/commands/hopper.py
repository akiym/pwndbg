import gdb
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.hopper
import pwndbg.regs


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.events.stop
def j(*args):
    """
    Synchronize Hopper's cursor with GDB
    """
    pc = int(gdb.selected_frame().pc())
    pwndbg.hopper.Jump(pc)


if pwndbg.hopper.available():
    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def up(n=1):
        """
        Select and print stack frame that called this one.
        An argument says how many frames up to go.
        """
        f = gdb.selected_frame()

        for i in range(n):
            o = f.older()
            if o:
                o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()

    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def down(n=1):
        """
        Select and print stack frame called by this one.
        An argument says how many frames down to go.
        """
        f = gdb.selected_frame()

        for i in range(n):
            o = f.newer()
            if o:
                o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()


class hopper(gdb.Function):
    """
    Return a value from Hopper that can be used in
    native GDB expressions.
    """
    def __init__(self):
        super(hopper, self).__init__('hopper')
    def invoke(self, name):
        return pwndbg.hopper.LocByName(name.string())

hopper()
