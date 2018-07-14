import time
import idaapi
idaapi.require("miscUtils")
idaapi.require("disasmUtils")
idaapi.require("fixUtils")
idaapi.require("srchUtils")
idaapi.require("TerminalModule")
idaapi.require("Definitions.Environment")
from Definitions import Environment
import miscUtils
import disasmUtils
import TerminalModule
import fixUtils
import srchUtils



class PseudoTerminal(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] pt (main terminal)'):
        # the module itelf also has a summary format, this is created by TerminalModule
        super(PseudoTerminal, self).__init__(fmt)

        # each command in the module is added to the help and fmt records
        self.registerCommand(self, self.help, "help", "<command/module>")
        self.registerCommand(self, self.fmt, "fmt", "<command/module>")
        self.registerCommand(self, self.echo, "echo", "<msg>")
        self.registerCommand(self, self.time, "time", "<func> <func_args>")
        self.registerCommand(self, self.clear, "clear", "")
        self.registerCommand(self, self.env, "env",  "<key>=<val>,...")
        self.registerCommand(self, self.clrenv, "clrenv", "")

        # __init__ of modules should set up things similarly to pt
        self.dis = disasmUtils.dis()
        self.registerHelp(self, self.help(self) + self.fmt(self.dis) + '\n')
        self.misc = miscUtils.misc()
        self.registerHelp(self, self.help(self) + self.fmt(self.misc) + '\n')
        self.fix = fixUtils.fix()
        self.registerHelp(self, self.help(self) + self.fmt(self.fix) + '\n')
        self.srch = srchUtils.srch()
        self.registerHelp(self, self.help(self) + self.fmt(self.srch) + '\n')



    @staticmethod
    def echo(msg):
        # type: (str) -> None
        """
        simply echos a message to the terminal
        :param msg: message to echo
        """
        print(msg)

    @staticmethod
    def time(func, *args, **kwargs):
        """
        Calls and times the passed in function in ms
        :param func: the function to call and time
        :param args: arguments to the function
        :param kwargs: keyworded arguments to the function
        :return: what the called function returns
        """
        stopwatch_ms = int(round(time.time()*1000))
        output = func(*args, **kwargs)
        stopwatch_ms = int(round(time.time()*1000)) - stopwatch_ms
        print("Execution time: %s ms" % (stopwatch_ms))
        return output

    @staticmethod
    def clear(n=32):
        """
        prints n new lines
        """
        if n < 0: n = 0
        for i in range(n): print('')

    @staticmethod
    def env(**kwargs):
        """
        changes the value of an environmental variable within pt.
        Those environmental variables are used by other commands and modules, and must be configured

        :param kwargs: key, value pairs to assign as variables within pt
        """
        for key in kwargs.keys():
            # only set it if the key actually already exiasts
            if key in Environment.env:
                Environment.env[key] = kwargs[key]
            else:
                raise KeyError("key %s was not found in the Definitions/Environment.py" % key)

    @staticmethod
    def clrenv():
        """
        sets the Environment back to its original state
        """
        for key in Environment.env.keys():
            if type(Environment.env[key]) == str:
                Environment.env[key] = ''
            else:
                Environment.env[key] = None





if __name__ == '__main__':
    pt = PseudoTerminal()
    pt.echo("PseudoTerminal, ready for combat!")