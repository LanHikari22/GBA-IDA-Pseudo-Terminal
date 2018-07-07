import idaapi
idaapi.require("miscUtils")
idaapi.require("disasmUtils")
idaapi.require("TerminalModule")
idaapi.require("Definitions.Environment")
from Definitions import Environment
import miscUtils
import disasmUtils
import TerminalModule


class PseudoTerminal(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] pt (main terminal)'):
        # the module itelf also has a summary format, this is created by TerminalModule
        super(PseudoTerminal, self).__init__(fmt)

        # eaach commznd in the module is added to the module help, and its __doc__ is
        # given the member alias help instead
        self.registerCommand(self, self.help, "help", "<command/module>")
        self.registerCommand(self, self.fmt, "fmt", "<command/module>")
        self.registerCommand(self, self.echo, "echo", "<msg>")
        self.registerCommand(self, self.clear, "clear", "")
        self.registerCommand(self, self.env, "env",  "<key>=<val>,...")
        self.registerCommand(self, self.clrenv, "clrenv", "")

        # __init__ of modules should set up things similarly to pt
        self.dis = disasmUtils.dis()
        self.registerHelp(self, self.help(self) + self.fmt(self.dis) + '\n')
        self.misc = miscUtils.misc()
        self.registerHelp(self, self.help(self) + self.fmt(self.misc) + '\n')


    @staticmethod
    def echo(msg):
        # type: (str) -> None
        """
        simply echos a message to the terminal
        :param msg: message to echo
        """
        print(msg)

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