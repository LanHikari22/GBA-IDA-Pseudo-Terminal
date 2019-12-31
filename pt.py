from Definitions import Environment
import TerminalModule

import DisasmTools.Terminal
import MiscTools.Terminal
import FixTools.Terminal
import SrchTools.Terminal
import time

class PseudoTerminal(TerminalModule.TerminalModule, object):
    """
    Contains all of the other terminal modules, as well as essential commands
    """
    def __init__(self, fmt='[+] pt (main terminal)'):
        # the module itelf also has a summary format, this is created by TerminalModule
        super(PseudoTerminal, self).__init__(fmt)

        try:
            # each command in the module is added to the help and fmt records
            self.registerCommand(self.help, "help (command/module)")
            self.registerCommand(self.fmt, "fmt (command/module)")
            self.registerCommand(self.echo, "echo (msg)")
            self.registerCommand(self.time, "time (func, func_args)")
            self.registerCommand(self.clear, "clear (n=32)")
            self.registerCommand(self.env, "env (key=Val)")
            self.registerCommand(self.clrenv, "clrenv ()")

            # __init__ of modules should set up things similarly to pt
            self.dis = DisasmTools.Terminal.DisTerminal()
            self.srch = SrchTools.Terminal.SrchTerminal()
            self.fix = FixTools.Terminal.fix()
            self.misc = MiscTools.Terminal.MiscTerminal()
            self.registerModule(self.dis)
            self.registerModule(self.srch)
            self.registerModule(self.fix)
            self.registerModule(self.misc)
            self._initialized = True
        except Exception as e:
            print(e)
            self._initialized = False

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

def main():
    # ida caches source. In active development, this forces it to re-read source
    import os
    import sys
    if os.getcwd() not in sys.path: sys.path.append(os.getcwd())

    import idaapi
    import Definitions, DisasmTools, FixTools, IDAItems, MiscTools, SrchTools

    def require_project():
        Definitions.require_package()
        DisasmTools.require_package()
        FixTools.require_package()
        IDAItems.require_package()
        MiscTools.require_package()
        SrchTools.require_package()

    import imp
    require_project()

    # if environment_path:
    #     environment = imp.load_source('environment', environment_path)
    #     environment = environment.MyClass()

    global pt
    pt = PseudoTerminal()
    if pt._initialized:
        pt.echo("PseudoTerminal, ready for combat!")
    else:
        print('Initalized Environment to Default')


if __name__ == '__main__':
    main()

