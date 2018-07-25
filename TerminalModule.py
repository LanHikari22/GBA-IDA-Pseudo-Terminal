import idaapi
idaapi.require('Definitions.Environment')

from Definitions import Environment


class TerminalModule:

    # those store records of all registered commands
    helpRecords = {}
    fmtRecords = {}

    def __init__(self, fmt):
        self.registerFmt(self, fmt)
        self.registerHelp(self, fmt + '\n')
        self.commands = []
        self.modules = []

    def __str__(self):
        return self.help(self)

    def registerModule(self, module):
        """
        Adds the module to the list of moudles and registers its help
        :param module: module to register within this module
        :return:
        """
        self.registerHelp(self, self.help(self) + self.fmt(module) + '\n')
        self.modules.append(module)

    def registerCommand(self, cmdf, fmt):
        """
        Registers the command within the specified module, registers help and fmt entries for them,
        and updates the help entry for the module
        :param module: the TerminalModule
        :param cmdf: the command function within the module
        :param fmt: the one-line summary of how to use the command
        """
        help = cmdf.__doc__
        if help == None:
            help = ''
        self.registerHelp(cmdf, help)
        self.registerFmt(cmdf, fmt)
        self.registerHelp(self, self.help(self) + fmt + '\n')
        self.commands.append(cmdf)


    @staticmethod
    def registerHelp(key, help):
        """
        Registers the help message within the terminal help records
        :param key: the key entry (command or module) to register the help for
        :param help: the help message
        """
        TerminalModule.helpRecords[key] = help

    @staticmethod
    def registerFmt(key, fmt):
        """
        Registers the one-summary line for the module/commmand
        :param key: the module/command being registered
        :param fmt: its format string
        """
        TerminalModule.fmtRecords[key] = fmt

    @staticmethod
    def get(key):
        """
        Gets the variable value from the vars class dictionary, if set
        :param key: the variable to get from the Environment (Definitions/Environment)
        :return: the value of the variable
        """
        if key in Environment.env:
            return Environment.env[key]
        else:
            return None

    @staticmethod
    def fmt(unit):
        """
        :param unit: either a command, or a module
        :return: one-line summary of command or module
        """
        return TerminalModule.fmtRecords[unit]

    @staticmethod
    def help(unit):
        """
        :param unit: a command or a module
        :return: the docs for that command or module
        """
        return TerminalModule.helpRecords[unit]
