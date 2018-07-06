import idaapi
idaapi.require('Definitions.Environment')

from Definitions import Environment


class TerminalModule:
    def __init__(self, fmt):
        self.fmt = fmt
        self.help = self.fmt + '\n'

    def cmds(self):
        """
        :return: list of all commands that can be executed from the module
        """
        for member in dir(self):
            pass

    def modules(self):
        """
        :return: list of all command modules found within the module
        """
        pass

    @staticmethod
    def _get_format(name, func):
        """
        adds the command to __docs__ of pt
        :param name: name of the command
        :param func: the command function to obtain __fmt__ from it
        :return:
        """
        return name + ' ' + func.fmt

    @staticmethod
    def registerCommand(module, cmdf, name, fmt):
        """
        Registers the command within the specified module, and assigns help and fmt members to it
        :param module: the TerminalModule
        :param cmdf: the command function within the module
        :param name: the name of the command
        :param fmt: the one-line summary of how to use the command
        """
        cmdf.help = cmdf.__doc__
        cmdf.fmt = fmt
        module.help += module._get_format(name, cmdf) + '\n'


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
