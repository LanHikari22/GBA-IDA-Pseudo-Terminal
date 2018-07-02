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

