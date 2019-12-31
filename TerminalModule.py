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
        self.registerSelfCommands()

    def __str__(self):
        return self.help(self)

    def registerModule(self, module):
        """
        Adds the module to the list of modules and registers its help
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


    def registerSelfCommands(self):
        command_names = iter([method_name for method_name in dir(self) if callable(getattr(self, method_name))])
        command_names = filter(lambda method_name: type(getattr(self, method_name)) != type, command_names)
        command_names = filter(lambda method_name: not method_name.startswith('_'), command_names)
        command_names = filter(lambda method_name: method_name not in
                                                   ['fmt', 'get', 'cmds', 'registerCommand', 'registerFmt',
                                                    'registerHelp', 'registerModule', 'registerSelfCommands'],
                               command_names)

        for command_name in command_names:
            command_func = getattr(self, command_name)

            # build the command signature
            command_signature = '{}('.format(command_name)
            param_names = command_func.func_code.co_varnames
            param_names = filter(lambda p: p != 'self', iter(param_names))
            for param in param_names:
                command_signature += '{}, '.format(param)
            if command_signature.endswith(', '):
                command_signature = command_signature[:-len(', ')]
            command_signature += ')'

            # get the first line in the documentation of the function, if available
            doc = command_func.__doc__
            if doc == None:
                doc = ''
            else:
                doc_lines = doc.split('\n')
                if len(doc_lines) > 1:
                    doc = doc_lines[1]
                else:
                    doc = ''

            def tabulate(s, n):
                if len(s) >= n:
                    return s + '\t\t'
                return s + ' ' * (n - len(s)) + '\t\t'

            self.registerCommand(command_func,'{sig}{help}'.format(sig=tabulate(command_signature, 70), help=doc))


    def cmds(self):
        output = []
        for cmd in self.commands:
            output.append(self.fmt(cmd))
        return output

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
        gets the docs of a command or module
        :param unit: a command or a module
        :return: the docs for that command or module
        """
        return TerminalModule.helpRecords[unit]