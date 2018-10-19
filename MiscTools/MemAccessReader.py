import idaapi

from IDAItems import Function, Data

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

import TerminalModule

class MemAccessReader:
    """
    This contains search tools for items and conditions found in the database, as well as binary files and
    comparisons
    """
    def __init__(self):
        self.accesses = []
        self.funcs = []
        self.data = []

    def read(self, accesses_path):
        # type: (str) -> None
        """
        Reads in the memory accesses defined by the MemAccessScanner protocol
        :param accesses_path: path to a file containing the accesses
        :return:
        """
        f = open(accesses_path, "r")
        s = f.read()
        items = s.split(' ')
        self.accesses = []
        for i in range(len(items)):
            if '::' in items[i]:
                access_ea = int(items[i][items[i].index('::')+2:], 16)
                access = items[i+1][:-1]
                self.accesses.append((access_ea, access))
        self.accesses.sort(key=lambda tup: tup[0])

        for access_ea, access in self.accesses:
            if Function.isFunction(access_ea):
                func_ea = Function.Function(access_ea).func_ea
                if func_ea not in self.funcs:
                    self.funcs.append(func_ea)
            else:
                data_ea = Data.Data(access_ea).ea
                if data_ea not in self.data:
                    self.data.append(data_ea)
        self.funcs.sort()
        self.data.sort()

        f.close()

    def formatAccessSources(self):
        # type: () -> str
        output = ''
        if self.funcs:
            output += 'Functions:\n'
            for func_ea in self.funcs:
                output += '\t%07X <%s>\n' % (func_ea, Function.Function(func_ea).getName())
        if self.data:
            output += 'Data:\n'
            for data_ea in self.data:
                output += '\t%07X <%s>\n' % (data_ea, Data.Data(data_ea).getName())
        return output