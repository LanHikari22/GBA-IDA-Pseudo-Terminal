# @file miscTools
# whatever utilities go here! sometimes for testing, sometimes for convenience!

import idaapi
import idautils

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

from Definitions import Architecture, Paths
import idc
from IDAItems import Function, Data
import TerminalModule


class misc(TerminalModule.TerminalModule, object):
    """
    Different kinds of commands and tools go here. No label. Just take a look, OK?
    """
    def __init__(self, fmt='[+] misc (tools of all kind)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(misc, self).__init__(fmt)

        self.registerCommand(self.gendocs, "gendocs (terminalModule)")
        self.registerCommand(self.test, "test (_)")
        self.registerCommand(self.fnrepl, "fnrepl (start_ea, end_ea, oldstr, newstr)")
        self.registerCommand(self.plcv, "plcv (ea)")
        self.registerCommand(self.nlrepl, "nlrepl (oldStr, newStr)")
        self.registerCommand(self.rngmkd, "rngmkd (start_ea, end_ea)")

    @staticmethod
    def test(n):
        """
        This is just a scratchpad!
        :param n:
        :return:
        """
        idc.get_color(here(), )

    @staticmethod
    def fnrepl(start_ea, end_ea, oldstr, newstr, log=True):
        """
        replace a string once if detected in the names of all functions within range
        :param start_ea: start of the range
        :param end_ea: end of the range
        :param oldstr: string to replace
        :param newstr: replacement string
        """
        ea = start_ea
        while ea < end_ea:
            if Function.isFunction(ea):
                f = Function.Function(ea)
                if oldstr in f.getName():
                    name = f.getName()
                    f.setName(f.getName().replace(oldstr, newstr))
                    if log: print("Renamed %s -> %s" % (name, f.getName()))

                ea += f.getSize(withPool=True)
            else:
                ea += Data.Data(ea).getSize()

    @staticmethod
    def nlrepl(oldstr, newstr, log=True):
        """
        Replaces string from all names in the global name list
        :param oldstr: occurrence to replace
        :param newstr: replaced string
        :param log: True by default, logging messages of what got replaced
        """
        for ea, name in idautils.Names():
            if oldstr in name:
                newName = name.replace(oldstr, newstr, 1)
                if log: print('%07X: Replacing %s -> %s' % (ea, name, newName))
                idc.MakeName(ea, newName)

    @staticmethod
    def plcv(ea):
        # type: (ea, bool) -> str
        """
        Converts pool to linker compatible version

        :param ea: ea of inst
        :param arm: True if arm, false if not. -8/-4 (-2 instructions due to pipeline)
        :return: string with the correct [PC, ...] format
        """
        d = Data.Data(ea)
        disasm = d._getPoolDisasm()
        return disasm

    @staticmethod
    def xrefs2str(xrefs):
        # type: (tuple[list[int], list[int]]) -> str
        """
        prints xref tuples in a good manner, with hex integer numbers in the lists
        """
        return "(" + misc.hexArr(xrefs[0]) + ", " + misc.hexArr(xrefs[1]) + ")"

    @staticmethod
    def hexArr(arr):
        # type: (list[int]) -> str
        """
        :param arr: array of integers
        :return: str representation of the array but with hex numbers instead
        """
        output = '['
        hasElement = False
        for i in arr:
            hasElement = True
            output += "0x%08X, " % i
        if hasElement:
            output = output[0:-2] + ']'
        else:
            output += "]"
        return output

    @staticmethod
    def readROM(ea, size):
        """
        Reads the size bytes of the analysis ROM at the specified address ea
        :param ea: effective address to read at
        :param size: number of bytes to read
        :raises ValueError: if ea < ROM_SEG or if size < 0
        :return: byte string representing the content read
        """
        # type: (int, int) -> list[int]
        if ea < Architecture.ROM_SEG or size < 0:
            raise (ValueError("Invalid ea or size to read"))
        # open binary ROM and go to EA
        fh = open(Paths.ROM_PATH, 'r')
        fh.seek(ea - Architecture.ROM_SEG)

        # read the requested bytes
        data = fh.read(size)
        # sometimes, not all of size is read
        while len(data) < size:
            data += fh.read(size - len(data))

        # close file handler and convert to byte str to bytes
        fh.close()

        return data

    def rngmkd(self, start_ea, end_ea):
        """
        Turns the data in the range to words. If not aligned with words, turns into bytes instead
        :param start_ea: start of the range
        :param end_ea: end of the range
        """
        ea = start_ea
        while ea % 4 != 0:
            print ('%07X: -> byte' % ea)
            idc.MakeByte(ea)
            ea += 1
        while ea < end_ea:
            print ('%07X: -> word' % ea)
            idc.MakeDword(ea)
            ea += 4

    def gendocs(self, mod):
        """
        Actually generates the docs for this file!
        :return: the docs to go to the COMMANDS.md file
        """
        name = self.fmt(mod)[len('[+] '):self.fmt(mod).index(' (')]
        desc = self.fmt(mod)[self.fmt(mod).index('('):]
        md = ''
        if name == 'pt':
            md += "This file contains documentation for all of the modules and commands available " \
             "through the pt (PseudoTerminal) object.\n"
            md += "\n# Main Terminal\n"
        else:
            md += "\n# %s\n" % name
        # display the description for the module
        modHelp = mod.__doc__
        if modHelp == None:
            modHelp = ''
        modHelp = modHelp.strip()
        md += modHelp + '\n'
        # document the modules and commands of this module
        for m in mod.modules:
            name = self.fmt(m)[len('[+] '):self.fmt(m).index(' (')]
            desc = self.fmt(m)[self.fmt(m).index('('):]
            md += "- **%s** %s\n" % (name, desc)
        for c in mod.commands:
            # only show the initial message, not teh parameter descriptions
            help = self.help(c).strip()
            if ':' in help:
                help = help[:help.index(':')]
            md += "- `%s` %s\n" % (self.fmt(c), help)
        # do the same for every module
        for m in mod.modules:
            md += self.gendocs(m)
        return md

