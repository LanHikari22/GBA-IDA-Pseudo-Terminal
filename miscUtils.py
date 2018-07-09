# @file miscUtils
# whatever utilities go here! sometimes for testing, sometimes for convenience!
import idaapi
idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

from Definitions import Architecture, Paths
import idc
from IDAItems import Function, Data
import TerminalModule


class misc(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] misc (tools of all kind)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(misc, self).__init__(fmt)

        self.registerCommand(self, self.test, "test", "...")
        self.registerCommand(self, self.fnrepl, "fnrepl", "<start_ea> <end_ea> <oldstr> <newstr>")
        self.registerCommand(self, self.plcv, "plcv", "<ea>")

    @staticmethod
    def test(ea):
        f = Function.Function(ea)
        print(f.getStackVarDisasm())

    @staticmethod
    def removeFuncChunks(start_ea, end_ea):
        """
        deletes all functions that have function chunks in them
        and appends "function_chunks_" to their names
        :param start_ea: start of the range to remove function chunks in
        :param end_ea: end of the range to remove function chunks in
        """
        ea = start_ea
        while ea < end_ea:
            if Function.isFunction(ea):
                f = idaapi.get_func(ea)
                # chunk f
                if f.tailqty > 0:
                    print("Removing chunk function @ %07X" % f.startEA)
                    idaapi.del_func(f.startEA)
                    name = idc.Name(f.startEA)
                    newName = 'function_chunks_%s' % name
                    print("Renaming %s -> %s" % ((name, newName)))
                    idc.MakeName(f.startEA, newName)
                    ea += idc.get_item_size(ea)
                else:
                    f = Function.Function(ea)
                    ea += f.getSize(withPool=True)
            else:
                ea += Data.Data(ea).getSize()
        print("Removed all function chunks!")



    @staticmethod
    def fnrepl(start_ea, end_ea, oldstr, newstr, log=True):
        """
        replace a string if detected in the names of all functions within range
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
        :return: list of bytes representing the content read
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
        bytes = []
        for char in data: bytes.append(ord(char))
        return bytes