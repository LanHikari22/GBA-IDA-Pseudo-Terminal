# @file miscTools
# whatever utilities go here! sometimes for testing, sometimes for convenience!

import idaapi
import idautils
import idc_bc695

from Definitions.Environment import env

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")
idaapi.require("SrchTools.nextTools")
from Definitions import Architecture, Paths
import idc
from IDAItems import Function, Data
import TerminalModule
import SrchTools.nextTools

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

        self.registerCommand(self.gendocs, "gendocs(terminalModule)")
        self.registerCommand(self.test, "test(_)")
        self.registerCommand(self.ea2gf, "ea2gf(ea)")
        self.registerCommand(self.sizeTillName, "sizeTillName(ea, blockSize=1)")
        self.registerCommand(self.getLZ77CompressedSize, "getLZ77CompressedSize(compressed_ea)")
        self.registerCommand(self.findMostUsedFunctions, "findMostUsedFunctions(count, notModified=False, disp=True)")
        self.registerCommand(self.fnrepl, "fnrepl(start_ea, end_ea, oldstr, newstr)")
        self.registerCommand(self.plcv, "plcv(ea)")
        self.registerCommand(self.nlrepl, "nlrepl(oldStr, newStr)")
        self.registerCommand(self.rngmkd, "rngmkd(start_ea, end_ea)")

    @staticmethod
    def test(n):
        """
        This is just a scratchpad!
        :param n:
        :return:
        """
        idc.get_color(here(), )

    @staticmethod
    def ea2gf(ea):
        # type: (int) -> str
        """
        Return the game file the ea belongs to
        :param ea: the linear address to find the file it belongs to
        :return: the game file name
        """
        gameFiles = env.get('gameFiles')
        output = None
        if not gameFiles:
            print('ERROR: environmental variable for gameFiles required')
            return None
        for file in gameFiles:
            if gameFiles[file][0] <= ea < gameFiles[file][1]:
                output = file
                break
        return output

    @staticmethod
    def getLZ77CompressedSize(compressed_ea):
        """
        Iterates the compressed data, and returns its size
        :param compressed_ea: the linear address of the compressed data
        :return: its size in bytes or -1 if this is an invalid format (compression type not 1)
        """
        dataHeader = 0
        chars = idc.get_bytes(compressed_ea, 4)
        for i in range(len(chars)):
            dataHeader |= ord(chars[i]) << 8*i
        decompSize = (dataHeader & ~0xFF) >> 8

        # compression type must match
        if (dataHeader & 0xF0) >> 4 != 1:
            return -1

        print('decompressed size: 0x%X' % decompSize)

        # iterate, and figure out the number of bytes copied
        size = 0
        ea = compressed_ea + 4
        # iterate the blocks and keep count of the data size
        while size < decompSize:
            # parse block flags (compressed or not)
            flags = ord(idc.get_bytes(ea, 1))
            ea += 1

            # iterate the blocks, MSB first.
            for i in range(7, -1, -1):
                if flags & (1<<i):
                    # block i is compressed
                    chars = idc.get_bytes(ea, 2)
                    block = ord(chars[0]) + (ord(chars[1]) << 8)
                    size += ((block & 0xF0) >> 4) + 3
                    ea += 2
                else:
                    # block i is uncompressed, it's just one byte
                    size += 1
                    ea += 1
                # we might finish decompressing while processing blocks
                if size >= decompSize:
                    break
        return ea-compressed_ea

    @staticmethod
    def sizeTillName(ea, blockSize=1):
        """
        :param ea: linear address to start searching from
        :param blockSize: the size of the blocks to be counted, a word is 4, a byte is 1.
        :return: the number of blocks till the next name appears
        """
        next = SrchTools.nextTools.next()
        return (next.name(ea, ui=False, hexOut=False) - ea) / blockSize

    @staticmethod
    def findMostUsedFunctions(count, notModified=False, disp=True):
        # type: (int, bool, bool) -> list[int]
        """
        Returns the functions with the highest count of xrefsTo. if notModified, only those that are in the format
        *_xxxxxxx are returned. if disp, the output is formatted and printed as well
        :param count: the number of the most used functions to find
        :param notModified: only functions with names ending in func_ea, or all functions
        :param disp: print the output
        :return: list of function linear addresses to the most used functions
        """
        funcXrefs = []
        if count <= 0: count = 1
        for i in range(count):
            funcXrefs.append((0,0))
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc_bc695.SegEnd(seg_ea)):
                if notModified:
                    name = Function.Function(func_ea).getName()
                    if not( '_' in name and name[name.rindex('_'):] == ('_%X' % func_ea)):
                        continue
                xrefs = Function.Function(func_ea).getXRefsTo()
                numXrefs = len(xrefs[0]) + len(xrefs[1])
                if numXrefs > funcXrefs[0][1]:
                    funcXrefs[0] = (func_ea, numXrefs)
                    funcXrefs = sorted(funcXrefs, key=lambda tup: tup[1])

        if disp:
            for func_ea, xrefCount in funcXrefs:
                print('%s: %d' % (Function.Function(func_ea).getName(), xrefCount))

        output = []
        for func_ea, xrefCount in funcXrefs:
            output.append(func_ea)
        return output

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
            # only show the initial message, not the parameter descriptions
            help = self.help(c).strip()
            if ':' in help:
                help = help[:help.index(':')]
            md += "- `%s` %s\n" % (self.fmt(c), help)
        # do the same for every module
        for m in mod.modules:
            md += self.gendocs(m)
        return md

