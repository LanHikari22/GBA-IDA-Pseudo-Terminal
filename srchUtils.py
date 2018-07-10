# @file srchUtils
# utilities for searching for things in the IDB, as well as in binaries (and against the IDB) go here!
import idaapi
import idautils

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

from Definitions import Architecture, Paths

import idc
from IDAItems import Function, Data
import TerminalModule


class srch(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] srch (IDB/binary searching utils)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(srch, self).__init__(fmt)

        self.registerCommand(self, self.nextarm, "nextarm", "[searchStartEA]")
        self.registerCommand(self, self.nextascii, "nextascii", "[searchStartEA]")
        # figure out the very last ea reachable
        self.end_ea = 0
        for seg in idautils.Segments():
            if idc.SegEnd(seg) > self.end_ea:
                self.end_ea = idc.SegEnd(seg)


    def nextarm(self, ea=idc.here()):
        # type: (int) -> str
        """
        Finds the next ARM instruction
        :param ea: address to start searching from
        :return: the address (in str) of the next ARM instruction
        """
        # don't count this item
        ea += Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if d.isCode() and d.getSize() == 4:
                if d.getOrigDisasm()[0] != 'B':
                    output = ea
                    break
            ea += d.getSize()
        return '%07X' % output

    def nextascii(self, ea=idc.here()):
        # type: (int) -> str
        """
        returns the next data item containing ascii characters (seems valid for utf too)
        :param ea: the address to start searching from
        :return: hex formatted str of the address of the next ascii item
        """
        # don't count this item
        ea += Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if idc.isASCII(d._getFlags()):
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output
