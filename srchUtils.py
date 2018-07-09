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

        # figure out the very last ea reachable
        self.end_ea = 0
        for seg in idautils.Segments():
            if idc.SegEnd(seg) > self.end_ea:
                self.end_ea = idc.SegEnd(seg)


    def nextarm(self, ea=idc.here()):
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