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

        self.registerCommand(self, self.nextarm, "nextarm", "<search_ea>")
        self.registerCommand(self, self.nextascii, "nextascii", "<search_ea>")
        self.registerCommand(self, self.nextfakeinst, "nextfakeinst", "<search_ea>")
        self.registerCommand(self, self.nextname, "nextname", "<search_ea>")
        self.registerCommand(self, self.nextknown, "nextknown", "<search_ea>")
        self.registerCommand(self, self.nextbin, "nextbin", "<search_ea>")

        # figure out the very last ea reachable
        self.end_ea = 0
        for seg in idautils.Segments():
            if idc.SegEnd(seg) > self.end_ea:
                self.end_ea = idc.SegEnd(seg)


    def nextarm(self, ea):
        # type: (int) -> str
        """
        Finds the next ARM item, which has a Segment register value 'T' of 0
        :param ea: address to start searching from
        :return: the address (in str) of the next ARM instruction
        """
        # don't count this item
        ea += Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # detect next code32
            if idc.GetReg(ea, 'T') == 0:
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def nextascii(self, ea):
        # type: (int) -> str
        """
        returns the next data item containing ascii characters (seems valid for utf too)
        :param ea: the address to start searching from
        :return: hex formatted str of the address of the next ascii item
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if idc.isASCII(d._getFlags()):
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def nextfakeinst(self, ea):
        # type: (int) -> str
        """
        returns the next code item which has a content value <= 0xFF.
        those are likely (but not always) to be actually data.
        :param ea: address to start searching from
        :return: hex formatted ea
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if d.isCode() and d.getContent() <= 0xFF:
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def nextname(self, ea):
        """
        Finds the next ea with which a name exists
        :param ea: ea to start searching from
        :return: hex formatted ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if d.getName():
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def nextknown(self, ea):
        """
        Finds the next ea with which a name exists
        :param ea: ea to start searching from
        :return: hex formatted ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if not idc.isUnknown(d._getFlags()):
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def nextbin(self, ea):
        """
        Finds the next big blob of data. The heuristic is it has to be at least 0x1000 in size
        :param ea: ea to search from
        :return: tuple hex format of the bin range: (%07X, %07X)
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()

        # range params
        start_ea = idaapi.BADADDR
        end_ea = idaapi.BADADDR
        size = 0

        # state machine of finding range
        st_start = 0
        st_traverse = 1
        st_end = 2
        state = st_start

        while ea < self.end_ea:
            d = Data.Data(ea)

            if d.isData():
                if state == st_start:
                    start_ea = ea
                    size = 0
                    state = st_traverse
                if state == st_traverse:
                    size += d.getSize()
                if state == st_end:
                    raise(Exception('entered invalid state'))

            if d.isCode():
                # only end if valid size
                if state == st_traverse:
                    if size >= 0x1000:
                        state = st_end
                    else:
                        state = st_start
                if state == st_end:
                    end_ea = ea
                    break

            ea += d.getSize()
        return '%07X, %07X' % (start_ea, end_ea)

    def nextstkfunc(self, ea):
        # type: (int) -> str
        """
        Finds the next function that uses stack variables
        :param ea: the current address to search from
        :return: hex formatted ea of next stack function
        """
        raise(NotImplemented())