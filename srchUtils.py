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

        self.registerCommand(self, self.nextarm, "nextarm", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextascii, "nextascii", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextfakeinst, "nextfakeinst", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextname, "nextname", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextknown, "nextknown", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextred, "nextred", "<search_ea> [ui=True]")
        self.registerCommand(self, self.nextbin, "nextbin", "<search_ea> [ui=True]")

        # figure out the very last ea reachable
        self.end_ea = 0
        for seg in idautils.Segments():
            if idc.SegEnd(seg) > self.end_ea:
                self.end_ea = idc.SegEnd(seg)


    def nextarm(self, ea, ui=True):
        # type: (int) -> str
        """
        Finds the next ARM item, which has a Segment register value 'T' of 0
        :param ea: address to start searching from
        :param ui: if True, jump to address automatically
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

    def nextascii(self, ea, ui=True):
        # type: (int) -> str
        """
        returns the next data item containing ascii characters (seems valid for utf too)
        :param ea: the address to start searching from
        :param ui: if True, jump to address automatically
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
        if ui: idaapi.jumpto(output)
        return '%07X' % output

    def nextfakeinst(self, ea, ui=True):
        # type: (int) -> str
        """
        returns the next code item which is registered as a potential fake instruction.
        Those may also be redundant instructions, which get encoded differently outside of IDA
        the found instructions may also be pure data
        :param ea: address to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted ea
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if d.isCode() and d.getContent() in self._getFakeInstructions():
                output = ea
                break
            ea += d.getSize()
        # trigger the gui to jump to the hypothetical next fake instruction
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    @staticmethod
    def _getFakeInstructions():
        """
        a list of detected instructions with different encoding using arm-none-eabi gcc
        :return: list of opcodes
        """
        # TODO: super clumsy, remove this with logical detection
        return [0x0, 0x1, 0x3, 0x4, 0x09, 0xA, 0x19, 0x1B, 0x1C00, 0x1C1B, 0x1F9B, 0x4425]


    def nextname(self, ea, ui=True):
        """
        Finds the next ea with which a name exists
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
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
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    def nextknown(self, ea, ui=True):
        """
        Finds the next ea with which a name exists
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
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
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    def nextbin(self, ea, ui=True):
        """
        Finds the next big blob of data. The heuristic is it has to be at least sizeLimitHeuristic in size
        UI jumps to start_ea automatically.
        :param ea: ea to search from
        :param ui: if True, jump to address automatically
        :return: tuple hex format of the bin range and the size: (%07X, %07X, 0x$X)
        """
        sizeLimitHeuristic = 0x1000

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

            if not d.isCode():
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
                    if size >= sizeLimitHeuristic:
                        state = st_end
                    else:
                        state = st_start
                if state == st_end:
                    end_ea = ea
                    break

            ea += d.getSize()
        idaapi.jumpto(start_ea)
        return '0x%07X, 0x%07X, 0x%X' % (start_ea, end_ea, size)

    def nextred(self, ea, ui=True):
        """
        Looks for code items outside function items. The first detected is returned
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if d.isCode() and not Function.isFunction(d.ea):
                output = ea
                break
            ea += d.getSize()
        if ui: idaapi.jumpto(ea)
        return '%07X' % output


