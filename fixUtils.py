# @file fixUtils
# utilities for automatic fixing go here!
import idaapi
import idautils

import srchUtils

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

from Definitions import Architecture, Paths

import idc
from IDAItems import Function, Data
import TerminalModule


class fix(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] fix (emergency room utils for your IDB)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(fix, self).__init__(fmt)

        self.registerCommand(self, self.remFuncChunks, "remFuncChunks", "")
        self.registerCommand(self, self.replNameParen, "replNameParen", "")
        self.registerCommand(self, self.markRedundantInsts, "markRedundantInsts", "<start_ea> <end_ea>")
        self.registerCommand(self, self.makeThumb, "makeThumb", "<start_ea> <end_ea>")
        self.registerCommand(self, self.changeASCII, "changeASCII", "")

    @staticmethod
    def remFuncChunks():
        """
        deletes all functions that have function chunks in them
        and appends "function_chunks_" to their names
        """
        foundProblem = False
        for seg in idautils.Segments():
            for ea in idautils.Functions(start=idc.SegStart(seg),end=idc.SegEnd(seg)):
                f = idaapi.get_func(ea)
                # chunk f
                if f.tailqty > 0:
                    foundProblem = True
                    print("Removing chunk function @ %07X" % f.startEA)
                    idaapi.del_func(f.startEA)
                    name = idc.Name(f.startEA)
                    if "function_chunks_" not in name:
                        newName = 'function_chunks_%s' % name
                        print("Renaming %s -> %s" % ((name, newName)))
                        idc.MakeName(f.startEA, newName)

        if foundProblem:
            print("Removed all function chunks!")
        else:
            print("No function chunks detected!")

    def replNameParen(self):
        """
        IDA treats the presence of a paranthesis as '_'. But visually still shows '_'.
        Just replace all of those '(' and ')'s with an actual '_'
        :return:
        """
        fixedName = False
        for ea, name in idautils.Names():
            newName = name
            if '(' in name:
                newName = newName.replace('(', '_')
            if ')' in name:
                newName = newName.replace(')', '_')

            if newName != name:
                fixedName = True
                print('%07X: Replacing %s -> %s...' % (ea, name, newName))
                idc.MakeName(ea, newName)
        if fixedName:
            print("Finished replacing all parenthesis!")
        else:
            print("No parenthesis found to fix!")

    @staticmethod
    def markRedundantInsts(start_ea, end_ea):
        """
        Some instructions, like add r0, r0, #0 can be optimized to add r0, #0 by assemblers.
        This gets in the way of disassembly. This attempts to fix that by replacing all such occurrances with
        purely their data format, and it also adds a comment on that line specifying the original inst.
        :param start_ea: start address of the marking
        :param end_ea: end address of the marking
        """
        ea = start_ea
        while ea < end_ea:
            d = Data.Data(ea)
            if d.isCode() and 'mkdata' not in d.getName():
                redundant = True
                # MOVS R3, R3
                content = d.getContent()
                if content == 0x1B:
                    print("%07X: mkdata (MOVS R3, R3)" % (ea))
                elif content == 0x09:
                    print("%07X: mkdata (MOVS R1, R1)" % (ea))
                elif content == 0x1C00:
                    print("%07X: mkdata (ADDS R0, R0, #0)" % (ea))
                else:
                    redundant = False

                if redundant:
                    name = d.getName()
                    if name:
                        name = 'mkdata_' + name
                    else:
                        name = 'mkdata_%X' % ea
                    print("Renaming '%s'-> '%s'" % (d.getName(), name))
                    idc.MakeName(ea, name)
            ea += d.getSize()

    @staticmethod
    def makeThumb(start_ea, end_ea):
        """
        Changes all ARM within the specified range to THUMB
        :param ea: the address to start from
        """
        srch = srchUtils.srch()
        ea = int(srch.nextarm(start_ea), 16)
        foundARM = False
        while ea <= end_ea:
            foundARM = True
            # fix arm to thumb
            print("%07X: Changing to THUMB mode" % ea)
            idc.SetRegEx(ea, "T", 1, idc.SR_user)
            ea = int(srch.nextarm(ea), 16)
        if foundARM:
            print("Successfully changed ARM modes to THUMB!")
        else:
            print("no ARM instruction found!")

    @staticmethod
    def changeASCII():
        """
        finds all ascii named data and changes it to bytes and removes its name
        """
        found = False
        for ea, name in idautils.Names():
            d = Data.Data(ea)
            if idc.isASCII(d._getFlags()):
                found = True
                print("%07X: Make ASCII -> Byte" % ea)
                idc.MakeByte(ea)
                idc.MakeName(ea, '')


        if found:
            print("changed all ASCII data to byte data!")
        else:
            print("no ASCII data was found!")