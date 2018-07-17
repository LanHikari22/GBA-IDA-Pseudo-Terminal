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
        self.registerCommand(self, self.removeStackVarUsages, "removeStackVarUsages", "<start_ea> <end_ea>")

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

        To specify that a data item has to be forced to data, this puts <mkdata> in its comment.
        :param start_ea: start address of the marking
        :param end_ea: end address of the marking
        """
        ea = start_ea
        while ea < end_ea:
            d = Data.Data(ea)
            if d.isCode() and '<mkdata>' not in d.getComment():
                redundant = True
                # MOVS R3, R3
                content = d.getContent()
                if d.getContent() in srchUtils.srch._getFakeInstructions():
                    print("%07X: <mkdata>" % (ea))
                else:
                    redundant = False

                if redundant:
                    cmt = d.getComment()
                    if cmt:
                        cmt = '<mkdata> ' + cmt
                    else:
                        cmt = '<mkdata>'
                    d.setComment(cmt)
            ea += d.getSize()


    @staticmethod
    def makeThumb(start_ea, end_ea):
        """
        Changes all ARM within the specified range to THUMB
        :param ea: the address to start from
        :return: False if no instruction found, else True
        """
        srch = srchUtils.srch()
        ea = int(srch.nextarm(start_ea, ui=False), 16)
        foundARM = False
        while ea <= end_ea:
            foundARM = True
            # fix arm to thumb
            print("%07X: Changing to THUMB mode" % ea)
            idc.SetRegEx(ea, "T", 1, idc.SR_user)
            ea = int(srch.nextarm(ea, ui=False), 16)
        if foundARM:
            print("Successfully changed ARM modes to THUMB!")
            return True
        else:
            print("No ARM Instructions in range [%7X, %7X) found!" % (start_ea, end_ea))
            return False

    @staticmethod
    def changeASCII(start_ea, ):
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

    @staticmethod
    def removeStackVarUsages(self_ea, end_ea):
        madeChanges = False
        for func_ea in idautils.Functions(self_ea, end_ea):
            changedStackVar = False
            if Function.hasStackVars(func_ea):
                stackVars = Function.getStackVars(func_ea)
                # traverse data items of function and op_bin all
                ea = func_ea
                while ea < func_ea + Function.Function(func_ea).getSize(withPool=False):
                    d = Data.Data(ea)
                    for name, off in stackVars:
                        if name != ' s' and name in d.getOrigDisasm():
                            changedStackVar = True
                            if not madeChanges: madeChanges = True
                            idc.op_hex(d.ea, 1)
                    ea += d.getSize()
                if changedStackVar:
                    print('%07X: stackvars op -> hex' % func_ea)
        if madeChanges:
            print("Removed all stack variable usages!")
        else:
            print("No stack variable usages to remove!")

