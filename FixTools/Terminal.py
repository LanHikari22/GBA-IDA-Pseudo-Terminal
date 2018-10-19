# @file fixTools
# utilities for automatic fixing go here!
import idaapi
import idautils

from SrchTools import srchTools, nextTools

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

from FixTools import fixTools
import idc
from IDAItems import Function, Data, InstDecoder
import TerminalModule

class fix(TerminalModule.TerminalModule, object):
    """
    This module contains tools to run on the database to fix problems all throughout the database
    or over a range
    """
    def __init__(self, fmt='[+] fix (emergency room tools for your IDB)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(fix, self).__init__(fmt)

        # register commands
        self.remFuncChunks = fixTools.remFuncChunks
        self.replNameParen = fixTools.replNameParen
        self.markRedundantInsts = fixTools.markRedundantInsts
        self.makeThumb = fixTools.makeThumb
        self.changeASCII = fixTools.changeASCII
        self.removeText = fixTools.removeText
        self.removeStackVarUsages = fixTools.removeStackVarUsages
        self.makeUnkPushFuncs = fixTools.makeUnkPushFuncs
        self.fixFunctionRanges = fixTools.fixFunctionRanges
        self.removeFakeRedCode = fixTools.removeFakeRedCode
        self.removeRedCode = fixTools.removeRedCode
        self.registerCommand(self.remFuncChunks, "remFuncChunks ()")
        self.registerCommand(self.replNameParen, "replNameParen ()")
        self.registerCommand(self.markRedundantInsts, "markRedundantInsts (start_ea, end_ea)")
        self.registerCommand(self.makeThumb, "makeThumb (start_ea, end_ea)")
        self.registerCommand(self.changeASCII, "changeASCII (start_ea, end_ea)")
        self.registerCommand(self.removeText, "removeText (start_ea, end_ea)")
        self.registerCommand(self.removeStackVarUsages, "removeStackVarUsages (start_ea, end_ea)")
        self.registerCommand(self.makeUnkPushFuncs, "makeUnkPushFuncs (start_ea, end_ea)")
        self.registerCommand(self.fixFunctionRanges, "fixFunctionRanges (start_ea, end_ea)")
        self.registerCommand(self.removeFakeRedCode, "removeFakeRedCode (start_ea, end_ea)")
        self.registerCommand(self.removeRedCode, "removeRedCode (start_ea, end_ea)")
