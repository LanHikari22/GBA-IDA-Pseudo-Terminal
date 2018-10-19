import idaapi
idaapi.require("TerminalModule")
idaapi.require("SrchTools.srchTools")
idaapi.require("SrchTools.nextTools")

import TerminalModule
import SrchTools.srchTools
import SrchTools.nextTools

class SrchTerminal(TerminalModule.TerminalModule, object):
    """
    This contains search tools for items and conditions found in the database, as well as binary files and
    comparisons
    """
    def __init__(self, fmt='[+] srch (database/binary search tools)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(SrchTerminal, self).__init__(fmt)

        # register modules
        self.next = SrchTerminal.nextTerminal()
        self.registerModule(self.next)

        # register commands
        self.getSymTable = SrchTools.srchTools.getSymTable
        self.listUpdatedSymbols = SrchTools.srchTools.listUpdatedSymbols
        self.registerCommand(self.getSymTable, "getSymTable(elfPath)")
        self.registerCommand(self.listUpdatedSymbols, "listUpdatedSymbols(elfPath)")


    class nextTerminal(TerminalModule.TerminalModule, object):
        """
        A collection of tools that find the next occurrance of a specific type of item
        """

        def __init__(self, fmt='[+] next (occurrence of something tools)'):
            """
            This module is responsible for printing disassemblies and necessary compoents
            of disassemblies
            """
            super(SrchTerminal.nextTerminal, self).__init__(fmt)

            # include commands
            self.arm = SrchTools.nextTools.arm
            self.ascii = SrchTools.nextTools.ascii
            self.fakeinst = SrchTools.nextTools.fakeinst
            self.name = SrchTools.nextTools.name
            self.known = SrchTools.nextTools.known
            self.bin = SrchTools.nextTools.bin
            self.red = SrchTools.nextTools.red
            self.immref = SrchTools.nextTools.immref
            self.ret = SrchTools.nextTools.ret
            self.unkret = SrchTools.nextTools.unkret
            self.deadfunc = SrchTools.nextTools.deadfunc
            self.fakered = SrchTools.nextTools.fakered
            self.unkptr = SrchTools.nextTools.unkptr

            self.registerCommand(self.arm, "arm(search_ea, ui=True)")
            self.registerCommand(self.ascii, "ascii(search_ea, ui=True)")
            self.registerCommand(self.fakeinst, "fakeinst(search_ea, ui=True)")
            self.registerCommand(self.name, "name(search_ea, ui=True, hexOut=True)")
            self.registerCommand(self.known, "known(search_ea, ui=True)")
            self.registerCommand(self.bin, "bin(search_ea, ui=True)")
            self.registerCommand(self.red, "red(search_ea, ui=True)")
            self.registerCommand(self.immref, "immref(search_ea, ui=True)")
            self.registerCommand(self.ret, "ret(search_ea, ui=True, hexOut=True)")
            self.registerCommand(self.unkret, "unkret(search_ea, ui=True, hexOut=True)")
            self.registerCommand(self.deadfunc, "deadfunc(ea, ui=True, hexOut=True)")
            self.registerCommand(self.fakered, "fakered(ea, ui=True, hexOut=True)")
            self.registerCommand(self.unkptr, "unkptr(self, ea, end_ea=0x8800000, ui=True, hexOut=True)")
