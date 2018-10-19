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

            next = SrchTools.nextTools.next()
            # include commands
            self.arm = next.arm
            self.ascii = next.ascii
            self.fakeinst = next.fakeinst
            self.name = next.name
            self.known = next.known
            self.bin = next.bin
            self.red = next.red
            self.immref = next.immref
            self.ret = next.ret
            self.unkret = next.unkret
            self.deadfunc = next.deadfunc
            self.fakered = next.fakered
            self.unkptr = next.unkptr

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
