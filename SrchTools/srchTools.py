# @file srchTools
# utilities for searching for things in the IDB, as well as in binaries (and against the IDB) go here!
import idaapi
idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")
idaapi.require("SrchTools.nextTools")

from SrchTools import nextTools
import TerminalModule


class srch(TerminalModule.TerminalModule, object):
    """
    This contains search tools for items and conditions found in the database, as well as binary files and
    comparisons
    """
    def __init__(self, fmt='[+] srch (database/binary search tools)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(srch, self).__init__(fmt)

        self.next = nextTools.next()
        self.registerModule(self.next)
