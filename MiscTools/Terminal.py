import idaapi
idaapi.require('TerminalModule')
idaapi.require('MiscTools.miscTools')
idaapi.require('MiscTools.Operations')
idaapi.require('MiscTools.MemAccessReader')
idaapi.require('MiscTools.Hotkeys')
idaapi.require('MiscTools.TimeProfiler')

import TerminalModule
from MiscTools import miscTools
import MiscTools.Operations
import MiscTools.MemAccessReader
import MiscTools.Hotkeys
import MiscTools.TimeProfiler

class MiscTerminal(TerminalModule.TerminalModule, object):
    """
    Different kinds of commands and tools go here. No label. Just take a look, OK?
    """
    def __init__(self, fmt='[+] misc (tools of all kind)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(MiscTerminal, self).__init__(fmt)

        # include modules
        self.ops = MiscTerminal.opsTerminal()
        self.memar = MiscTerminal.MemAccessReaderTerminal()
        self.registerModule(self.ops)
        self.registerModule(self.memar)

        # register commands
        self.setHotKeys = MiscTools.Hotkeys.setHotkeys
        self.runTimeTests = MiscTools.TimeProfiler.runTimeTests
        self.ea2gf = miscTools.ea2gf
        self.sizeTillName = miscTools.sizeTillName
        self.getLZ77CompressedSize = miscTools.getLZ77CompressedSize
        self.findMostUsedFunctions = miscTools.findMostUsedFunctions
        self.fnrepl = miscTools.fnrepl
        self.plcv = miscTools.plcv
        self.nlrepl = miscTools.nlrepl
        self.rngmkd = miscTools.rngmkd

        self.registerCommand(self.gendocs, "gendocs(terminalModule)")
        self.registerCommand(self.setHotKeys, "setHotKeys()")
        self.registerCommand(self.runTimeTests, "runTimeTests(n=10)")
        self.registerCommand(self.ea2gf, "ea2gf(ea)")
        self.registerCommand(self.sizeTillName, "sizeTillName(ea, blockSize=1)")
        self.registerCommand(self.getLZ77CompressedSize, "getLZ77CompressedSize(compressed_ea)")
        self.registerCommand(self.findMostUsedFunctions, "findMostUsedFunctions(count, notModified=False, disp=True)")
        self.registerCommand(self.fnrepl, "fnrepl(start_ea, end_ea, oldstr, newstr)")
        self.registerCommand(self.plcv, "plcv(ea)")
        self.registerCommand(self.nlrepl, "nlrepl(oldStr, newStr)")
        self.registerCommand(self.rngmkd, "rngmkd(start_ea, end_ea)")

    def gendocs(self, mod):
        """
        Actually generates the docs for this file!
        :return: the docs to go to the COMMANDS.md file
        """
        name = self.fmt(mod)[len('[+] '):self.fmt(mod).index(' (')]
        desc = self.fmt(mod)[self.fmt(mod).index('('):]
        md = ''
        if name == 'pt':
            md += "This file contains documentation for all of the modules and commands available " \
                  "through the pt (PseudoTerminal) object.\n"
            md += "\n# Main Terminal\n"
        else:
            md += "\n# %s\n" % name
        # display the description for the module
        modHelp = mod.__doc__
        if modHelp == None:
            modHelp = ''
        modHelp = modHelp.strip()
        md += modHelp + '\n'
        # document the modules and commands of this module
        for m in mod.modules:
            name = self.fmt(m)[len('[+] '):self.fmt(m).index(' (')]
            desc = self.fmt(m)[self.fmt(m).index('('):]
            md += "- **%s** %s\n" % (name, desc)
        for c in mod.commands:
            # only show the initial message, not the parameter descriptions
            help = self.help(c).strip()
            if ':' in help:
                help = help[:help.index(':')]
            md += "- `%s` %s\n" % (self.fmt(c), help)
        # do the same for every module
        for m in mod.modules:
            md += self.gendocs(m)
        return md

    class opsTerminal(TerminalModule.TerminalModule, object):
        """
        This contains search tools for items and conditions found in the database, as well as binary files and
        comparisons
        """
        def __init__(self, fmt='[+] ops (Operations to perform to IDB)'):
            """
            This module is responsible for printing disassemblies and necessary compoents
            of disassemblies
            """
            super(MiscTerminal.opsTerminal, self).__init__(fmt)
            self.accesses = []
            self.funcs = []
            self.data = []

            self.registerUncompFile = MiscTools.Operations.registerUncompFile
            self.registerCommand(self.registerUncompFile, "registerUncompFile(ea)")

    class MemAccessReaderTerminal(TerminalModule.TerminalModule, object):
        def __init__(self, fmt='[+] memar (MemAccessScanner protocol reader)'):
            """
            This module is responsible for printing disassemblies and necessary compoents
            of disassemblies
            """
            super(MiscTerminal.MemAccessReaderTerminal, self).__init__(fmt)

            memAccessReader = MiscTools.MemAccessReader.MemAccessReader()
            self.read = memAccessReader.read
            self.formatAccessSources = memAccessReader.formatAccessSources

            self.registerCommand(self.read, "read(accesses_path)")
            self.registerCommand(self.formatAccessSources, "formatAccessSources()")