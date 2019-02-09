# @file disasmTools
# provides utility commands for disassembling
import TerminalModule
import GNUDisassembler

class DisTerminal(TerminalModule.TerminalModule, object):
    """
    This module contains utilities that help with disassembly exporting from IDA.
    The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
    """
    def __init__(self, fmt='[+] dis (disassembly tools)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(DisTerminal, self).__init__(fmt)

        # init GPUDisassembler
        # grab necessary variables from the environment and assert that they were given
        err_msg = 'The following environment variables were not found: '
        try:
            gameFiles = self.get('gameFiles')
            projPath = self.get('dismProjPath')
            incPath = self.get('incPath')
            binAliases = self.get('binAliases')
            if not gameFiles:
                err_msg += 'gameFiles, '
            if not projPath:
                err_msg += 'projPath, '
            if not incPath:
                err_msg += 'incPath, '
            if not binAliases:
                err_msg += 'binAliases, '

            if not gameFiles or not projPath or not incPath or not binAliases:
                # remove tail ', '
                err_msg = err_msg[:-2]
                raise Exception(err_msg)

        except TypeError:
            raise Exception('Not all environment variables are present')

        gnuDis = GNUDisassembler.GNUDisassembler(gameFiles, projPath, incPath, binAliases)

        # register commands
        self.push = gnuDis.push
        self.extract = gnuDis.extract
        self.decomp = gnuDis.decomp
        self.checkExtractedCode = gnuDis.checkExtractedCode
        self.rng = gnuDis.rng
        self.rngExterns = gnuDis.rngExterns
        self.rngSyncedExterns = gnuDis.rngSyncedExterns
        self.rngInc = gnuDis.rngInc
        self.romIncs = gnuDis.romIncs
        self.addFile = gnuDis.addFile
        self.formatGameFiles = gnuDis.formatGameFiles
        self.registerCommand(self.push, "push()")
        self.registerCommand(self.extract, "extract()")
        self.registerCommand(self.decomp, "decomp(decompPath, gameFiles=None)")
        self.registerCommand(self.checkExtractedCode, "checkExtractedCode()")
        self.registerCommand(self.rng, "rng(start_ea, end_ea)")
        self.registerCommand(self.rngExterns, "rngExterns(start_ea, end_ea)")
        self.registerCommand(self.rngSyncedExterns, "rngSyncedExterns(start_ea, end_ea)")
        self.registerCommand(self.rngInc, "rngInc(start_ea, end_ea)")
        self.registerCommand(self.romIncs, "romIncs()")
        self.registerCommand(self.addFile, "addFile(filename, start_ea, end_ea)")
        self.registerCommand(self.formatGameFiles, "formatGameFiles()")