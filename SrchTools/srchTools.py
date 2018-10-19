# @file srchTools
# utilities for searching for things in the IDB, as well as in binaries (and against the IDB) go here!
import idaapi
import idautils
import idc

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")
idaapi.require("SrchTools.nextTools")

from SrchTools import nextTools
import TerminalModule
import os
import re


def getSymTable(elfPath):
    """
    This creates temporary files and deletes them immediately after for interacting with arm-none-eabi-readelf
    It displays the symbol table of the elf file, and searches for the specified symbol
    :param elfPath:  the elf file path to read the symbol from
    :param symbolName: the symbol to read
    :return: its integer value
    """
    symTable = {}
    FILE_NAME = 'tempGetSymbols'
    # generate readelf output
    tmpStdout = '%s_stdout.tmp' % FILE_NAME
    tmpStderr = '%s_stderr.tmp' % FILE_NAME
    os.system('arm-none-eabi-readelf -sW %s 1> %s 2> %s' % (elfPath, tmpStdout, tmpStderr))
    # find the tail symbol in the output
    stdoutFile = open(tmpStdout, 'r')

    for line in stdoutFile.readlines():
        fields = list(filter(None, re.split('[ \n]', line)))
        # only parse the right row struct, and now the keys line.
        if len(fields) == 8 and fields[0] != 'Num:' and '$' not in fields[7]:
            addr = int(fields[1], 16)
            name = fields[7]
            isLocal = fields[4] == 'LOCAL'
            if addr in symTable and (name, isLocal) not in symTable[addr]:
                symTable[addr].append((name, isLocal))
            else:
                symTable[addr] = [(name, isLocal)]

    stdoutFile.close()
    # delete temporary files
    os.remove(tmpStdout)
    os.remove(tmpStderr)
    return symTable

def listUpdatedSymbols(elfPath):
    """
    Searches through the symtable in the elfPath, and computes a list of name_eas, and their
    new names
    :param elfPath: path of the elf file to process
    :return: list of (name_ea, new_name)
    """
    output = []
    symTable = getSymTable(elfPath)
    for ea, name in idautils.Names():
        eaInSymTable = ea in symTable
        if eaInSymTable or ea+1 in symTable:

            # increment by 1 for thumb function symbols
            if ea+1 in symTable:
                name_ea = ea+1
            else:
                name_ea = ea

            # check if the name exists in the symTable
            nameInSymTable = False
            globalSymbol = ''
            for symName, isLocal in symTable[name_ea]:
                if name == symName:
                    nameInSymTable = True
                if not isLocal:
                    globalSymbol = symName

            if nameInSymTable:
                continue

            # At this point, a name must have changed.
            if globalSymbol:
                output.append((ea, globalSymbol))
            else:
                output.append((ea, symTable[name_ea][0][0]))

    return output