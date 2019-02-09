# @file srchTools
# utilities for searching for things in the IDB, as well as in binaries (and against the IDB) go here!
import idautils
import idc
import idc_bc695
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

    # compute all names in RAM and ROM
    names = []
    for seg_ea in idautils.Segments():
        # skip BIOS
        if seg_ea == 0:
            continue
        for head in idautils.Heads(seg_ea, idc_bc695.SegEnd(seg_ea)):
            if idc.Name(head):
                names.append((head, idc.Name(head)))

    for ea, name in names:
        eaInSymTable = ea in symTable
        if eaInSymTable or ea+1 in symTable:

            # increment by 1 for thumb function symbols
            if ea+1 in symTable and idc.isCode(idc.GetFlags(ea)):
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