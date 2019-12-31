"""
@Author Lan
This module allows for writing disassembly files that are compatible with the gnu
arm-none-eabi toolchain.
"""
import ida_hexrays
import idaapi
import idc_bc695
import idc
import ida_enum
import idautils
from IDAItems import Function, Data
import os
import re

class GNUDisassembler:
    """
    This module contains utilities that help with disassembly exporting from IDA.
    The disassembly is in a format compatible with the none-arm-eabi-as assembler.
    """
    def __init__(self, gameFiles, projPath, incPath, binAliases):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        # grab necessary variables from the environment and assert that they were given
        self.gameFiles = gameFiles
        self.projPath = projPath
        self.incPath = incPath
        self.binAliases = binAliases

        # changes to the disassembly through IDA since the last dump, this is so that not everything
        # is disassembled as a whole everytime.
        self.dirtyBlocks = []

    def push(self, startFile=''):
        """
        Automatcally generates disassembly .s files and .inc headers for assembly files specified
        in self.gameFiles, to self.projPath. Header files are put to the same relative path specified in
        self.gameFiles, except in the folder specified by self.incPath.
        """
        for file in sorted(self.gameFiles.keys(), key=self.gameFiles.__getitem__):
            if startFile and self.gameFiles[file][0] < self.gameFiles[startFile][0]:
                continue
            # filename = self._getBaseFilename(file)
            if file.endswith('.s'):
                filename = file[:file.rindex('.')]
                # include header into disassembly
                disasm = '.include "%s.inc"\n\n' % (filename)
                # write disassembly to file
                print("> Disassembling %s... " % (file))
                disasm += self.rng(*self.gameFiles[file])
                asmfile = open(self.projPath + file, 'w')
                asmfile.write(disasm)
                asmfile.close()
                # write public interface and external symbol includes to header file
                incpath = self.incPath + filename + '.inc'
                print("Defining a header file in %s..." % (incpath))
                headerFilename = filename.upper().replace('/', '_')
                headerStart = '.ifndef INC_%s\n.equ INC_%s, 0\n\n' % (headerFilename, headerFilename)
                headerEnd = '\n.endif // INC_%s\n' % (headerFilename)
                incs = self.rngInc(*self.gameFiles[file])
                externs = self.rngSyncedExterns(*self.gameFiles[file])
                incfile = open(self.projPath + incpath, 'w')
                incfile.write(headerStart + incs + '\n' + externs + headerEnd)
                incfile.close()

        print("Push complete!")

    def sync(self):
        """
        Updates all *.s files already dumped with push() by the recent changes to the database
        marked as dirty. the *incs are also updated accordingly.
        :return:
        """
        raise(NotImplemented())

    def pull(self):
        """
        Reads the disassembly and updates the database based on it.
        This should update:
            1. All symbols
            2. All added/removed comments
        The symbols would be extracted from an elf built from the disassembly.
        Other changes operate like sync(), in that changed name blocks will be parsed and analyzed
        to determine the changes to the disassembly.
        In order to obtain the list of dirty name blocks, git diff is used against a commit of the last push()
        :return: list of name block addresses in which a change was detected but was not parsed.
        """
        raise(NotImplemented())

    def extract(self):
        """
        Binary extracts all files in self.gameFiles with an extension found in self.binAliases
        to their specified relative addresses, in self.projPath.
        """
        for file in sorted(self.gameFiles.keys(), key=self.gameFiles.__getitem__):
            # ensure the file is a binary file to be extracted
            isBinFile = file.endswith('.bin')
            for alias in self.binAliases:
                if isBinFile: break
                isBinFile = isBinFile or file.endswith('.' + alias)

            if isBinFile:
                # get bytes in specified range
                bytes = idc.get_bytes(self.gameFiles[file][0],
                                      self.gameFiles[file][1] - self.gameFiles[file][0])

                # write bytes to bin file
                print("Extracting %s... " % (file))
                binfile = open(self.projPath + file, 'wb')
                binfile.write(bytes)
                binfile.close()
        print("Binary Extraction complete!")

    def decomp(self, decompPath, gameFiles=None):
        if not gameFiles:
            gameFiles = self.gameFiles
        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            if file.endswith('.s'):
                filename = file[:file.rindex('.')]
                decomp = ''
                # decompile all functions within file
                print("> Decompiling %s... " % (self._getBaseFilename(file)[:-2] + '.c'))
                ea = gameFiles[file][0]
                while ea < gameFiles[file][1]:
                    if Function.isFunction(ea):
                        func = Function.Function(ea)
                        # include address for ease of search in case of label name changes
                        decomp += '// 0x%07x\n' % func.func_ea
                        # try to decompile, or put the asm
                        try:
                            decomp += str(idaapi.decompile(func.func_ea)) + '\n\n'
                        except ida_hexrays.DecompilationFailure as e:
                            print('\tFailed to decompile %07X <%s>' % (func.func_ea, func.getName()))
                            decomp += 'int %s() { // could not decompile\n' % func.getName()
                            decomp += '\tasm("%s"\n\t);\n}\n\n' % func.getFormattedDisasm().replace('\n', '\\\n\t').rstrip()
                        ea = func.func_ea + func.getSize(withPool=True)
                    else:
                        ea += idaapi.get_item_size(ea)
                # write decomp to file.c
                if decomp:
                    decomp = decomp.replace('  ', '    ')
                    decomp = decomp.replace('\t', '    ')
                    print(self.projPath, decompPath)
                    cFile = open(self.projPath[0] + decompPath + self._getBaseFilename(file)[:-2] + '.c', 'w')
                    cFile.write(decomp)
                    cFile.close()

        print("Decompilation complete!")


    def resetDirtyBlocks(self):
        """
        Resets the list of changed name blocks (a region from a label to another).
        sync() only updates dirty blocks from a label to another, rather than disassembling everything
        like push().
        """
        raise (NotImplemented())

    def markDirty(self, ea):
        """
        Marks the block from when the last label till the next one as dirty, so that it can be sync'd
        with the disassembly.
        :param ea: linear address of the change ocurred in the disassembly
        """
        raise (NotImplemented())

    def romIncs(self):
        """
        creates the .incs and .incbin as per the gamefiles defined.
        This defines how all of the files are included together to make the final rom image. That is only true
        if the range in gameFiles actually cover the entire ROM
        :return: a string containing the includes to put in a rom.s file to include all files together
        """
        output = ''
        for file in sorted(self.gameFiles.keys(), key=self.gameFiles.__getitem__):
            if file.endswith('.s'):
                label = self._getBaseFilename(file)
                label = label[:label.rindex('.')]
                output += '%s:\n.include "%s"\n' % (label, file)
            else:
                d = Data.Data(self.gameFiles[file][0])
                label = d.getName()
                if not label:
                    label = self._getBaseFilename(file)
                    label = label[:label.rindex('.')]
                output += '%s:\n.incbin "%s"\n' % (label, file)

        return output

    def addFile(self, filename, start_ea, end_ea):
        """
        Adds in a file, and recomputes the chunks if it's found within another file.
        :param gameFiles: dictionary of filenames and ranges
        :param filename: name of the file to be added
        :param start_ea: the start of the range, inclusive
        :param end_ea: the end of the range, exclusive
        """
        changeChunks = False
        chunkedFileName = ''
        chunkedFileExt = ''
        chunks = []
        gameFiles = self.gameFiles
        files = sorted(gameFiles.keys(), key=gameFiles.__getitem__)
        for file in files:
            fileNoExt = file[:file.rindex('.')]
            ext = file[file.rindex('.')+1:]

            if (gameFiles[file][0] < start_ea < gameFiles[file][1] and
                    gameFiles[file][0] < end_ea < gameFiles[file][1]):
                # if it's a chunked file already, we have to sync the chunks
                if '_' in fileNoExt and fileNoExt[fileNoExt.rindex('_')+1:].isdigit():
                    chunkedFileName = fileNoExt[:file.rindex('_')]
                    chunkedFileExt = file[file.rindex('.')+1:]
                    chunkedFileExt = file[file.rindex('.')+1:]
                    chunkNo = int(fileNoExt[fileNoExt.rindex('_')+1:])
                    chunkEnd = gameFiles[file][1]
                    gameFiles[file] = (gameFiles[file][0], start_ea)
                    gameFiles[filename] = (start_ea, end_ea)
                    nextChunkName = '%s_%d.%s' % (chunkedFileName, chunkNo+1, ext)
                    print(nextChunkName)
                    if nextChunkName in gameFiles:
                        chunks.append(gameFiles[nextChunkName]) # add modified range again later
                    gameFiles[nextChunkName] = (end_ea, chunkEnd)
                    changeChunks = True
                else:
                    # chunk the current file
                    firstChunkName = '%s_0.%s' % (fileNoExt, ext)
                    secondChunkName = '%s_1.%s' % (fileNoExt, ext)
                    # replace file, with a chunked version of itself
                    gameFiles[firstChunkName] = gameFiles[file]
                    gameFiles.pop(file, None)
                    # set chunk ranges
                    chunkEnd = gameFiles[firstChunkName][1]
                    gameFiles[firstChunkName] = (gameFiles[firstChunkName][0], start_ea)
                    gameFiles[filename] = (start_ea, end_ea)
                    gameFiles[secondChunkName] = (end_ea, chunkEnd)
                break
            elif start_ea == gameFiles[file][0] and end_ea < gameFiles[file][1]:
                gameFiles[file] = (end_ea, gameFiles[file][1])
                gameFiles[filename] = (start_ea, end_ea)
                break
            elif start_ea > gameFiles[file][0] and end_ea == gameFiles[file][1]:
                gameFiles[file] = (gameFiles[file][0], start_ea)
                gameFiles[filename] = (start_ea, end_ea)
                break
            elif start_ea == gameFiles[file][0] and end_ea == gameFiles[file][1]:
                # simply rename exact matching range
                gameFiles.pop(file, None)
                gameFiles[filename] = (start_ea, end_ea)
        if changeChunks:
            print(chunkedFileName, chunkedFileExt)
            for file in files:
                if ('_' in file and file[:file.rindex('_')] == chunkedFileName
                        and file[file.rindex('_')+1:file.rindex('.')].isdigit()):
                    chunks.append(gameFiles[file])

            # modify the chunks so they sync up in the game files
            chunks.sort()
            for i in range(len(chunks)):
                gameFiles['%s_%d.%s' % (chunkedFileName, i, chunkedFileExt)] = chunks[i]

    def formatGameFiles(self):
        # type: (dict[str, (int, int)]) -> str
        """
        Outputs the game files in a good format. This allows for the dynamic modification of game files
        :return:
        """
        gameFiles = self.gameFiles
        padSize = len("'start.s':        ")
        output = ''
        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            output += ("'" + file + "':\n")
            output += '\t(0x%07X, 0x%07X), # size=0x%X\n' % (gameFiles[file][0], gameFiles[file][1],
                                                      gameFiles[file][1] - gameFiles[file][0])
        return output

    def rngSyncedExterns(self, start_ea, end_ea):
        """
        The same as rngExterns(), except it includes header files if they exist.
        This is based on all header files for asm files in self.gameFiles.
        when a header file is included, used symbols from the header file are shown commented out after it
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :return: a string containing all the external symbol .equs and .includes
        """

        xrefs = self.rngExterns(start_ea, end_ea, toStr=False)
        includes = {}

        # compute includes, and find the ones not declared anywhere
        undeclaredXrefs = []
        dataFileLabels = [] # those are declared in _rom.s and must not be .equ'd.
        for xref in xrefs:
            # figure out if it's in any include (within asmFile ranges)
            isDeclared = False
            for file in sorted(self.gameFiles.keys(), key=self.gameFiles.__getitem__):
                if file.endswith('.s'):
                    # if xref is within file range
                    if self.gameFiles[file][0] <= xref < self.gameFiles[file][1]:
                        if file not in includes:
                            includes[file] = (self.gameFiles[file][0], [xref])
                        else:
                            includes[file][1].append(xref)
                        # we found what file that xref belongs to now
                        isDeclared = True
                        break
                else:
                    dataFileLabels.append(self.gameFiles[file][0])

            # xref doesn't belong to any header file
            if not isDeclared and xref not in undeclaredXrefs:
                undeclaredXrefs.append(xref)

        # output includes and specific usages
        output =  '/* External Symbols */\n'
        for include, _ in sorted(includes.items(), key=lambda x:x[1][0]):
            output += '.include "%s.inc"\n' % (include[:include.rindex('.')])
            for xref in includes[include][1]:
                # Only global if all symbols are defined somewhere.
                d = Data.Data(xref)
                if d.isFunctionStart():
                    cmt = idc.get_func_cmt(xref, repeatable=1)
                    if cmt: cmt = ' // ' + cmt.replace('\n', '\n// ')
                else:
                    cmt = ''
                # TODO: while debugging/actively disassembling .set is more convenient
                output += '// .global %s%s\n' % (d.getName(), cmt)
                # output += '.set %s, 0x%07X\n' % (Data.Data(xref).getName(), Data.Data(xref).ea)
            output += '\n'

        # output remaining xrefs
        if undeclaredXrefs:
            output += '\n/* Undeclared Symbols */\n'

        for xref in undeclaredXrefs:
            # make sure the undeclared xref is not declared in _rom.s (data files)
            d = Data.Data(xref)
            name = d.getName()
            xref = d.ea
            if xref in dataFileLabels:
                output += '// .global %s\n' % (name)
            # IWRAM/EWRAM are linked as their own objects
            elif xref >= 0x2000000 and xref < 0x3008000:
                output += '// .equ %s, 0x%07X\n' % (name, xref)
            else:
                output += '.equ %s, 0x%07X\n' % (name, xref)

        return output

    def checkExtractedCode(self):
        """
        Checks if any gameFile that is not disassembled has any code in it
        All code must be disassembled, and data should be extracted
        If code is contained within extracted binaries, they are reported back
        :return: [] if no code in extracted ranged. list[gameFile] otherwise.
        """
        markedFiles = []
        keys = self.gameFiles.keys()
        keys.sort()
        for file in keys:
            if not file.endswith('.s'):
                # traverse the range, make sure it has no code
                ea = self.gameFiles[file][0]
                while ea < self.gameFiles[file][1]:
                    d = Data.Data(ea)
                    if (d.isCode()):
                        markedFiles.append(file)
                        break
                    ea += d.getSize()
        return markedFiles

    @staticmethod
    def _getBaseFilename(file):
        # type: (str) -> str
        if '/' in file:
            file = file[file.rindex('/') + 1:]
        elif '\\' in file:
            file = file[file.rindex('\\') + 1:]
        return file

    @staticmethod
    def rng(start_ea, end_ea, debug=False):
        # type: (int, int) -> str
        """
        disassembles all data elements within a range
        if a function is detected within the range, the function itself is disassembled
        as a whole item. (meaning it could surpass end_ea, but it would be the last item)
        :param start_ea: the start ea of the range
        :param end_ea: the end ea, not included
        :return: the disassembly of the range, in optimal format
        """
        ea = start_ea
        disasm = ''

        # disassemble the range
        ea = start_ea
        while ea < end_ea:
            if  Function.isFunction(ea):
                f = Function.Function(ea)
                if debug: print("%07X: disass function %s @ %07X" % (ea, f.getName(), f.func_ea))
                disasm += f.getFormattedDisasm(start_ea, end_ea) + "\n\n"
                ea = ea + f.getSize(withPool=True)
            else:
                d = Data.Data(ea)
                if debug: print("%07X: disass data %s @ %07X" % (ea, d.getName(), d.ea))
                disasm += d.getFormattedDisasm() + "\n"
                ea = ea + d.getSize()

        # add comment for debugging purposes
        # disasm += "/*For debugging purposes, connect comment at any range!*/\n"

        return disasm

    @staticmethod
    def rngExterns(start_ea, end_ea, toStr=True):
        """
        creates .equs for all external symbols used in the range
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :return: a string containing all the external symbol .equs, or just the refs if not disp
        """
        ea = start_ea
        xrefs = []

        # if end_ea is mid-way through a function, include all of its refs
        if Function.isFunction(end_ea) and Function.Function(end_ea).func_ea != end_ea:
            f = Function.Function(end_ea)
            end_ea = f.func_ea + f.getSize(withPool=True)

        # obtain xrefs of every data item, filtering out internal ones and duplicates
        while ea < end_ea:
            d = Data.Data(ea)
            # append crefs ands xrefs

            for xref in d.getXRefsFrom()[0]:
                # all code refs shouldn't have a +1 in them. The thumb switch isn't involved with the symbol itself
                if (idc.isCode(idc.GetFlags(xref)) or idc.isCode(idc.GetFlags(xref-1))) and xref & 1 == 1:
                    xref = xref - 1

                if ((xref < start_ea or xref >= end_ea) # filter internal (not external; within range)
                        and xref not in xrefs): # filter duplicate
                    xrefs.append(xref)
            for xref in d.getXRefsFrom()[1]:
                # all code refs shouldn't have a +1 in them. The thumb switch isn't involved with the symbol itself
                if (idc.isCode(idc.GetFlags(xref)) or idc.isCode(idc.GetFlags(xref-1))) and xref & 1 == 1:
                    xref = xref - 1

                if ((xref < start_ea or xref >= end_ea) # filter internal (not external; within range)
                        and xref not in xrefs # filter duplicate
                        and d.isPointer(xref) # filter non-pointer symbols, like byte_50
                        and Data.Data(xref).getName()): # an xref has to have a name to be defined as a symbol
                    xrefs.append(xref)
            # advance to next item
            ea = ea + d.getSize()

        xrefs.sort()

        if not toStr:
            return xrefs

        output = ''
        # output file formats to include symbols into linking process
        for xref in xrefs:
            d = Data.Data(xref)
            name = d.getName()
            xref = d.ea
            if name:
                output += '.equ %s, 0x%07X\n' % (name, xref)

        return output

    @staticmethod
    def rngInc(start_ea, end_ea):
        """
        Reports back the exposed (or public) symbols of the range
        The symbols are .global forwarded, and represent the symbols defined within the range
        :param start_ea: linear address of the start of the range
        :param end_ea: linear address of the end of the range, exclusive
        :return: a series of .equ's representing the public (and private) interface of the range
        """
        ea = start_ea
        pubrefs = []
        # fwdrefs = []
        while ea < end_ea:
                d = Data.Data(ea)
                if d.getName():
                    # check xrefs to the item, if any is outside the range, it's a public reference
                    isPublic = False
                    xrefsTo = d.getXRefsTo()
                    for cref in xrefsTo[0]:
                        if cref < start_ea or cref >= end_ea:
                            isPublic = True
                    for dref in xrefsTo[1]:
                        if dref < start_ea or dref >= end_ea:
                            isPublic = True
                    if isPublic:
                        pubrefs.append((d.getName(), d.ea))
                     # For debugging purposes
                    # else:
                    #     fwdrefs.append((d.getName(), d.ea))
                ea = ea + d.getSize()

        # string build includes
        inc = '/* Public Symbols */\n'
        for name, ea in pubrefs:
            d = Data.Data(ea)
            if d.isFunctionStart():
                cmt = idc.get_func_cmt(ea, repeatable=1)
                if cmt: cmt = ' // ' + cmt.replace('\n', '\n// ')
            else:
                cmt = ''
            inc += '.global %s%s\n' % (name, cmt)
        # For debugging purposes, defining forward references could be useful in include files
        # inc += "\n// Forward Reference\n"
        # for name, ea in fwdrefs:
        #     inc += ".equ %s, 0x%07X\n" % (name, ea)
        inc += "\n"
        return inc

def readStructMacro(path):
    """
    Parses struct macros and updates a corresponding enum with their values
    :param path: the path to the file containing the macros
    :return:
    """
    # parse macro file
    macroFile = open(path)
    members = []
    structName = ''
    for line in macroFile.readlines():
        if line.lstrip().startswith('\struct_entry'):
            if ', ' in line:
                name = line[line.index(')')+1 : line.index(',')]
                size = line[line.index(', ')+2 :].rstrip()
                if '//' in size:
                    size = size[:size.index('//')].rstrip()
                if size.startswith('0x'):
                    size = int(size, 16)
                else:
                    size = int(size)
            else:
                name = line[line.index(')')+1 :].rstrip()
                if '//' in name:
                    name = name[:name.index('//')].rstrip()
                size = 0
            members.append((name, size))
        if line.startswith('def_struct_offsets'):
            structName = line[line.index(', ')+2:].rstrip()
    print('parsed struct "' + structName + '"')

    # read into enum
    enumId = idc.get_enum(structName)
    if enumId == idaapi.BADADDR:
        enumId = idc.add_enum(idaapi.BADADDR, structName, idaapi.decflag())

    # parse all enum members, needed to know what member to replace
    offset = 0x00
    for member, size in members:
        enumMember = idc.get_enum_member(enumId, offset, 0, ida_enum.DEFMASK)
        if enumMember == idaapi.BADADDR:
            print("why???")
            idc.add_enum_member(enumId, structName + member, offset, idaapi.BADADDR)
        elif idc.get_enum_member_name(enumMember) != structName + member:
            # update member name, if value already exists
            print('\tupdate %s // 0x%X' % (structName + member, offset))
            idc.set_enum_member_name(enumMember, structName + member)

        offset += size
    return True

def _getSymTable(elfPath):
    """
    This creates temporary files and deletes them immediately after for interacting with arm-none-eabi-readelf
    It displays the symbol table of the elf file, and searches for the specified symbol
    :param elfPath:  the elf file path to read the symbol from
    :param symbolName: the symbol to read
    :return: its integer value
    """
    # TODO [DESIGN]: function exists in Srch too. Remove redundancy
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

def _listUpdatedSymbols(elfPath):
    """
    Searches through the symtable in the elfPath, and computes a list of name_eas, and their
    new names
    :param elfPath: path of the elf file to process
    :return: list of (name_ea, [(new_name, isLocal)])
    """
    # TODO [DESIGN]: function exists in Srch too. Remove redundancy
    output = []
    symTable = _getSymTable(elfPath)

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
        if ea in symTable or ea+1 in symTable:

            # increment by 1 for thumb function symbols
            if ea+1 in symTable and idc.isCode(idc.GetFlags(ea)):
                name_ea = ea+1
            else:
                name_ea = ea

            # check if the name exists in the symTable
            nameInSymTable = False
            for symName, isLocal in symTable[name_ea]:
                if name == symName:
                    nameInSymTable = True

            # a name change was detected
            if not nameInSymTable:
                output.append((ea, symTable[name_ea]))


    return output