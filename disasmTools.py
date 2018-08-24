# @file disasmTools
# provides utility commands for disassembling
import idaapi
idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")
import idc
from IDAItems import Function, Data
import TerminalModule


class dis(TerminalModule.TerminalModule, object):
    """
    This module contains utilities that help with disassembly exporting from IDA.
    The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
    """
    def __init__(self, fmt='[+] dis (disassembly tools)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(dis, self).__init__(fmt)
        self.registerCommand(self.push, "push()")
        self.registerCommand(self.extract, "extract()")
        self.registerCommand(self.checkExtractedCode, "checkExtractedCode()")
        self.registerCommand(self.rng, "rng(start_ea, end_ea)")
        self.registerCommand(self.rngExterns, "rngExterns(start_ea, end_ea)")
        self.registerCommand(self.rngSyncedExterns, "rngSyncedExterns(start_ea, end_ea)")
        self.registerCommand(self.rngInc, "rngInc(start_ea, end_ea)")
        self.registerCommand(self.romIncs, "romIncs()")
        self.registerCommand(self.addFile, "addFile(filename, start_ea, end_ea)")
        self.registerCommand(self.formatGameFiles, "formatGameFiles()")


    @staticmethod
    def _getBaseFilename(file):
        # type: (str) -> str
        if '/' in file:
            file = file[file.rindex('/') + 1:]
        elif '\\' in file:
            file = file[file.rindex('\\') + 1:]
        return file

    def push(self):
        """
        Automatcally generates disassembly, header, and external symbols for all asmFiles specified
        in env['asmFiles'] and updates the files in the project folder specified
        """

        # grab necessary variables from the environment and assert that they were given
        err_msg = 'ERROR: environmental variables for dismProjPath, gameFiles, and incPath' \
                      + ' must be provided.'
        try:
            gameFiles = self.get('gameFiles')
            projPath = self.get('dismProjPath')
            incPath = self.get('incPath')
            if not gameFiles or not projPath or not incPath:
                print(err_msg)
                return
        except TypeError:
            print(err_msg)
            return

        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            filename = self._getBaseFilename(file)
            if '.s' in file:
                filename = filename[:filename.rindex('.')]
                # include header into disassembly
                disasm = '.include "%s.inc"\n\n' % (filename)
                # write disassembly to file
                print("> Disassembling %s... " % (file))
                disasm += self.rng(*gameFiles[file])
                asmfile = open(projPath + file, 'w')
                asmfile.write(disasm)
                asmfile.close()
                # write public interface and external symbol includes to header file
                incpath = incPath + filename + '.inc'
                print("Defining a header file in %s..." % (incpath))
                headerFilename = filename.upper().replace('/', '_')
                headerStart = '.ifndef INC_%s\n.equ INC_%s, 0\n\n' % (headerFilename, headerFilename)
                headerEnd = '\n.endif // INC_%s\n' % (headerFilename)
                incs = self.rngInc(*gameFiles[file])
                externs = self.rngSyncedExterns(*gameFiles[file])
                incfile = open(projPath + incpath, 'w')
                incfile.write(headerStart + incs + '\n' + externs + headerEnd)
                incfile.close()

        print("Push complete!")

    def extract(self):
        """
        Extracts all binary ranges specified in env['binFiles'] into *.bin files in the folder env['binPath']
        """
        # grab necessary variables from the environment and assert that they were given
        gameFiles = self.get('gameFiles')
        projPath = self.get('dismProjPath')
        if not gameFiles or not projPath:
            print('ERROR: environmental variable for gameFiles and dismProjPath'
                  + ' must be provided.')
            return

        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            if '.bin' in file or '.lz77' in file:
                # get bytes in specified range
                bytes = idc.get_bytes(gameFiles[file][0], gameFiles[file][1] - gameFiles[file][0])

                # write bytes to bin file
                print("Extracting %s... " % (file))
                binfile = open(projPath + file, 'wb')
                binfile.write(bytes)
                binfile.close()
        print("Binary Extraction complete!")

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
                disasm += f.getFormattedDisasm() + "\n\n"
                ea = ea + f.getSize(withPool=True)
            else:
                d = Data.Data(ea)
                if debug: print("%07X: disass data %s @ %07X" % (ea, d.getName(), d.ea))
                disasm += d.getFormattedDisasm() + "\n"
                ea = ea + d.getSize()

        # add comment for debugging purposes
        disasm += "/*For debugging purposes, connect comment at any range!*/\n"

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
                        and d.isPointer(xref)): # filter non-pointer symbols, like byte_50
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
            output += '.equ %s, 0x%07X\n' % (name, xref)

        return output

    def rngSyncedExterns(self, start_ea, end_ea):
        """
        The same as rngext(), except, where it can, it includes header files too!
        This is based on the asmFiles found in env['asmFiles']
        when a header file is included, used symbols from the header file are shown commented out after it
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :return: a string containing all the external symbol .equs and .includes
        """
        # grab necessary variables from the environment and assert that they were given
        err_msg = 'ERROR: environmental variables for gameFiles' \
                  + ' must be provided.'
        try:
            gameFiles = self.get('gameFiles')
            if not gameFiles:
                print(err_msg)
                return
        except TypeError:
            print(err_msg)
            return

        xrefs = dis.rngExterns(start_ea, end_ea, toStr=False)
        includes = {}

        # compute includes, and find the ones not declared anywhere
        undeclaredXrefs = []
        dataFileLabels = [] # those are declared in _rom.s and must not be .equ'd.
        for xref in xrefs:
            # figure out if it's in any include (within asmFile ranges)
            isDeclared = False
            for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
                if '.s' in file:
                    filename = self._getBaseFilename(file)
                    # if xref is within file range
                    if gameFiles[file][0] <= xref < gameFiles[file][1]:
                        if filename not in includes:
                            includes[filename] = (gameFiles[file][0], [xref])
                        else:
                            includes[filename][1].append(xref)
                        # we found what file that xref belongs to now
                        isDeclared = True
                        break
                else:
                    dataFileLabels.append(gameFiles[file][0])

            # xref doesn't belong to any header file
            if not isDeclared and xref not in undeclaredXrefs:
                undeclaredXrefs.append(xref)

        # output includes and specific usages
        output =  '/* External Symbols */\n'
        for include, _ in sorted(includes.items(), key=lambda x:x[1][0]):
            output += '.include "%s.inc"\n' % (include[:include.index('.')])
            for xref in includes[include][1]:
                # Only global if all symbols are defined somewhere. While actively disassembling, .equ is helpful
                d = Data.Data(xref)
                if d.isFunctionStart():
                    cmt = idc.get_func_cmt(xref, repeatable=1)
                    if cmt: cmt = ' // ' + cmt.replace('\n', '\n// ')
                else:
                    cmt = ''
                output += '// .global %s%s\n' % (d.getName(), cmt)
                # output += '.equ %s, 0x%07X\n' % (Data.Data(xref).getName(), Data.Data(xref).ea)
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
            else:
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

    def checkExtractedCode(self):
        """
        Checks if any gameFile that is not disassembled has any code in it
        All code must be disassembled, and data should be extracted
        If code is contained within extracted binaries, they are reported back
        :return: [] if no code in extracted ranged. list[gameFile] otherwise.
        """
        # grab necessary variables from the environment and assert that they were given
        gameFiles = self.get('gameFiles')
        if not gameFiles:
            print('ERROR: environmental variables for gameFiles'
                  + ' must be provided.')
            return
        markedFiles = []
        keys = gameFiles.keys()
        keys.sort()
        for file in keys:
            if not '.s' in file:
                # traverse the range, make sure it has no code
                ea = gameFiles[file][0]
                while ea < gameFiles[file][1]:
                    d = Data.Data(ea)
                    if (d.isCode()):
                        markedFiles.append(file)
                        break
                    ea += d.getSize()
        return markedFiles


    def romIncs(self):
        """
        creates the .incs and .incbin as per the gamefiles defined.
        This defines how all of the files are included together to make the final rom image. That is only true
        if the range in gameFiles actually cover the entire ROM
        :return: a string containing the includes to put in a rom.s file to include all files together
        """
        output = ''
        gameFiles = self.get('gameFiles')
        if not gameFiles:
            print('ERROR: environmental variables for gameFiles'
                  + ' must be provided.')
            return

        output = ''
        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            if '.s' in file:
                label = self._getBaseFilename(file)
                label = label[:label.rindex('.')]
                output += '%s:\n.include "%s"\n' % (label, file)
            else:
                d = Data.Data(gameFiles[file][0])
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
        gameFiles = self.get('gameFiles')
        changeChunks = False
        chunkedFileName = ''
        chunkedFileExt = ''
        chunks = []
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
        gameFiles = self.get('gameFiles')
        padSize = len("'start.s':        ")
        output = ''
        for file in sorted(gameFiles.keys(), key=gameFiles.__getitem__):
            output += ("'" + file + "':" + (padSize-len(file)+1)*' ')
            output += '(0x%07X, 0x%07X), # size=0x%X\n' % (gameFiles[file][0], gameFiles[file][1],
                                                      gameFiles[file][1] - gameFiles[file][0])
        return output

