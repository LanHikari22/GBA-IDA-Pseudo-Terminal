# @file disasmUtils
# provides utility commands for disassembling
import idaapi
idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")
import idc
from IDAItems import Function, Data
import TerminalModule, miscUtils


class dis(TerminalModule.TerminalModule, object):
    def __init__(self, fmt='[+] dis (disassembly utils)'):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(dis, self).__init__(fmt)
        self.registerCommand(self, self.rng, "rng", "<start_ea> <end_ea>")
        self.registerCommand(self, self.rngext, "rngext", "<start_ea> <end_ea>")
        self.registerCommand(self, self.push, "push", "")
        self.registerCommand(self, self.extract, "extract", "")


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
    def rngext(start_ea, end_ea, toStr=True):
        """
        creates .equs for all external symbols used in the range
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :return: a string containing all the external symbol .equs, or just the refs if not disp
        """
        ea = start_ea
        xrefs = []

        # if there's a function at end_ea, include all of its refs
        if Function.isFunction(end_ea):
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

    def rnglinkedext(self, start_ea, end_ea):
        """
        The same as rngext(), except, where it can, it includes header files too!
        This is based on the asmFiles found in env['asmFiles']
        when a header file is included, used symbols from the header file are shown commented out after it
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :return: a string containing all the external symbol .equs and .includes
        """
        # grab necessary variables from the environment and assert that they were given
        err_msg = 'ERROR: environmental variables for asmFiles' \
                  + ' must be provided.'
        try:
            asmFiles = self.get('asmFiles')
            if not asmFiles:
                print(err_msg)
                return
        except TypeError:
            print(err_msg)
            return

        xrefs = dis.rngext(start_ea, end_ea, toStr=False)
        includes = {}
        # compute includes, and remove xrefs inside them
        for xref in xrefs:
            # figure out if it's in any include (within asmFile ranges)
            keys = asmFiles.keys()
            keys.sort()
            for file in keys:
                # if xref is within file range
                if asmFiles[file][0] <= xref < asmFiles[file][1]:
                    xrefs.remove(xref)
                    if file not in includes:
                        includes[file] = [xref]
                    else:
                        includes[file].append(xref)
        output = ''
        # output includes and specific usages
        for include in includes.keys():
            output += '.include "%s.inc"\n' % (include)
            for xref in includes[include]:
                output += '// .equ %s, 0x%07X\n' % (Data.Data(xref).getName(), xref)
            output += '\n'

        output += '\n'

        # output remaining xrefs
        for xref in xrefs:
            d = Data.Data(xref)
            name = d.getName()
            xref = d.ea
            output += '.equ %s, 0x%07X\n' % (name, xref)
        return output


    @staticmethod
    def rnginc(start_ea, end_ea):
        """
        Creates includes as well as forward references for the range
        The symbols are .equ defined, and represent the symbols defined within the range
        :param start_ea: linear address of the start of the range
        :param end_ea: linear address of the end of the range, exclusive
        :return: a series of .equ's representing the public (and private) interface of the range
        """
        ea = start_ea
        pubrefs = []
        fwdrefs = []
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
                    else:
                        fwdrefs.append((d.getName(), d.ea))
                ea = ea + d.getSize()

        # string build includes
        inc = '// Public Interface\n'
        for name, ea in pubrefs:
            inc += ".equ %s, 0x%07X\n" % (name, ea)
        inc += "\n// Forward Reference\n"
        for name, ea in fwdrefs:
            inc += ".equ %s, 0x%07X\n" % (name, ea)
        inc += "\n"
        return inc

    def push(self):
        """
        Automatcally generates disassembly, header, and external symbols for all asmFiles specified
        in env['asmFiles'] and updates the files in the project folder specified
        """

        # grab necessary variables from the environment and assert that they were given
        err_msg = 'ERROR: environmental variables for dismProjPath, asmFiles, asmPath, incPath, and externsPath' \
                      + ' must be provided.'
        try:
            asmFiles = self.get('asmFiles')
            asmPath = self.get('dismProjPath') + self.get('asmPath')
            incPath = self.get('dismProjPath') + self.get('incPath')
            externsPath = self.get('dismProjPath') + self.get('externsPath')
            if not asmFiles or not asmPath or not externsPath or not incPath:
                print(err_msg)
                return
        except TypeError:
            print(err_msg)
            return

        keys = asmFiles.keys()
        keys.sort()
        for file in keys:
            # include header into disassembly
            disasm = '.include "%s.inc"\n\n' % (file)
            # write disassembly to file
            spath = asmPath + file + '.s'
            print("> Disassembling %s.s into %s... " % (file, spath))
            disasm += self.rng(asmFiles[file][0], asmFiles[file][1])
            asmfile = open(spath, 'w')
            asmfile.write(disasm)
            asmfile.close()
            # write inc file
            incpath = incPath + file + '.inc'
            print("Defining header symbols for %s.s in %s..." % (file, incpath))
            incs = self.rnginc(asmFiles[file][0], asmFiles[file][1])
            incfile = open(incpath, 'w')
            incfile.write(incs)
            incfile.close()
            # write externs to file
            extpath = externsPath + file + '.inc'
            print("Defining external symbols for %s.s in %s..." % (file, extpath))
            externs = self.rnglinkedext(asmFiles[file][0], asmFiles[file][1])
            extfile = open(extpath, 'w')
            extfile.write(externs)
            extfile.close()
        print("Push complete!")

    def extract(self):
        """
        Extracts all binary ranges specified in env['binFiles'] into *.bin files in the folder env['binPath']
        """
        # grab necessary variables from the environment and assert that they were given
        binFiles = self.get('binFiles')
        binPath = self.get('dismProjPath') + self.get('binPath')
        if not binFiles or not binPath:
            print('ERROR: environmental variables for dismProjPath, binFiles, and binPath'
                  + ' must be provided.')
            return

        keys = binFiles.keys()
        keys.sort()
        for file in keys:
            # get bytes in specified range
            bytes = idc.get_bytes(binFiles[file][0], binFiles[file][1] - binFiles[file][0])

            # write bytes to bin file
            bpath = binPath + file + '.bin'
            print("Extracting %s.bin into %s... " % (file, bpath))
            binfile = open(bpath, 'wb')
            binfile.write(bytes)
            binfile.close()
        print("Extraction complete!")
