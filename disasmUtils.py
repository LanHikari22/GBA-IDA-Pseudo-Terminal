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

        # first, insert forward references. This is useful for debugging. (Comment regions with defined
        # symbols)
        frefs = []
        while ea < end_ea:
                d = Data.Data(ea)
                if d.getName():
                    frefs.append((d.getName(), d.ea))
                ea = ea + d.getSize()

        # add forward references to disassembly
        disasm += "// forward references\n"
        for name, ea in frefs:
            disasm += ".equ %s, 0x%08X\n" % (name, ea)
        disasm += "\n"

        # rewind to disassemble
        ea = start_ea


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
    def rngext(start_ea, end_ea):
        # type: (int, int) -> str
        """
        creates .equs for all external symbols used in the range
        :param start_ea: start ea of the range, inclusive
        :param end_ea: end ea of the range, exclusive
        :param inc: if False, symbols output in file.x format are output, else in file.inc
        :return: a string containing all the external symbol .equs
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

        output = ''
        # output file formats to include symbols into linking process
        for xref in xrefs:
            d = Data.Data(xref)
            name = d.getName()
            xref = d.ea
            output += '.equ %s, 0x%07X\n' % (name, xref)

        return output

    def push(self):
        """
        Automatcally generates disassembly and external symbols for all asmFiles specified
        in env['asmFiles']
        """

        # grab necessary variables from the envrionment and assert that they were given
        asmFiles = self.get('asmFiles')
        asmPath = self.get('dismProjPath') + self.get('asmPath')
        externsPath = self.get('dismProjPath') + self.get('externsPath')
        if not asmFiles or not asmPath or not externsPath:
            print('ERROR: environmental variables for asmFiles, dismProjPath, asmPath, and externsPath'
                  + ' must be provided.')
            return

        keys = asmFiles.keys()
        keys.sort()
        for file in keys:
            # generate disassembly and external symbols output
            disasm = self.rng(asmFiles[file][0], asmFiles[file][1])
            externs = self.rngext(asmFiles[file][0], asmFiles[file][1])
            # write disassembly to file
            spath = asmPath + file + '.s'
            print("Disassembling %s.s into %s... " % (file, spath))
            asmfile = open(spath, 'w')
            asmfile.write(disasm)
            asmfile.close()
            # write externs to file
            incpath = externsPath + file + '.inc'
            print("Defining external symbols for %s.s in %s..." % (file, incpath))
            incfile = open(incpath, 'w')
            incfile.write(externs)
            incfile.close()
        print("Push complete!")