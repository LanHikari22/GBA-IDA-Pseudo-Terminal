# @file disasmUtils
# provides utility commands for disassembling
import idaapi
import idc

from IDAItems import Function, Data

idaapi.require("TerminalModule")

import TerminalModule, miscUtils


class dis(TerminalModule.TerminalModule, object):
    def __init__(self):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        super(type(self), self).__init__('[+] dis (dissassembly utils)')

        self.rng.help = self.rng.__doc__
        self.rng.fmt = "<start_ea> <end_ea>"
        self.help += self._get_format("rng", self.rng) + '\n'

        self.rngext.help = self.rngext.__doc__
        self.rngext.fmt = "<start_ea> <end_ea>"
        self.help += self._get_format("rngext", self.rngext) + '\n'


    @staticmethod
    def rng(start_ea, end_ea):
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
        while ea < end_ea:
            if  Function.isFunction(ea):
                f = Function.Function(ea)
                disasm += f.getFormattedDisasm() + "\n\n"
                ea = ea + f.getSize(withPool=True)
            else:
                d = Data.Data(ea)
                disasm += d.getFormattedDisasm() + "\n"
                ea = ea + d.getSize()
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
                        and xref not in xrefs): # filter duplicate
                    xrefs.append(xref)
            # advance to next item
            ea = ea + d.getSize()


        output = ''
        # output file formats to include symbols into linking process
        for xref in xrefs:
            d = Data.Data(xref)
            name = d.getName()
            xref = d.ea
            output += '.equ %s, 0x%07X\n' % (name, xref)

        return output