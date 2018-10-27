#
# @Author Lan
# This module classifies a Data type and defines operations done on them using the IDA API
#
import idaapi
idaapi.require("IDAItems.Instruction")

import re
import ida_bytes
import idautils
import idc
import Instruction


class DataException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)

# noinspection PyPep8Naming
class Data:
    def __init__(self, ea):
        # type: (int) -> None
        """
        :param ea: effective address of the data item
        :raise InvalidDataException: if the current item is not data (isCode)
        """
        # determine actual EA of the dataitem by analyzing its size. Going back in EA should increase the size
        # if we're in the middle of an array, or of the item. If it remains unchanged, or decreases, then we exited
        # the item.
        size = 0
        ranLoop = False
        # TODO [SLOW]: bottleneck algorithm (especially for big arrays, accessed at index 0x100+)
        while idc.get_item_size(ea) > size:
            if not ranLoop: ranLoop = True
            size = idc.get_item_size(ea)
            ea -= 1
        if ranLoop:
            # we just hit a failure condition, so the previous one is the correct one!
            ea += 1
        self.ea = ea

    def __str__(self):
        """
        :return: (str) The disassembly, compatible with arm-none-eabi-gcc
        """
        return self.getFormattedDisasm()


    def getName(self):
        """
        :return: the item's name, as last recorded by idaapi
        """
        return idc.Name(self.ea) or ''

    def setName(self, name):
        # type: (str) -> None
        """
        Sets the name of the data item
        :param name: the string to rename the data item to
        """
        idc.MakeName(self.ea, name)

    def getSize(self):
        """
        updates the size precomputed parameter and returns it
        :return: data item size, as last recorded by idaapi
        """
        return idc.get_item_size(self.ea)

    def getComment(self, repeatable=False):
        """
        :return: data item comment, prioritizes GUI-added comments over API added ones
        """
        mode = 1 if repeatable else 0
        return idc.get_cmt(self.ea, mode) or ''

    def setComment(self, comment):
        # type: (str) -> None
        """
        sets the comment for the data item
        user-set comments through the GUI have higher priority to display
        :param comment: comment to set to the data item
        """
        idc.MakeComm(self.ea, comment)

    def getXRefsTo(self):
        """
        Computes a list of the names of the xrefs to the data item and updates the xrefsto computed
        parameter.
        This includes all functions calls/branches, but also data xrefs such as LDR/STR and data (DCDs, DCBs..)
        there is also the weird case that a labelless asm line has a cref to the last asm line.
        :returns: a tuple of two lists: crefs and drefs
        """
        # type: () -> (list[int], list[int])
        crefs = []
        drefs = []

        # Find all code references to item
        ref = idc.get_first_cref_to(self.ea)
        while ref != idaapi.BADADDR:
            crefs.append(ref)
            ref = idaapi.get_next_cref_to(self.ea, ref)

        # Find all data references to item
        for ref in idautils.DataRefsTo(self.ea):
            drefs.append(ref)
        # TODO: why -1?? remove if redundant
        for ref in idautils.DataRefsTo(self.ea - 1):  # needed in case this is a code item
            drefs.append(ref)
        for ref in idautils.DataRefsTo(self.ea + 1):  # needed in case this is a code item
            drefs.append(ref)


        return (crefs, drefs)

    def getXRefsFrom(self):
        # type: () -> (list[int], list[int])
        """
        computes data and code references references from this data item
        This defines all data and code dependencies to this data item
        :return:
        """
        crefs = []
        drefs = []

        for xref in idautils.XrefsFrom(self.ea, 0):
            # if the xref is to a far or near called function/jump
            # also discluded the trivial case of flowing to next inst (fl_F)
            # (in case the data item is an asm line)
            if (xref.type != idc.fl_F and
                        xref.type == idc.fl_CN or xref.type == idc.fl_CF or
                        xref.type == idc.fl_JF or xref.type == idc.fl_JN):
                if xref.to not in crefs:
                    crefs.append(xref.to)
            elif xref.type != idc.fl_F:
                drefs.append(xref.to)

        return crefs, drefs

    def getContent(self, bin=False):
        """
        reads bytes at the EA of the data item and constructs its content representation based on its type
        :param bin: if True, array of bytes is always passed back
        """
        flags = idc.GetFlags(self.ea)
        output = -1

        if idc.isCode(flags):
            # an instruction is also data, its bytes are gathered and combined into one integer
            bytes = []
            for char in idc.get_bytes(self.ea, self.getSize()): bytes.append(ord(char))
            # either return one discrete instruction int, or an array of bytes representing it
            if bin:
                output = bytes
            else:
                output = self._combineBytes(bytes, self.getSize())[0]
        elif idc.isStruct(flags):
            output = [ord(char) for char in idc.get_bytes(self.ea, self.getSize())]
        elif idc.isData(flags):
            # normal case, build up a u8, u16, or u32
            if idc.is_data(flags) and (idc.is_byte(flags) and self.getSize() == 1
                                       or idc.is_word(flags) and self.getSize() == 2
                                       or idc.is_dword(flags) and self.getSize() == 4):
                bytes = []
                for char in idc.get_bytes(self.ea, self.getSize()): bytes.append(ord(char))
                # either return one discrete primitive, or the array of bytes representing it
                if bin:
                    output = bytes
                else:
                    output = self._combineBytes(bytes, self.getSize())[0]
            # The weird case... an array. I don't know why it's weird. IDA doesn't like it!
            else:
                # It is assumed this is an array, but the type is unknown. Imply type based on disasm of first line!
                firstLineSplitDisasm = list(filter(None, re.split('[ ,]', idc.GetDisasm(self.ea))))
                dataType = firstLineSplitDisasm[0]
                elemsPerLine = len(firstLineSplitDisasm) - 1  # don't include type, ex: DCB 0, 4, 5, 0x02, 0

                # Grab all of the bytes in the array
                bytes = [ord(char) for char in idc.get_bytes(self.ea, idc.get_item_size(self.ea))]

                # figure out datatype to convert the array to be of
                bytesPerElem = dataType == 'DCB' and 1 \
                               or dataType == 'DCW' and 2 \
                               or dataType == 'DCD' and 4 \
                               or 1  # if type unknown, just show it as a an array of bytes

                # create new array with correct type, or just return the bytes
                if bin:
                    output = bytes
                else:
                    output = self._combineBytes(bytes, bytesPerElem)
        elif idc.isUnknown(flags):
            # unknown data elements are always 1 byte in size!
            output = ord(idc.get_bytes(self.ea, 1))
            if bin: output = [output]

        return output

    def withinFunction(self):
        return idc.get_func_flags(self.ea) != -1

    def isFunctionStart(self):
        output = False
        if self.getName():
            if self.withinFunction():
                output = idaapi.get_func(self.ea).startEA == self.ea
        return output

    def getType(self):
        # type: () -> _
        """
        :return: the datatype: whether it's a primitive, enum, or struct, and that specific type.
        """
        raise (NotImplemented())

    def getTypeName(self):
        # type: () -> str
        """
        :return: the type of the data item, if it's a struct/enum/const, the name of it.
        a number of stars can follow, indicating that it's a pointer.
        """
        type = idc.get_type(self.ea)
        flags = idc.GetFlags(self.ea)
        typeName = "INVALID"
        if idc.isCode(flags):
            typeName = "code"
        elif idc.isData(flags):
            if idc.is_byte(flags) and self.getSize() == 1:
                typeName = "u8"
            elif idc.is_word(flags) and self.getSize() == 2:
                typeName = "u16"
            elif idc.is_dword(flags) and self.getSize() == 4:
                if self.isPointer(self.getContent()):
                    typeName = "void*"
                else:
                    typeName = "u32"
            else:  # The weird case... an array. I don't know why it's weird. IDA doesn't like it!
                # It is assumed this is an array, but the type is unknown. Imply type based on disasm of first line!
                firstLineSplitDisasm = list(filter(None, re.split('[ ,]', idc.GetDisasm(self.ea))))
                dataType = firstLineSplitDisasm[0]
                if dataType == "DCB":
                    typeName = "u8[%d]" % (self.getSize())
                if dataType == "DCW":
                    typeName = "u16[%d]" % (self.getSize() / 2)
                if dataType == "DCD":
                    if self.hasPointer():
                        typeName = "void*[%d]" % (self.getSize() / 4)
                    else:
                        typeName = "u32[%d]" % (self.getSize() / 4)
        elif idc.isUnknown(flags):
            typeName = "u8"
        elif idc.isStruct(flags):
            typeName = idc.GetStrucName
        return typeName

    def getOrigDisasm(self):
        # type: () -> str
        """
        Gets the original disassembly without any further applied transformations
        However, the formatting is different from the original and is more convenient
        for parsing
        :return: the disassembly
        """
        flags = idc.GetFlags(self.ea)
        if idc.isCode(flags):
            disasm = idc.GetDisasm(self.ea)
            disasm = self._filterComments(disasm)
            disasm = disasm.replace('  ', ' ')
        elif idc.isStruct(flags):
            disasm = self._getStructDisasm()
            # disasm = "INVALID"
        elif idc.isAlign(flags):
            disasm = idc.GetDisasm(self.ea)
            disasm = self._convertAlignDisasm(disasm)
        elif idc.isASCII(flags):
            content = self.getContent()
            numNewLines = content.count(0x0A)
            if numNewLines > 1:
                disasm = '.ascii "'
            else:
                disasm = '.asciz "'
            for i in range(len(content)):
                if content[i] == 0x00:
                    disasm += '"'
                elif chr(content[i]) == '"':
                    disasm += '\\\"'
                elif chr(content[i]) == '\\':
                    disasm += '\\\\'
                elif content[i] == 0x0A:
                    disasm += '\\n'
                    numNewLines -= 1
                    if numNewLines > 1:
                        disasm += '"\n\t.ascii "'
                    elif numNewLines == 1:
                        disasm += '"\n\t.asciz "'
                elif chr(content[i]) == ' ':
                    disasm += ' '
                elif not chr(content[i]).isspace():
                    disasm += chr(content[i])
                else:
                    # TODO [INVALID] arm-none-eabi doesn't recognize \xXX? \x seems to become a byte.
                    disasm += '\\x%02X' % content[i]
        elif idc.isData(flags):
            disasm = self._getDataDisasm()
        else:
            disasm = idc.GetDisasm(self.ea)
            disasm = self._filterComments(disasm)
            disasm = disasm.replace('  ', ' ')

        # parse force command
        if '<force>' in self.getComment():
            comment = self.getComment()
            disasm = comment[comment.index('<force> ') + len('<force> '):]
        return disasm

    def getDisasm(self):
        """
        :return: transformed disassembly so that it's functional with the gcc assembler
        """
        disasm = self.getOrigDisasm()
        flags = idc.GetFlags(self.ea)
        if idc.isData(flags) or idc.isUnknown(flags):
            disasm = self._convertData(disasm)
        elif idc.isCode(flags):
            disasm = self._convertCode(disasm)
            # make code small case
            disasm = self._lowerCode(disasm)
        elif idc.isAlign(flags):
            disasm = self._convertAlignDisasm(disasm)

        # TODO tabs or spaces? tabs for now
        # disasm = self._convertTabs(disasm)
        return disasm

    def getFormattedDisasm(self):
        """
        puts together the name label, comment, and disassembly, as well as proper spacing
        :return:
        """
        name = self.getName()
        disasm = ''
        # include label
        if name:
            disasm = name + ':'
            # only add a new line for code labels
            if self.isCode():
                disasm += "\n"

        # include comment
        comment = ''
        inlineComment = ''
        # include the data item's comment
        comment = self.getComment()
        if comment:
            # TODO: parsing the force out of the comment, but replacing with original
            if '<force>' in comment:
                origDisasm = idc.GetDisasm(self.ea)
                if ';' in origDisasm:
                    origDisasm = origDisasm[:origDisasm.index(';')]
                comment = comment[:comment.index('<force>')] +  '<il><force> ' + origDisasm
            if '<il>' in comment:
                splitIdx = comment.index('<il>')
                inlineComment = comment[splitIdx+len('<il>'):]
                comment = comment[:splitIdx]
            if comment:
                comment = "// " + comment.replace('\n', '\n\t// ') + '\n'
                if self.isCode():
                    disasm = disasm + '\t' + comment # label comes before comment
                else:
                    # for data, comment comes before label
                    if name:
                        disasm = disasm + '\n'
                    disasm = disasm + '\t' + comment # label comes before comment

        # include disassembly
        if self.isCode() or not name:
            disasm += '\t' + self.getDisasm()
        else:
            if comment:
                disasm += '\t' + self.getDisasm()
            else:
                disasm += ' ' + self.getDisasm()

        # include repeatable comments for function calls in the same line
        if self.isCode() and 'BL ' in self.getOrigDisasm():
            repCmt = idc.get_func_cmt(self.getXRefsFrom()[0][0], repeatable=1)
            repCmt = ' // ' + repCmt if repCmt else ''
            disasm += repCmt
        if inlineComment:
            disasm += ' // ' + inlineComment

        # TODO: tabs or spaces?
        # disasm = self._convertTabs(disasm)
        return disasm

    def getDefinition(self):
        # type: () -> str
        """
        :return: C-style definition for the data item
        """
        type = self.getTypeName()
        # code has no data definition, a function object can determine the definition of itself, but not one asm line
        # likewise, for a data element to have a definition, it must have a label
        if type == "code" or not self.getName():
            return ''

        # if this is an array, then it already refers to itself
        if '[' in type:
            output = "#define %s ((%s)0x%08X)" % (self.getName(), type, self.ea)
        else:
            output = "#define %s ((%s*)0x%08X)" % (self.getName(), type, self.ea)
        return output

    def isCode(self):
        return idc.isCode(idc.GetFlags(self.ea))

    def isData(self):
        return idc.isData(idc.GetFlags(self.ea))

    def isUnknown(self):
        return idc.isUnknown(idc.GetFlags(self.ea))

    def _convertCode(self, disasm):
        """
        modifies code data items so that they're compatible with arm-none-eabi-gcc
        Some comment tags are reserved for conversion actions:
            <mkdata>:  Converts the code to data, this is necessary when encountering redundant instructions.
        :param ea: (long) addr of disasm
        :param disasm: (str) disasm to transform
        :return: (str) converted disasm
        """
        flags = idc.GetFlags(self.ea)
        output = disasm  # Default case, no modifications
        if idc.isCode(flags):

            # some instructions take no operands, like NOP
            instName = idc.GetMnem(self.ea)

            # if the instruction is THUMB, it cannot have an 'S' in it... (except for branches)
            # the BIC instruction is not a branch, account for that
            isThumb = self.getSize() == 2

            isBranch = instName[0] == 'B' and 'BIC' not in instName
            hasCond = instName[-1] == 'S'
            if isThumb and not isBranch and hasCond:
                output = instName[:-1] + ' ' + output[len(instName):].lstrip()
                instName = instName[:-1]

            # adjust instruction spacing TODO: tabs or pad`s for instruction?
            output = instName + ' ' + output[len(instName):].lstrip()

            # convert immediate reference instructions
            output = self._convertImmediateReferences(output)

            # if the instruction is a pool instruction, the format should be changed
            poolDisasm = self._getPoolDisasm()
            if poolDisasm: output = poolDisasm

            # convert ADD Rx, Ry, #0 to a nicer form MOV Rx, Ry
            if instName == 'ADD' and output.endswith(', #0') and output.count(',') > 1:
                insn = Instruction.Insn(self.ea)
                if insn.ops[0].reg <= 7 and insn.ops[1].reg <= 7:
                    output = output.replace(instName, 'MOV', 1)[:output.rindex(',')]

            # if the instruction is an adc, replace it with a short
            if "ADR " in instName:
                output = "DCW 0x%X // %s" % (self.getContent(), output)
                output = self._convertData(output)

            # parse comment commands -- if it's a redundant instruction, it should have the <mkdata> tag in it
            if "<mkdata>" in self.getComment():
                output = "DCW 0x%X // %s" % (self.getContent(), output)
                output = self._convertData(output)

        return output

    def _getFlags(self):
        return idc.GetFlags(self.ea)


    def _convertData(self, disasm):
        """
        Simply replaces occurrances of DCD/DCB with what is compatible with the assembler
        :param disasm: disassembly to convert
        :return: converted disassembly
        """
        while 'DCD ' in disasm: disasm = disasm.replace('DCD ', '.word ')
        while 'DCW ' in disasm: disasm = disasm.replace('DCW ', '.hword ')
        while 'DCB ' in disasm: disasm = disasm.replace('DCB ', '.byte ')
        # gnu assembler format
        while '.long ' in disasm: disasm = disasm.replace('.long ', '.word ')
        while '.short ' in disasm: disasm = disasm.replace('.short ', '.hword ')


        return disasm

    def _convertComments(self, disasm):
        return disasm.replace(';', ' //', disasm.count(';'))
        pass

    def _getArrDisasm(self, elemsPerLine, dataType):
        # type: (int, int, str) -> str
        """

        :param ea: linear address to disassemble
        :param elemsPerLine: number of elements to disassemble in one line
        :param dataType: 'DCB', 'DCW', 'DCD', etc
        :return: disassembly string
        """
        # Grab all of the bytes in the array
        arr = self.getContent()

        # whether to display a name, or data, is determiend by the xrefs from this item!
        xrefs = self.getXRefsFrom()

        # only bother to check for names if it's an array of words
        wordArray = dataType == 'DCD'

        # generate disassembly for array
        disasm = dataType + ' '
        elemIndex = 0
        for elem in arr:
            # tab if new line
            if disasm[-1] == '\n': disasm += '\t%s' % (dataType + ' ')
            # add element and increment counter until new line
            # if it's a pointer and defined as an xref, display its label not just the number
            # isPointer is a bottleneck call, so prefer to call it last
            if wordArray and (elem in xrefs[1] or elem in xrefs[0]) and self.isPointer(elem):
                # TODO: maybe you ahould get the name of Data.Data(elem) also, for +index
                elemEA = Data(elem).ea
                name = idc.Name(elemEA)
                if name:
                    offset = elem - elemEA
                    if offset != 0:
                        offset = '+%d' % offset
                    else:
                        offset = ''
                    disasm += "%s%s, " % (name, offset)
                else:
                    disasm += '0x%X, ' % elem
            else:
                disasm += '0x%X, ' % elem

            elemIndex += 1

            # if we reach the number of elements a line, we add a new line
            if elemIndex % elemsPerLine == 0:
                # replace ", " at the end if present
                disasm = disasm[len(disasm) - 2:] == ', ' and disasm[:-2] or disasm
                # advance for the next line
                disasm += "\n"

        # remove ", " at the end if present
        disasm = disasm[len(disasm) - 2:] == ', ' and disasm[:-2] or disasm
        # remove new line at the end if present
        disasm = disasm[len(disasm) - 1:] == '\n' and disasm[:-1] or disasm

        return disasm

    def _getDataDisasm(self):
        """
        You cannot get array data using getdisasm. The disassembly has to be extracted differently.
        This identifies the data in question, and gets its disassembly
        :return: the disasssembly of the data item
        """
        # First, do the easy cases that just work with GetDisasm
        flags = idc.GetFlags(self.ea)
        # TODO: change this so it accounts for arrays also
        if idc.is_enum0(flags):
            return self._filterComments(idc.GetDisasm(self.ea))
        if idc.is_data(flags) and (idc.is_byte(flags) and idc.get_item_size(self.ea) == 1
                                   or idc.is_word(flags) and idc.get_item_size(self.ea) == 2
                                   or idc.is_dword(flags) and idc.get_item_size(self.ea) == 4):
            # normal case where an int is not misread as a reference
            content = self.getContent()
            if self.getXRefsFrom()[1] and self.isPointer(content):
                disasm = idc.GetDisasm(self.ea)
                contentData = Data(content)
                # If it's a struct member, replace it with its hex, but keep the information
                if '.' in disasm and (';' not in disasm or '.' in disasm[:disasm.index(';')]):
                    disasm = 'DCD %s+0x%X // %s' % (contentData.getName(), content - contentData.ea,
                                                    disasm[len('DCD '):])


            elif ida_bytes.is_manual(flags, 0):
                # Manual forms put in IDA, just grab it. (This is for cases where computations are applied to data)
                disasm = idc.GetDisasm(self.ea)
            else:
                # build the disassembly: this is for none-pointer symbols found in IDA (ex: word_0)
                if idc.is_byte(flags): op = 'DCB'
                elif idc.is_word(flags): op = 'DCW'
                else: op = 'DCD'
                disasm = op + ' ' + '0x%X' % content

            return self._filterComments(disasm)
        else:  # The weird case... an array. I don't know why it's weird. IDA doesn't like it!
            # It is assumed this is an array, but the type is unknown. Imply type based on disasm of first line!
            # analysis on the array is based on the very first line
            disasm = idc.GetDisasm(self.ea)
            if ';' in disasm:
                disasm = disasm[:disasm.index(';')]
            firstLineSplitDisasm = list(filter(None, re.split('[ ,]', disasm)))
            dataType = firstLineSplitDisasm[0]

            return self._getArrDisasm(len(firstLineSplitDisasm) - 1, dataType)



    def _getStructDisasm(self):
        # type: (int) -> str
        return self._getArrDisasm(8, 'DCB')


    def _filterComments(self, disasm):
        # filter comments out. this must be a one-line disasm.
        if '\n' in disasm: raise (DataException("disasm is not a one line"))
        if ';' in disasm: disasm = disasm[:disasm.index(';')]
        return disasm

    def hasPointer(self):
        """
        determines whether the item has a pointer in its content
        :return: True if the content is or contains a pointer in it
        """
        flags = idc.GetFlags(self.ea)
        output = False
        content = self.getContent()
        # only arrays may have pointers,
        if type(content) == list:
            # whether to display a name, or data, is determined by the xrefs from this item!
            xrefs = self.getXRefsFrom()
            for word_ea in content:
                if (word_ea in xrefs[1] or word_ea in xrefs[0]) and self.isPointer(word_ea):
                    output = True
        elif type(content) == int or type(content) == long:
            output = self.isPointer(content)
        return output

    @staticmethod
    def isPointer(ea):
        """
        an ea is likely a pointer if it has a possible value for physical addressing.
        :param ea: linear address of the data item
        :return: True if it's a pointer
        """
        if (0x02000000 <= ea < 0x02040000 or
                   0x03000000 <= ea < 0x03008000 or
                   0x04000000 <= ea < 0x04000400 or
                   0x08000000 <= ea < 0x09FFFFFF):
            return True
        return False

    def _getPoolDisasm(self):
        # type: () -> str
        """
        Disassembles pool in a linker compatible version. If the instruction is not a pool
        instruction

        :param ea: ea of inst
        :return: disassembly with the correct LDR/STR [PC, ...] format or ''
        :raise DataException: if an invalid state is entered while parsing the pool load
        """
        output = ''
        if 'LDR' in idc.GetMnem(self.ea) and Instruction.isPoolLDR(self.ea):
            insn = Instruction.Insn(self.ea)
            inst = 'LDR'
            reg = 'R%d' % (insn.ops[0].reg)

            # retrieve the pool address from the instruction
            pool_ea = insn.ops[1].addr
            poolData = Data(pool_ea)
            offset = pool_ea - poolData.ea

            # every pool reference must have a name
            if not poolData.getName():
                raise (DataException("%07X: pool_ea %07X does not have a name" % (self.ea, pool_ea)))

            content = poolData.getContent()

            # the pool might point to an array. The offset determines which element is loaded
            if type(content) == list:
                content = content[offset/(poolData.getSize()/len(content))]

            if type(content) != int and type(content) != long:
                raise (DataException("%07X: attempt to load non-int to register" % pool_ea))

            # write the actual pool value being loaded for readability
            contentData = Data(content)
            if contentData.isPointer(contentData.ea):
                # figure out unsync between xref of pool and content data... that's the index +!
                # depending on the data format of the value in the db, it may have no xrefs...
                if poolData.getXRefsFrom()[1]:
                    contentXref = poolData.getXRefsFrom()[1][0]
                    if contentXref - contentData.ea > 0:
                        index = "+%d" % (contentXref - contentData.ea)
                    elif contentXref - contentData.ea < 0:
                        index = "-%d" % (contentData.ea - contentXref)
                    else:
                        index = ''
                else:
                    index = ''

                cmt = "=%s%s" % (contentData.getName(), index)
            else:
                cmt = "=0x%X" % content

            # in case pool_ea is within an array, then it could be offset
            if offset:
                offset = '+%d' % offset
            else:
                offset = ''

            output = "%s %s, %s%s // %s " % (inst, reg, poolData.getName(), offset, cmt)

            # TODO: old output style for debugging purposes
            # if self.getSize() == 4:
            #     shift = 8
            # elif (pool_ea - self.ea - 4) % 4 != 0:
            #     # to achieve word alignment, we round down to the last word aligned value
            #     shift = 2
            # else:
            #     # normal case, PC is 2 instructions ahead
            #     shift = 4
            #
            # output =  "%s %s, [PC, #0x%07X-0x%07X-%d] // %s" % (inst, reg,
            #                                                    pool_ea, self.ea, shift, cmt)
        return output

    def _isFunctionPointer(self, firstLineSplitDisasm):
        """
        Identifies the construct 'DCD <funcName>' as a function pointer entry!
        The function Name is checked in the database for confirmation!
        This actually extend to none-identified functions, because it only checks if the location is valid code.
        :param firstLineSplitDisasm: list of space and comma split operands in the instruction. ['DCD', 'sub_DEADBEEF+1']
        :return:
        """
        return len(firstLineSplitDisasm) >= 2 and firstLineSplitDisasm[0] == 'DCD' \
               and idc.isCode(idc.GetFlags(idc.get_name_ea(0, firstLineSplitDisasm[1])))

    def _getFuncPtrArrayDisasm(self, bytes, elemsPerLine, thumbMode=True):
        subpad = '+1' if thumbMode else ''
        func_eas = self._combineBytes(bytes, 4)
        newLineCounter = 0
        disasm = 'DCD '
        for func_ea in func_eas:
            if disasm[-1] == '\n': disasm += '\tDCD '
            disasm += '%s, ' % (idc.get_name(func_ea) + subpad)
            newLineCounter += 1
            if newLineCounter % elemsPerLine == 0:
                disasm = (disasm[len(disasm) - 2:] == ', ' and disasm[:-2] or disasm) + '\n'
            disasm = (disasm[len(disasm) - 2:] == ', ' and disasm[:-2] or disasm)
        return disasm

    @staticmethod
    def _combineBytes(bytes, newDataSize):
        """
        Converts an array of bytes into an array of halfwords, or an array of words, or whatever the new data size is.
        Note that the passed b
        :raises ValueError: if list of bytes is not a multiple of newDataSize
        :param bytes: (list(int)) list of bytes. Length must be a multiple of newDataSize
        :param newDataSize: (iut) number of bytes in each element
        :return: an array of each element
        """
        if len(bytes) % newDataSize != 0: raise ValueError('bytes is not a multiple of newDataSize')
        # generate new list
        output = []
        i = 0
        while i + newDataSize - 1 < len(bytes):
            n = 0
            for j in range(newDataSize - 1, -1, -1):
                n |= bytes[i + j] << 8 * j
            output.append(n)
            i += newDataSize
        return output

    def _convertTabs(self, disasm):
        # convert tabs to spaces
        disasm = disasm.replace('\t', '    ', disasm.count('\t'))
        return disasm

    def _lowerCode(self, disasm):
        # type: (str) -> str
        """
        converts code to lower case except for names (like testFUNC in BL testFUNC)
        :param disasm: disassembly to filter
        :return: filtered disasembly
        """
        # type: (str) -> str
        # TODO [OPTIMIZE]: Perform the lowering in a more systematic fashion. There are only a handful of keywords to
        # lower. (This can take up to 278 us)

        # trivial cases where the whole statement is lower:
        # PUSH/POP, SVC, BX, STMIA, LDMIA
        if (disasm[0] == 'P'
                or disasm.startswith('BX')
                or disasm.startswith('SVC')
                or disasm.startswith('LDM')
                or disasm.startswith('STM')
        ):
            return disasm.lower()


        if disasm[0] == '.' and '// ' in disasm:
            searchDisasm = disasm[disasm.index('// ')+3:] # for fake instructions commented out
        else:
            searchDisasm = disasm

        # always lower the first word (mnemoic)
        if ' ' in searchDisasm:
            firstSpaceIdx = searchDisasm.index(' ')
            mnemoic = searchDisasm[: firstSpaceIdx]
            disasm = disasm.replace(mnemoic, mnemoic.lower(), 1)
            # if there are only two keywords (one space), only the mnemoic is lowered.
            # Those are BL xxxx, B xxxx, nop, etc.
            if (mnemoic[0] == 'B' and mnemoic != 'BIC') or mnemoic == 'SVC':
                return disasm
            searchDisasm = searchDisasm[firstSpaceIdx+1:]

        words = list(filter(None, re.split('[ \t+=\#,()\[\]]', searchDisasm)))
        for word in words:
            if ( (word[0] == 'R' and word[1:].isalnum())
                or (word == 'PC' or word == 'LR' or word == 'SP')
                or (word.startswith('0x'))
            ):
                disasm = disasm.replace(word, word.lower(), 1)

        return disasm

    def _lowerCodeOLD(self, disasm):
        words = list(filter(None, re.split('[ \t//()]', disasm)))

        for word in words:
            # filter specific conditions
            if (word[0] == '=' or  # special case, do not filter pool comments/names
                    (word[0] == '#' and word[1:].isalnum())): # filter immediate opcode text
                continue

            # lower the word in the disasm if it's not a global symbol
            if idc.get_name_ea(self.ea, word) == idaapi.BADADDR:
                disasm = disasm.replace(word, word.lower(), 1)

        return disasm


    def _convertAlignDisasm(self, disasm):
        # type: (str) -> str
        """
        converts ALIGN <n> to a consistent equivalent compatible with GNU assembler standards
        ALIGN <n> -> .balign <n>, 0x00
        This tells the assembler to pad with zeros, and to align to an address divisible by n
        :param disasm: align disassembly to convert
        :return: the converted disassembly
        """
        words = list(filter(None, re.split('[ \t]', disasm)))
        # nothing to convert
        if words[0] != "ALIGN":
            return disasm

        # filter comment
        if ';' in words[1]:
            words[1] = words[1][:words[1].index(';')]

        # obtain n from ALIGN <n>
        if "0x" in words[1]:
            n = int(words[1], 16)
        else:
            n = int(words[1])

        # TODO: ALIGN <n> for n >= 8 seems to modify data before it. Why??
        if n <= 4:
            disasm = ".balign %s, 0x00" % words[1]
        else:
            # compute as .word and .byte instead.
            remainingBytes = n - (self.ea % n)

            disasm = ''
            # pad with words
            wordPadded = False
            if remainingBytes > 4:
                disasm += '.word '
            while remainingBytes > 4:
                if not wordPadded:
                    wordPadded = True
                disasm += '0, '
                remainingBytes -= 4
            # remove trailing ", " if it exists
            if wordPadded:
                disasm = disasm[:-2]

            # pad with bytes
            bytePadded = False
            if remainingBytes > 0:
                # in case both word padding and byte padding is needed, format that right
                if wordPadded:
                    disasm += '\n\t.byte '
                else:
                    disasm += '.byte '
            while remainingBytes > 0:
                if not bytePadded:
                    bytePadded = True
                # we have word padded, in case we byte pad too
                if not wordPadded:
                    wordPadded = True
                disasm += '0, '
                remainingBytes -= 1
            # remove trailing ", " if it exists
            if bytePadded:
                disasm = disasm[:-2]

        return disasm

    def _convertImmediateReferences(self, disasm):
        """
        IDA puts references/symbols in immediete values as a way of indicating that those instructions
        really are accessing that memory, but the compiler does not allow for this formatting, so the
        immediates are calculated and provided as hex instead
        This converts instructions that look like this: ldr r2, [r2,#(dword_809EEF4+0x1F8 - 0x809f0e4)]

        The order of when this is called matters. Do not call this after converting pool instructions.
        :param disasm: the source disassembly, it's returned if there's nothing to change
        :return: the source disasm or the new one if there are changes to be made
        """
        # TODO[BUG] (slight): doesn't account for cases like  'STRB R7, [R6,#byte_5]' because the pointe is not taken as valid.
        if '#' in disasm:
            xrefs = self.getXRefsFrom()
            # if any references are present at this line
            if len(xrefs[0]) != 0 or len(xrefs[1]) != 0:
                # OK! we need to convert the immediate reference with a hexadecimal equivelant
                if '#(' in disasm:
                    expression = disasm[disasm.index('('):disasm.index(')')+1]
                else:
                    expression = disasm[disasm.index('#')+1:]
                    if ' ' in expression:
                        expression = expression[:expression.index(' ')]
                    if ']' in expression:
                        expression = expression[: expression.index(']')]
                isDigit = expression.isdigit()
                if not isDigit and  expression[0:2] == '0x':
                    try:
                        int(expression, 16)
                        isDigit = True
                    except:
                        pass
                if not isDigit:
                    imms = idaapi.get_operand_immvals(self.ea, 1)
                    if len(imms) == 1:
                        disasm = disasm[:disasm.index(expression)] + '0x%X' % (imms[0]) \
                                 + disasm[disasm.index(expression)+len(expression):] + ' // %s' % (expression)
        return disasm