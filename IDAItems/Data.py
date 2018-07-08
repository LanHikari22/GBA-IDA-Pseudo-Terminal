#
# @Author Lan
# This module classifies a Data type and defines operations done on them using the IDA API
#
import idaapi
import idautils
import idc
import re

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
        while idc.get_item_size(ea) > size:
            ranLoop = True
            size = idc.get_item_size(ea)
            ea -= 1
        if ranLoop:
            # we just hit a failure condition, so the previous one is the correct one!
            ea += 1
        self.ea = ea

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

    def getComment(self):
        """
        :return: non-repeatable comment, prioritizes GUI-added comments over API added ones
        """
        return idc.get_cmt(self.ea, 0) or ''

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
        for ref in idautils.DataRefsTo(self.ea - 1):  # needed in case this is a code item
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
            pass
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
                bytes = []
                for char in idc.get_bytes(self.ea, idc.get_item_size(self.ea)):
                    bytes.append(ord(char))

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
        if idc.isStruct(flags):
            disasm = "INVALID"
        elif idc.isAlign(flags):
            disasm = idc.GetDisasm(self.ea)
        elif idc.isData(flags):
            disasm = self._getDataDisasm(self.ea)
        else:
            disasm = idc.GetDisasm(self.ea)
            disasm = self._filterComments(disasm)
            while '  ' in disasm: disasm = disasm.replace('  ', ' ')
        return disasm

    def getDisasm(self):
        """
        :return: transformed disassembly so that it's functional with the gcc assembler
        """
        disasm = self.getOrigDisasm()
        flags = idc.GetFlags(self.ea)
        if idc.isAlign(flags):
            disasm = self._convertAlignDisasm(disasm)
        elif idc.isData(flags) or idc.isUnknown(flags):
            disasm = self._convertData(disasm)
        elif idc.isCode(flags):
            disasm = self._convertCode(self.ea, disasm)
            # make code small case
            disasm = self._lowerCode(disasm)
        disasm = self._convertTabs(disasm)
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
            disasm = name + ":"
            # only add a new line for code labels
            if self.isCode():
                disasm += "\n"

        # include disassembly
        disasm += "\t" + self.getDisasm()
        # include comment
        comment = self.getComment()
        if comment:
            disasm += "  // " + comment

        disasm = self._convertTabs(disasm)
        return disasm

    def findPoolFunction(self):
        # type: () -> int
        """
        If this data item is within the pool of a function, that function's ea is returned
        otherwise, None is returned. The function is first found by traversing back in ea, and computing the poolsize
        of the function. If that matches, then the data itsem must have at least one code xref from that function.
        :return: None or the start address of the function containing the data item in its pool
        """
        raise (NotImplemented())

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

    def _convertCode(self, ea, disasm):
        """
        Just removing 'S' from instructions like MOVS.
        :param ea: (long) addr of disasm
        :param disasm: (str) disasm to transform
        :return: (str) converted disasm
        """
        flags = idc.GetFlags(ea)
        output = disasm  # Default case, no modifications
        if idc.isCode(flags):
            # some instructions take no operands, like NOP
            instName = disasm[:disasm.index(' ')] if ' ' in disasm else disasm

            # if the instruction is THUMB, it cannot have an 'S' in it...
            if self.getSize() == 2 and instName[-1] == 'S':
                output = instName[:-1] + ' ' + output[len(instName):].lstrip()
                instName = instName[:-1]

            # adjust instruction spacing TODO: tabs or pads for instruction?
            output = instName + ' ' + output[len(instName):].lstrip()

            # if the instruction is a pool instruction, the format should be changed
            try:
                    output = self._getPoolDisasm()
            except DataException:
                pass

        return output

    def __str__(self):
        """
        :return: (str) The disassembly, but in a disassembler-compatible manner!
        """
        name = self.getName() and self.getName() + ':\n' or ''
        return self.getFormattedDisasm()

    def _getFlags(self):
        return idc.GetFlags(self.ea)

    def _convertData(self, disasm):
        """
        Simply replaces occurrances of DCD/DCB with what is compatible with the assembler
        :param disasm: disassembly to convert
        :return: converted disassembly
        """
        while 'DCD' in disasm: disasm = disasm.replace('DCD', '.word')
        while 'DCW' in disasm: disasm = disasm.replace('DCW', '.half')
        while 'DCB' in disasm: disasm = disasm.replace('DCB', '.byte')

        return disasm

    def _convertComments(self, disasm):
        return disasm.replace(';', ' //', disasm.count(';'))
        pass

    def _getDataDisasm(self, ea, dispLabel=True, elemsPerLine=-1):
        """
        You cannot get array data using getdisasm. The disassembly has to be extracted differently.
        This identifies the data in question, and gets its disassembly
        :param ea: the effective address of the item to get the disassembly of
        :param dispLabel: if a data element is a pointer, the name (or name+1) is displayed instead
        :param elemsPerLine: if 0, maximum will be used. if <0, it'll be parsed from the database. otherwise, it's n.
        :return: the disasssembly of the data item
        """
        # First, do the easy cases that just work with GetDisasm
        flags = idc.GetFlags(ea)
        if idc.is_data(flags) and idc.is_byte(flags) and idc.get_item_size(ea) == 1:
            pass
        elif idc.is_data(flags) and idc.is_word(flags) and idc.get_item_size(ea) == 2:
            pass
        elif idc.is_data(flags) and idc.is_dword(flags) and idc.get_item_size(ea) == 4:
            pass
        if idc.is_data(flags) and (idc.is_byte(flags) and idc.get_item_size(ea) == 1
                                   or idc.is_word(flags) and idc.get_item_size(ea) == 2
                                   or idc.is_dword(flags) and idc.get_item_size(ea) == 4):
            # normal case where an int is not misread as a reference
            content = Data(ea).getContent()
            if self.isPointer(content) or idc.Name(ea) == '':
                disasm = idc.GetDisasm(ea)  # very simple, this works.
            else:
                # build the disassembly
                if idc.is_byte(flags): op = 'DCB'
                elif idc.is_word(flags): op = 'DCW'
                else: op = 'DCD'
                disasm = op + ' ' + '0x%X' % content
            return self._filterComments(disasm)
        else:  # The weird case... an array. I don't know why it's weird. IDA doesn't like it!
            # It is assumed this is an array, but the type is unknown. Imply type based on disasm of first line!

            # analysis on the array is based on the very first line
            firstLineSplitDisasm = list(filter(None, re.split('[ ,]', idc.GetDisasm(ea))))
            dataType = firstLineSplitDisasm[0]

            # Grab all of the bytes in the array
            arr = self.getContent()

            # determine the number of elements per line, if 0 (default) is specified, then it's parsed instead
            if elemsPerLine < 0:
                commentWords = len(list(filter(None, re.split('[ ,]', self.getComment()))))
                # -1 to not include type, ex: DCB, DCD... But comments can exist on the first line too!
                elemsPerLine = len(firstLineSplitDisasm) - 1 - commentWords
            elif elemsPerLine == 0:  # when specifying 0, all will show in one line!
                elemsPerLine = len(arr)

            # determine if this is normal data, or pointers if dispLabel is enabled
            if dispLabel:
                isPointerArr = self.hasPointer()
            else:
                isPointerArr = False

            # generate disassembly for array
            disasm = dataType + ' '
            elemIndex = 0
            for elem in arr:
                # tab if new line
                if disasm[-1] == '\n': disasm += '\t%s' % (dataType + ' ')
                # add element and increment counter until new line
                # if it's a pointer, display its label not just the number
                if isPointerArr:
                    name = idc.Name(elem)
                    if name:
                        disasm += "%s, " % name
                    else:
                        # try name+1 in case of CPU mode differences in address
                        name = idc.get_name(elem - 1)
                        if name:
                            disasm += "%s+1, " % name
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

    def _filterComments(self, disasm):
        # filter comments out. this must be a one-line disasm.
        if '\n' in disasm: raise (DataException("disasm is not a one line"))
        if ';' in disasm: disasm = disasm[:disasm.index(';')]
        return disasm

    def hasPointer(self):
        flags = idc.GetFlags(self.ea)
        output = False
        content = self.getContent()
        try:
            for word_ea in content:
                if self.isPointer(word_ea):
                    output = True
        except TypeError:
            # in case the data item is not an array
            pass
        return output

    def isPointer(self, ea):
        # to account for the fact that the address can have a +1 or not for CPU mode switch
        # in case of +1 for different CPU mode, both ea and ea-1 are considered
        # any value less than 0x01000000 is likely not a pointer
        output = ea > 0x01000000 and (idaapi.get_name(ea) != '' or idaapi.get_name(ea - 1) != '')
        return output

    def _getPoolDisasm(self):
        # type: () -> str
        """
        Converts pool to linker compatible version. If the instruction is not a pool
        instruction

        :param ea: ea of inst
        :param arm: True if arm, false if not. -8/-4 (-2 instructions due to pipeline)
        :return: disassembly with the correct LDR/STR [PC, ...] format
        :raise: DataException if conversion is impossible
        """

        disasm = idc.GetDisasm(self.ea)

        # must be a load or store
        if "LDR" not in disasm:
            raise(DataException('attempt to convert pool in non-pool inst'))

        # retrieve the instrution and register used
        words = list(filter(None, re.split('[ \t]', disasm)))

        inst = words[0]
        no_inst_disasm = disasm[len(inst):].lstrip()
        reg = words[1]

        # it's not a pool instruction if it ends with ']' (ldr r0, [r1] vs ldr r0, =beep)
        if disasm[-1] == ']':
            raise(DataException('attempt to convert pool in non-pool inst'))

        # determine whether it's arm or thumb
        arm = self.getSize() == 4

        # there must be xrefs, LDR/STR must not be register relative
        xrefsFrom = self.getXRefsFrom()

        if not len(xrefsFrom[1]):
            raise(DataException('%07X: attempt to convert pool in non-pool inst' % self.ea))

        # sometimes, xrefsFrom point to both content_ra and pool_ea. order is inconsistent
        pool_ea = -1

        # we're using the LDR Rx, =... format
        if '=' in words[2]:
            # assert '=' is the first char. it makes no sense otherwise
            if words[2][0] != '=':
                raise (DataException('%07X: found = in a weird place in PC-relative load' % self.ea))
            # grab the value in the =. That content must be consistent with pool_ea's content
            instName = words[2][1:]
            # filter out potential ()s
            if instName[0] == '(':
                instName = instName[1:-1]
            # filter out index
            if '+' in instName:
                instName = instName[:instName.index('+')]
            for xref in xrefsFrom[1]:
                # there are always two options, the content, or teh pool_ea. Make sure we're not
                # grabbing content
                if idc.Name(xref) and idc.Name(xref) != instName:
                    pool_ea = xref
                    break
        # we're using the LDR RX, name format.
        else:
            # the correct xref is the one with the identical name in the instruction
            for xref in xrefsFrom[1]:
                d = Data(xref)
                if (d.getName() == words[2] or
                                '+' in words[2] and d.getName() == words[2][:words[2].index('+')]):
                    pool_ea = xref

        # assert that a pool_ea was found
        if pool_ea == -1:
            raise (DataException('%07X: no pool_ea was found' % self.ea))

        # confirm that the content being loaded is an int. can't load anything else to a register!
        poolData = Data(pool_ea)

        content = poolData.getContent()

        if type(content) != int and type(content) != long:
            raise(DataException("%07X: attempt to load non-int to register" % pool_ea))

        # write the actual pool value being loaded for readability
        content = Data(content)
        if content.isPointer(content.ea):
            # figure out unsync between xref of pool and content data... that's the index +!
            # depending on the data format of the value in the db, it may have no xrefs...
            if poolData.getXRefsFrom()[1]:
                contentXref = poolData.getXRefsFrom()[1][0]
                if contentXref - content.ea > 0:
                    index = "+%d" % (contentXref - content.ea)
                elif contentXref - content.ea  < 0:
                    index = "-%d" % (content.ea - contentXref)
                else:
                    index = ''
            else:
                index = ''

            cmt = "%s%s" % (content.getName(), index)
        else:
            cmt = "=0x%X" % content.ea

        # the amount of shift to apply depends on the instruction mode
        if arm:
            shift = 8
        else:
            # this is more complicated since it can be word unaligned
            if (pool_ea - self.ea - 4) % 4 != 0:
                # to achieve word alignment, we round down to the last word aligned value
                shift = 2
            else:
                # normal case, PC is 2 instructions ahead
                shift = 4
        # TODO: tabs or pads for instructions?
        return "%s %s [PC, #0x%07X-0x%07X-%d] // %s" % (inst, reg,
                                                        pool_ea, self.ea, shift, cmt)

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
        words = list(filter(None, re.split('[ \t//()]', disasm)))
        for word in words:
            # special case, do not filter pool comments/names
            if word[0] == '=':
                continue
            # lower the word in the disasm if it's not a global symbol
            if idc.get_name_ea(self.ea, word) == 0xffffffffL:
                disasm = disasm.replace(word, word.lower(), 1)
            # an exceptional case is symbols not globally defined... like stack symbols
            if 'SP' in word.upper() and '+' in word and '#' in word and ']' in word:
                stackVar = word[word.index('+')+1:word.index(']')] # [SP,#0xXX+<stackVar>]
                disasm = disasm.replace(stackVar.lower(), stackVar, 1)

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