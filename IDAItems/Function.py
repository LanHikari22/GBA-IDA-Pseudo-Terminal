#
# @Author Lan
# This module abstracts operations on Functions and CFunctions in IDAPython.
# It allows easy modification of propreties related to functions, and the
# abiility to save all modifications easily.
#

import idautils
import idaapi
import idc

from IDAItems import Data

idaapi.require("IDAItems.Data")


class FunctionException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)
        pass


class Function:
    func = None  # func_t
    func_ea = None  # ea_t

    def __init__(self, func_ea):
        """
        :raises: InvalidFunctionException if func_ea does not live within a function, or the function is not defined.
        :param func_ea: long: Effective Address of function to manipulate
        """
        # If the current address is a function process it
        if idc.get_func_flags(func_ea) != -1:

            self.func = idaapi.get_func(func_ea)
            self.func_ea = self.func.startEA

            # TODO: these shouldn't be unsupported. detect each chunk as its own function? fix func_ea
            # function chunks can give invalid behavior when definind functions!
            if self.func.tails:
                raise (FunctionException("%07X: Function Chunks are not supported" % func_ea))
        else:
            raise (FunctionException("Address %08x does not live within a function" % func_ea))

    def __str__(self):
        """
        :return: (str) The disassembly, in a format compatible with arm-none-eabi-gcc
        """
        return self.getFormattedDisasm()


    def getName(self):
        return idaapi.get_func_name(self.func_ea)

    def setName(self, funcName):
        # type: (str) -> None
        """
        Same as in Head. Kept for reference.
        :param funcName:  (str) name of the function
        """
        idc.MakeName(self.func_ea, funcName)

    def getPrototype(self):
        """
        :return: (str) representing the return type
        :raises idaapi.DecompilationFailure: if function is not decompilable
        """
        # return idc.get_type(self.func_ea) Only works if type is defined with 'y' in disassembly
        cfunc = idaapi.decompile(self.func)
        retType = idaapi.tinfo_t()
        cfunc.get_func_type(retType)
        return str(retType)

    def getFuncPtrCMacro(self):
        """
        Will return the Prototype of the function in the format:
        #define <funcName> ((<retType> (*) (<params>)) (<funcAddr>+1))
        Example:
        #define sound_play ((void (*)(int a1, int a2, int a3))(0x080005CC+1))
        this DOES assume that the function is THUMB.
        TODO: Support ARM Functions too!
        :return: (str) Function pointer in a CMacro definition.
        """
        try:
            prototype = self.getPrototype()
            retType = prototype[0:prototype.index('(')]
            params = prototype[prototype.index('(') : prototype.index(')')+1]
            funcAddr = '0x%08X' % self.func_ea
            output = '#define ' + self.getName() + ' ((' + retType + ' (*) ' + params + ') (' + funcAddr + ' +1))'
        except idaapi.DecompilationFailure:
            funcAddr = '0x%08X' % self.func_ea
            output = '#define ' + self.getName() + ' ((void (*) () (' + funcAddr + ' +1))'
        return output

    def ongoing_getParameters(self):
        """
        :return: A list of tuples of (typeName, paramName)
                 int a2 would give ('int, 'a2')
        """
        raise(NotImplemented())

    def getXRefsTo(self):
        """
        Computes a list of the names of the xrefs to the function.
        This includes all functions that call this, but also data xrefs.
        :returns: a tuple of two lists: crefs and drefs
        """
        # type: () -> (list[int], list[int])
        crefs = []
        drefs = []
        # If the current address is function process it
        if idc.get_func_flags(self.func_ea) != -1:
            # Find all code references to func
            ref = idc.get_first_cref_to(self.func_ea)
            while ref != idaapi.BADADDR:
                # name = get_func_name(ref)
                # if not name: name = "ROM:%08X" % ref
                crefs.append(ref)
                ref = idaapi.get_next_cref_to(self.func_ea, ref)
            # Find all data references to func
            for ref in idautils.DataRefsTo(self.func_ea):
                drefs.append(ref)
            for ref in idautils.DataRefsTo(self.func_ea + 1):
                drefs.append(ref)

            return crefs, drefs

    def getXRefsFrom(self):
        # type: () -> (list[int], list[int])
        """
        computes code references called from this function, and data references accessed
        if the data reference accessed is a pool variable, and it's a pointer,
        the pointer is given instead (as compliant with the LDR RX =<refInPool> syntax)
        This defines all data and code dependencies in the function
        :return:
        """
        crefs = []
        drefs = []


        # normalFlow = True
        # for ref in idautils.CodeRefsFrom(self.func_ea, normalFlow):  # XrefsFrom
        #     crefs.append(ref)
        # for ref in idautils.CodeRefsFrom(self.func_ea, not normalFlow):  # XrefsFrom
        #     crefs.append(ref)
        # for ref in idautils.CodeRefsFrom(self.func_ea-1, normalFlow):  # XrefsFrom
        #     crefs.append(ref)
        # for ref in idautils.CodeRefsFrom(self.func_ea-1, not normalFlow):  # XrefsFrom
        #     crefs.append(ref)

        # needed to identify pool variables. drefs accessing the pool may access pointers
        # in the pool. the pointers should be retrieved instead
        size_pool = self.getSize(withPool=True)
        # for each instruction
        for i in idautils.FuncItems(self.func_ea):
            for xref in idautils.XrefsFrom(i, 0):
                # if the xref is to a far or near called function
                if xref.type == idc.fl_CN or xref.type == idc.fl_CF:
                    if xref.to not in crefs:
                        crefs.append(xref.to)
                # if the xref is to a read or write data access
                if xref.type == idc.dr_W or xref.type == idc.dr_R:
                    if xref.to not in drefs:
                        # if xref.to is in the pool, then retrieve content if it's a pointer
                        if xref.to < self.func_ea + size_pool:
                            # those are the references found at the pool location
                            iteratedOnce = False
                            for poolRef in idautils.XrefsFrom(xref.to, 0):
                                if iteratedOnce:
                                    raise(FunctionException("%08X: there should only be one data xref in pool variable"
                                                            % (self.func_ea)))
                                # there should only be one in the pool refernce
                                if poolRef.to not in drefs:
                                    drefs.append(poolRef.to)
                                iteratedOnce = True
                        else:
                            drefs.append(xref.to)

        # for ref in idautils.DataRefsFrom(self.func_ea):
        #     drefs.append(ref)
        # for ref in idautils.DataRefsFrom(self.func_ea - 1):
        #     drefs.append(ref)
        return crefs, drefs

    def getComment(self):
        # type: () -> str
        """
        Sometimes the comment is repeatable (created through decomp) or not (created through disass).
        Returning disass comment
        """
        cmt = idc.get_func_cmt(self.func_ea, 1)
        if not cmt: cmt = idc.get_func_cmt(self.func_ea, 0)
        return cmt

    def setComment(self, cmt):
        # type: (str) -> ()
        """
        :param cmt: Comment to be set as a function comment
        """
        idaapi.set_func_cmt(self.func, cmt, 1)

    def getSize(self, withPool=False):
        """
        Computes the size of the function the first time this is called, and caches that computation for later
        Parsed Comment commands:
            <endpool> specifies the last element in the pool. That element's size is included in the pool.
                      to specify a function has no pool at all, put the comment command at its last instruction.
        :param withPool: (bool) somewhat of a heuristic. Computes the pool size as simply the amount of bytes since
                         the function's code portion finished (endEA) until a new code head is detected
        :return:  Returns the size of the Function in bytes: EndEA - StartEA (if no pool selected, otherwise + pool)
        """
        if not withPool: return self.func.end_ea - self.func.start_ea
        head = self.func.end_ea

        # check if the function is set to have no pool
        instSize = self.isThumb() and 2 or 4
        endCmt = idc.Comment(self.func.end_ea-instSize)
        if endCmt and '<endpool>' in endCmt:
            return self.func.end_ea - self.func.start_ea

        while not idc.isCode(idc.GetFlags(head)) :
            # manual pool computation, trust and assume that this is the last element in the pool!
            if idc.Comment(head) and '<endpool>' in idc.Comment(head):
                head += idc.get_item_size(head)
                break
            # advance to next data element
            head += idc.get_item_size(head)

        return head - self.func.start_ea

    def isThumb(self):
        """
        A thumb function must contain at least one thumb instruction with the size of 2.
        branch instructions are of size 4, although are still thumb.
        :return:
        """
        output = False
        ea = self.func_ea
        while ea < self.func_ea + self.getSize():
            size = idc.get_item_size(ea)
            if size == 2 and idc.isCode(idc.GetFlags(ea)):
                output = True
                break
            ea = ea + size
        return output


    def getBoundaries(self):
        """
        :return: Tuple of Start address and end address of function
        """
        return self.func.start_ea, self.func.end_ea

    def getPoolData(self):
        # type: () -> (list[Data.Data])
        """
        Using the computed pool size algorithm, all data items within the pool can be identified and
        created.
        :return: A list of all data items in the pool of this function
        """
        output = []
        # start from the beginning of the pool area
        ea = self.func_ea + self.getSize(withPool=False)
        while ea < self.getSize(withPool=True):
            # create and append the data item
            data = Data.Data(ea)
            output.append(data)
            # advance ea to the next item
            ea += data.getSize()
        return output

    def getFormattedDisasm(self):
        # type: () -> str
        """
        Gets the disassembly of the function by creating data elements of all
        its items, including its pool.
        :return:
        """
        ea = self.func_ea

        # specify  whether this is an arm or thumb function
        if self.isThumb():
            disasm = ".thumb\n"
        else:
            disasm = ".arm\n"

        # spefiy function comment, if available
        # put // for function comment in each line
        if self.getComment():
            comment = '// ' + self.getComment().replace('\n', '\n// ',
                                                self.getComment().count("\n")) + '\n'
        else:
            comment = ''
        disasm += comment

        # if available, provide .equs for all stack variables
        # TODO: stack variables no longer supported
        # disasm += self.getStackVarDisasm()

        # disassemble all items within the function
        while ea < self.func_ea + self.getSize(withPool=True):
            d = Data.Data(ea)
            disasm += d.getFormattedDisasm() + "\n"
            # advance to next item
            ea = ea + d.getSize()
        disasm += "// end of function %s" % self.getName()
        return disasm


    def getStackVarDisasm(self):
        """
        if the function uses stack variables with SP, their symbols should be defined
        :return:
        """
        disasm = ''
        id = idc.GetFrame(self.func_ea)
        firstMember = idc.GetFirstMember(id)
        if hasStackVars(self.func_ea):
            # first, obtain the base by finding an instruction that uses one of the stack variables
            stackVars = getStackVars(self.func_ea)
            ea = self.func_ea
            base = -1

            # TODO: maybe use get_min_spd_ea(func_ea) to get the base pointer? this stands for stack pointer delta!

            # search function instructions to find base (TODO: hacky, but i dunno how else to find base yet)
            while ea < self.func_ea + self.getSize():
                d = Data.Data(ea)
                origDisasm = d.getOrigDisasm()
                # case where the stack frame is referenced
                for var, offset in stackVars:
                    if var in origDisasm and '#' in origDisasm:
                        # cases like LDR SP, [base+var_xx]
                        if '[' in origDisasm:
                            # grab the base
                            if '+' in origDisasm:
                                base = int(origDisasm[origDisasm.index('#')+1:origDisasm.index('+')], 16)
                            else:
                                base = 0
                            # obtained base! no need to continue looping
                            break
                        # some cases like ADD SP, base+var_xx don't have '['
                        elif '+' in origDisasm:
                            base = int(origDisasm[origDisasm.index('#')+1:origDisasm.index('+')], 16)
                            # obtained base! no need to continue looping
                            break
                if base != -1:
                    break
                ea += d.getSize()
            # if base couldn't be found still, it's likely no SP access is done with variables
            if base == -1:
                base = 0

            # build up disasm based on stack vars using base-relative offsets
            for name, off in stackVars:
                relOff = base - off
                if relOff > 0:
                    disasm += ".equ %s, -0x%X\n"  % (name, abs(relOff))
                else:
                    disasm += ".equ %s, 0x%X\n"  % (name, abs(relOff))


        return disasm

def isFunction(ea):
    return idc.get_func_flags(ea) != -1

def hasStackVars(ea):
    """
    :param ea: address of the function
    :return: whether the function has stack variables or not
    """
    id = idc.GetFrame(ea)
    firstMember = idc.GetFirstMember(id)
    return firstMember != idaapi.BADADDR and firstMember != -1

def getStackVars(ea, base=-1):
    # type: (int, int) -> list[(str, int)]
    """
    Gets the stack variables associted with the function at ea
    If no base is specified, the offsets don't include the base calculation in them
    :param ea: the address of the function
    :param base: the stack base, must obtain to compute the offsets relative to it
    :return: a list of tuples, the stack variable name and its offset
    """
    stackVars = []
    id = idc.GetFrame(ea)


    firstMember = idc.GetFirstMember(id)
    # if the function has stack variables
    if firstMember != idaapi.BADADDR and firstMember != -1:
        # build up disasm based on stack vars
        lastMember = idc.GetLastMember(id)
        i = firstMember

        # Stack can be offset, first member might not be found at index 0, and all offsets must be adjusted by this
        foundFirstElement = False
        stackOffset = 0
        while i <= lastMember:
            name = idc.GetMemberName(id, i)
            off = idc.GetMemberOffset(id, name) # this is the offset in the struct... which isn't always consistent!
            size = idc.GetMemberSize(id, i)
            # append if varname is found (sometimes, None is returned because the variables are not in the next index)
            if name:
                # first variable found! this is the stack of the stack variables!
                if not foundFirstElement:
                    stackOffset = i
                    foundFirstElement = True
                if base == -1:
                    # absolute offsets appended
                    stackVars.append((name, off - stackOffset))
                else:
                    # base-relative offsets appended
                    stackVars.append((name, base - off - stackOffset))
            # sometimes, for some reason, the offset for stack variables does not follow linearly
            if size:
                i += size
            else:
                # reach next var, which might not be one size unit after the last...
                while not idc.GetMemberSize(id, i) and i <= lastMember:
                    i += 1
    return stackVars
