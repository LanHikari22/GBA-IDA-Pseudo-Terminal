import idaapi
import idc
import ida_ua

from IDAItems import Function, Instruction

def traceRegVar(start_ea, end_ea, reg, writeIdx):
    """
    Takes a list of instructions as it is unsafe to reinitiate Instruction objects
    Runs through the function and traces all accesses to a register with a particular writeIdx.
    The writeIdx with the register forms the current local variable in that register.
    :param insts: instructions to analyze. list of IDAItems.Instruction objects
    :param reg: the register to trace, 0 to 15
    :param writeIdx: the counts of writes to this register before being traced. If 0, it will be traced
    as an input register to the function. If 1, it will have to be written to once before being traced.
    And so on.
    :return: list of EAs of register usages/reads or False if not in a valid function
    """

    writeCount = 0
    accesses = []
    ea = start_ea
    while ea < end_ea:
        insn = Instruction.Insn(ea)
        # if the reg is written, its writeCount increases
        if insn.isComputationalInsn():
            # check read accesses, even if a write occurs to this register, its previous value can be read
            for i in range(1, ida_ua.UA_MAXOP):
                if (insn.ops[i].type in [ida_ua.o_reg, ida_ua.o_displ] # normal reg or ldr/str
                    and writeCount == writeIdx
                    and insn.ops[i].reg == reg
                ):
                    # print(hex(ea), idc.GetDisasm(ea))
                    accesses.append(ea)
                    break
            if insn.ops[0].reg == reg:
                writeCount += 1
        else:
            for i in range(0, ida_ua.UA_MAXOP):
                if (insn.ops[i].type in [ida_ua.o_reg, ida_ua.o_displ] # normal reg or ldr/str
                    and writeCount == writeIdx
                    and insn.ops[i].reg == reg
                ):
                    accesses.append(ea)
                    break
        ea += idc.get_item_size(ea)
    return accesses

def traceRegWrites(start_ea, end_ea, reg):
    """
    Takes a list of instructions as it is unsafe to reinitiate Instruction objects
    Specifies all the times the register has been written
    :param insts: list of instructions to analyze.
    :param reg: int. register number to check writes to
    :return: list of eas of writes, or False if not in code
    """

    writes = []
    ea = start_ea
    while ea < end_ea:
        insn = Instruction.Insn(ea)
        # if the reg is written, its writeCount increases
        if insn.isComputationalInsn():
            if insn.ops[0].reg == reg:
                writes.append(ea)
        ea += idc.get_item_size(ea)
    return writes

def getRegWriteIndex(ip, writeTrace):
    """
    looks through instructions-relative addresses of when the register was written,
    and computes its writeIndex.
    If it was never written or ip is less than the range of writeTrace, then it's 0.
    If ea is greater than the range, it's len(writeTraces)
    :param ip: analysis-region relative address to compute writeIndex to register
    :param writeTrace: a list of addresses in which the register has been written
    :return: the write index of the register.
    """
    output = 0
    for trace_ea in writeTrace:
        if ip >= trace_ea:
            output += 1
    return output


def guessFuncSig(func_ea):
    # type: (int) -> (list[str], list[str])
    """
    Guesses the signature of the current function based on the input registers it uses (R0-R3) and
    based on the output registers it may return. (most likely R0, but sometimes multiple registers are returned)
    It also checks for whether the zero flag have been written to by the function without being used, then it would
    return the zero flag.
    :param func_ea: the linear address of the function to analyze
    :return: the list of types for the input parameters, and for the returns.
    'zf' can be included, in the return types list.
    """
    # input register parameters -- r0 through r3. If they are identified as an input, this will store
    # a string of their type. (States -- None: No param found yet. '': Parameter. But Unknown Type.
    paramTypes = [None, None, None, None]
    retType = None
    zf = False
    # flags
    updatedRegs = 0b0000 # if the register is updated, its flag is set
    # make sure to recognize push/pop like patterns. A register can be saved to be used later.
    savedRegs = 0b0000
    # This flag is cleared whenever R0 is updated.
    # It is set whenever R0 is used. This indicated whether the return is used or not
    usedRet = False
    # the returns of calls are remembered since their type can match with the current function
    callRets = None
    func = Function.Function(func_ea)

    ea = func.func_ea
    while ea < func.func_ea + func.getSize():
        insn = Instruction.Insn(ea)
        if insn.size != 0:
            # parse destination and source registers, if any
            if insn.ops[0].type == idaapi.o_reg:
                destReg = insn.ops[0].reg
                # now parse all source registers
                sourceRegisters = insn.getSourceRegisters()
                # if a destReg is R0~R3, set its flag
                raise(NotImplemented())
                # update return status to know whether the register is used after being set at the end of the function

            # traverse function calls if parameters weren't identified yet
            if insn.ops[0].type in [idaapi.o_far, idaapi.o_near] and None in paramTypes:
                callParams, callRets = guessFuncSig(insn.ops[0].addr)
                # deduce input parameters for this function from input parameters for the called function
                for i in range(len(callParams)):
                    if not updatedRegs & i:
                        # register is passed in as input to callee! Register it as an input of this function too!
                        raise(NotImplemented())

            # handle the push/pop register saving pattern
            if insn.itype == idaapi.NN_push:
                raise(NotImplemented())
            if insn.itype == idaapi.NN_pop:
                raise(NotImplemented())


            ea += insn.size
        else:
            ea += idc.get_item_size(ea)

    # return the params and return types

def analyzeFuncUsages(func_ea):
    # type: (int) -> list[(int, list[int])]
    """
    This analyzes calls of the passed functions and attempts to retrieve the parameters passed to the function.
    If the information is dynamic, and a parameter cannot be retrieved, it's returned as a None inside
    the list of parameters returned.
    :param func_ea: linear address of the function to analyze
    :return: A list of the call linear address, and a list of the parameters passed per call
    """
    raise(NotImplemented())

def analyzeFuncCalls(func_ea):
    # type: (int) -> list[(int, list[int])]
    """
    This analyzes all of the functions called by the passed function as well as the parameters passed to them.
    If the information is dynamic and cannot be retrieved, a parameter will be passed as None.
    :param func_ea: linear address of the function to analyze
    :return:
    """
    raise(NotImplemented())