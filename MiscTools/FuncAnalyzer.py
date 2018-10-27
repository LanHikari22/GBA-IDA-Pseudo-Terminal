import idaapi
import idc

from IDAItems import Function, Instruction

def traceRegisterUsages(func_ea, reg, writeIdx):
    """
    Runs through the function and traces all accesses to a register with a particular writeIdx.
    The writeIdx with the register forms the current local variable in that register.
    :param func_ea: effective address of function to analyze
    :param reg: the register to trace, 0 to 15
    :param writeIdx: the counts of writes to this register before being traced. If 0, it will be traced
    as an input register to the function. If 1, it will have to be written to once before being traced.
    And so on.
    :return: list of EAs of register usages/reads.
    """
    raise(NotImplemented())

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