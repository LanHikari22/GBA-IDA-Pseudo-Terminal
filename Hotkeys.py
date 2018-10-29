import idaapi
idaapi.require('IDAItems.Data')
idaapi.require('IDAItems.Function')
idaapi.require('IDAItems.Instruction')
idaapi.require('MiscTools.Operations')
idaapi.require('MiscTools.miscTools')
idaapi.require('MiscTools.FuncAnalyzer')
idaapi.require('DisasmTools.GNUDisassembler')
import MiscTools.miscTools as mt
import MiscTools.TimeProfiler as tp
from MiscTools import FuncAnalyzer
from IDAItems import Data, Function, Instruction

import idc
import ida_enum
import ida_ua
from idc_bc695 import AddHotkey
from idc import here
import MiscTools.Operations as ops
import SrchTools.nextTools as next
import FixTools.fixTools as fix
import DisasmTools.GNUDisassembler as dis
from Definitions.Environment import env

compiled_functions = {}

def ida_run_python_function(func_name):
    if func_name not in compiled_functions:
        ida_func_name = "py_%s" % func_name
        idaapi.CompileLine('static %s() { RunPythonStatement("%s()"); }'
                           % (ida_func_name, func_name))
        compiled_functions[func_name] = ida_func_name
        return ida_func_name
    else:
        return func_name


def actionZ():
    pass
    # return next.ret(here(), end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    # return next.byDataElement(here(), lambda ea: ('POP' in idc.GetDisasm(ea) and 'PC' in idc.GetDisasm(ea))
    #                                              or 'PC, LR' in idc.GetDisasm(ea),
    #                           end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    # fix.fixThumbPushPopFuncRanges(Function.Function(here()-4).func_ea, here())
    # return next.unkptr(here())
    return ops.tillName(here(), ops.delShiftedContent)


def actionX():
    # Mainly for removing things, or fixing things.
    # return ops.tillName(here(), ops.delShiftedContent)
    fix.collapseUnknowns(*env['gameFiles'][mt.ea2gf(here())])

def actionA():
    # print(ops.arrTillName(here()))
    print(ops.arrTillRef(here()))


def actionS(ea=None):
    # Mainly for search-type actions or analysis
    if not ea: ea = here()

    # output = next.unkptr(here(), end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    # output = next.red(here(), end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    # if output == idaapi.BADADDR:
    #     print(False)

    global v, cur
    idaapi.jumpto(v[cur])
    print('%07X [%d/%d]' % (v[cur], cur, len(v)))
    cur += 1

    # ops.tillName(here(), lambda ea: idc.SetRegEx(ea, "T", 0, idc.SR_user))
    # pt.misc.getLZ77CompressedSize(pointerOf(here()) - (1<<31))

def actionQ():
    # print(ops.arrTillName(here()))
    idc.jumpto(env['gameFiles'][mt.ea2gf(here())][1])
    print('jumped to %s' % mt.ea2gf(here()))

def actionW():
    # fix.fixThumbPushPopFuncRanges(Function.Function(here() - 4).func_ea, here())
    fix.makeThumb(*env['gameFiles'][mt.ea2gf(here())])
    pass

# Convenient Actions
#
def actionF():
    """
    Shift+F - Display current file
    """
    gfs = env['gameFiles']
    gf = mt.ea2gf(here())
    fileAddr = here() - gfs[gf][0]
    size = gfs[gf][1] - gfs[gf][0]
    # get last name found
    ea = here()
    while not idc.Name(ea):
        ea -= 1
    relAddr = here() - ea
    print('%s+0x%X::<%s>+0x%X (%d%%)' % (gf, fileAddr, idc.Name(ea), relAddr, float(fileAddr) / size * 100))

def actionI():
    """
    Import files for quick access to functions not registered within the pseudoterminal
    """

    status = True
    status = status and dis.readStructMacro("dev/dis/bn6f/include/structs/Toolkit.inc")
    status = status and dis.readStructMacro("dev/dis/bn6f/include/structs/GameState.inc")
    status = status and dis.readStructMacro("dev/dis/bn6f/include/structs/BattleObject.inc")
    print(status)

def actionP():
    """
    Profiling Action. Time Profiling and other analyses go here.
    """
    # tp.runTimeTests()
    n = 10
    x = lambda ea: Data.Data(ea).__str__()
    t, output = tp.avgTime_us(n, x, here())
    print('[%03d us] %s' % (t, Data.Data(here()).getDisasm()))

def actionT():
    """
    Test Action. Scratchpad, you can erase this.
    """

    # for ea in range(0x3005B00, 0x3007FFF):
    #     if idc.Name(ea):
    #         print('.equ %s, 0x%07x' % (idc.Name(ea), ea))

    # print(mt.getLabelsWithSpaceDirective(0x2009450, 0x203a9b0))
    # print(mt.getLabelsWithSpaceDirective(0x203C4A0, 0x203F7E4))

    ea = 0x8000000
    while ea < 0x8800000:
        if Function.isFunction(ea):
            f = Function.Function(ea)
            # markToolkit(f.func_ea)
            markStructFromToolkit(f.func_ea, 0x3C, 'oGameState')
            ea += f.getSize(withPool=True)
        else:
            ea += Data.Data(ea).getSize()


def markToolkit(func_ea):
    f = Function.Function(func_ea)
    toolkitAccesses = FuncAnalyzer.traceRegVar(f.func_ea, f.func_ea + f.getSize(withPool=False), 10, 0)
    for trace_ea in toolkitAccesses:
        # lock into the register in question
        insn = Instruction.Insn(trace_ea)
        # print('trace', hex(trace_ea), insn.ops[0].reg, idc.GetDisasm(trace_ea))
        if insn.isComputationalInsn():
            regWrites = FuncAnalyzer.traceRegWrites(f.func_ea, f.func_ea + f.getSize(withPool=False),
                                                    insn.ops[0].reg)
            # TODO: traceRegWrites messes up insn
            insn = Instruction.Insn(trace_ea)
            # find the relevent register variable to trace
            regVarIdx = FuncAnalyzer.getRegWriteIndex(trace_ea, regWrites)
            insn = Instruction.Insn(trace_ea)
            # trace all reads to this register variable in particular
            # print('args', f.func_ea, f.func_ea + f.getSize(withPool=False),
            #                                           insn.ops[0].reg, regVarIdx)
            structAccesses = FuncAnalyzer.traceRegVar(f.func_ea, f.func_ea + f.getSize(withPool=False),
                                                      insn.ops[0].reg, regVarIdx)
            # those now will represent all registers R10 moved to, and thus, all of those accesses
            # are accesses to the R10 struct
            for access in structAccesses:
                # print(hex(access), idc.GetDisasm(access))
                # now mark with Toolkit enum
                if Instruction.Insn(access).ops[1].type == ida_ua.o_displ:
                    idc.op_enum(access, 1, idc.get_enum('oToolkit'), 0)
    return True

def markStructFromToolkit(func_ea, structOff, structName):
    f = Function.Function(func_ea)
    toolkitMovs = FuncAnalyzer.traceRegVar(f.func_ea, f.func_ea + f.getSize(withPool=False), 10, 0)
    for trace_ea in toolkitMovs:
        # lock into the register in question
        insn = Instruction.Insn(trace_ea)
        if insn.isComputationalInsn():
            regWrites = FuncAnalyzer.traceRegWrites(f.func_ea, f.func_ea + f.getSize(withPool=False),
                                                    insn.ops[0].reg)
            # TODO: traceRegWrites messes up insn
            insn = Instruction.Insn(trace_ea)
            # find the relevent register variable to trace
            regVarIdx = FuncAnalyzer.getRegWriteIndex(trace_ea, regWrites)
            insn = Instruction.Insn(trace_ea)
            # trace all reads to this register variable in particular
            # print('args', f.func_ea, f.func_ea + f.getSize(withPool=False),
            #                                           insn.ops[0].reg, regVarIdx)
            toolkitAccesses = FuncAnalyzer.traceRegVar(f.func_ea, f.func_ea + f.getSize(withPool=False),
                                                      insn.ops[0].reg, regVarIdx)
            # those now will represent all registers R10 moved to, and thus, all of those accesses
            # are accesses to the R10 struct
            for access in toolkitAccesses:
                # now mark with Toolkit enum
                accessInsn = Instruction.Insn(access)
                if accessInsn.ops[1].type == ida_ua.o_displ:
                    if accessInsn.ops[1].addr == structOff:
                        print(hex(access), idc.GetDisasm(access))

                        structAcccesses = FuncAnalyzer.traceRegVar(f.func_ea, f.func_ea + f.getSize(withPool=False),
                                                                   accessInsn.ops[0].reg, regVarIdx+1)
                        for structAccess in structAcccesses:
                            print(hex(structAccess), idc.GetDisasm(structAccess))
                            idc.op_enum(structAccess, 1, idc.get_enum(structName), 0)
    return True

# Quick Action commands
def setHotkeys():
    """
    This compiles the hot key functions and maps them so they can be used with shortcuts in IDA
    """
    AddHotkey("Shift+Z", ida_run_python_function("actionZ"))
    AddHotkey("Shift+X", ida_run_python_function("actionX"))
    AddHotkey("Shift+A", ida_run_python_function("actionA"))
    AddHotkey("Shift+S", ida_run_python_function("actionS"))
    AddHotkey("Shift+Q", ida_run_python_function("actionQ"))
    AddHotkey("Shift+W", ida_run_python_function("actionW"))

    # Perm-mapped
    AddHotkey("Shift+F", ida_run_python_function("actionF"))
    AddHotkey("Shift+I", ida_run_python_function("actionI"))
    AddHotkey("Shift+P", ida_run_python_function("actionP"))
    AddHotkey("Shift+T", ida_run_python_function("actionT"))

    print('Hotkeys set!')

if __name__ == '__main__':
    setHotkeys()