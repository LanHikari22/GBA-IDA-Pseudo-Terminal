import idaapi
idaapi.require('MiscTools.Operations')
idaapi.require('MiscTools.miscTools')
import MiscTools.miscTools as mt
from MiscTools import TimeProfiler
from IDAItems import Data, Function

import idc
from idc_bc695 import AddHotkey
from idc import here
import MiscTools.Operations as ops
import SrchTools.nextTools as next
import FixTools.fixTools as fix
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

    output = next.unkptr(here(), end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    # output = next.red(here(), end_ea=env['gameFiles'][mt.ea2gf(here())][1])
    if output == idaapi.BADADDR:
        print(False)

    # global v, cur
    # idaapi.jumpto(v[cur])
    # print('%07X [%d/%d]' % (v[cur], cur, len(v)))
    # cur += 1

    # ops.tillName(here(), lambda ea: idc.SetRegEx(ea, "T", 0, idc.SR_user))
    # pt.misc.getLZ77CompressedSize(pointerOf(here()) - (1<<31))

def actionQ():
    print(ops.arrTillName(here()))

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
    :return:
    """
    status = True
    status = status and readStructMacro("dev/dis/bn6f/include/structs/Toolkit.inc")
    status = status and readStructMacro("dev/dis/bn6f/include/structs/GameState.inc")
    status = status and readStructMacro("dev/dis/bn6f/include/structs/BattleObject.inc")
    print(status)

def actionT():
    """
    Test Action. Scratchpad, you can erase this.
    :return:
    """
    # for ea in range(0x3005B00, 0x3007FFF):
    #     if idc.Name(ea):
    #         print('.equ %s, 0x%07x' % (idc.Name(ea), ea))

    # print(mt.getLabelsWithSpaceDirective(0x2009450, 0x203a9b0))
    # print(mt.getLabelsWithSpaceDirective(0x203C4A0, 0x203F7E4))
    TimeProfiler.runTimeTests()


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
    AddHotkey("Shift+T", ida_run_python_function("actionT"))

    print('Hotkeys set!')

def readStructMacro(path):
    """
    Parses struct macros and updates a corresponding enum with their values
    :param path: the path to the file containing the macros
    :return:
    """
    # parse macro file
    macroFile = open(path)
    members = []
    structName = ''
    for line in macroFile.readlines():
        if line.startswith('\struct_entry'):
            if ', ' in line:
                name = line[line.index(')')+1 : line.index(',')]
                size = line[line.index(', ')+2 :].rstrip()
                if '//' in size:
                    size = size[:size.index('//')].rstrip()
                if size.startswith('0x'):
                    size = int(size, 16)
                else:
                    size = int(size)
            else:
                name = line[line.index(')')+1 :].rstrip()
                if '//' in name:
                    name = name[:name.index('//')].rstrip()
                size = 0
            members.append((name, size))
        if line.startswith('def_struct_offsets'):
            structName = line[line.index(', ')+2:].rstrip()

    print('parsed struct "' + structName + '"')
    # read into enum
    enumId = idc.get_enum(structName)
    if enumId == idaapi.BADADDR:
        enumId = idc.add_enum(idaapi.BADADDR, structName, idaapi.decflag())
    # add members in
    offset = 0x00
    for member, size in members:
        idc.add_enum_member(enumId, structName + member, offset, idaapi.BADADDR)
        offset += size

    return True
if __name__ == '__main__':
    setHotkeys()