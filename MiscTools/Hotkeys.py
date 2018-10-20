import idaapi

import MiscTools.miscTools

idaapi.require("MiscTools.Operations")

import idc
from idc_bc695 import AddHotkey
from idc import here
import MiscTools.Operations as ops
import SrchTools.nextTools as next
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
    print("work?")
    # return next.unkptr(here())


def actionX():
    return ops.tillName(here(), ops.delShiftedContent)


def actionA():
    print(ops.arrTillName(here()))


def actionS(ea=None):
    # print('Action S')
    if not ea: ea = here()
    ops.tillName(here(), lambda ea: idc.SetRegEx(ea, "T", 0, idc.SR_user))
    # pt.misc.getLZ77CompressedSize(pointerOf(here()) - (1<<31))


# Convenient Actions
#
def actionF():
    """
    Shift+F - Display current file
    """
    gfs = env['gameFiles']
    gf = MiscTools.miscTools.ea2gf(here())
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
    pass

def actionT():
    """
    Test Action. Scratchpad, you can erase this.
    :return:
    """
    import MiscTools.TimeProfiler
    MiscTools.TimeProfiler.runTimeTests()

# Quick Action commands
def setHotkeys():
    """
    This compiles the hot key functions and maps them so they can be used with shortcuts in IDA
    """
    AddHotkey("Shift+Z", ida_run_python_function("actionZ"))
    AddHotkey("Shift+X", ida_run_python_function("actionX"))
    AddHotkey("Shift+A", ida_run_python_function("actionA"))
    AddHotkey("Shift+S", ida_run_python_function("actionS"))

    # Perm-mapped
    AddHotkey("Shift+F", ida_run_python_function("actionF"))
    AddHotkey("Shift+T", ida_run_python_function("actionT"))

    print('Hotkeys set!')

if __name__ == '__main__':
    setHotkeys()