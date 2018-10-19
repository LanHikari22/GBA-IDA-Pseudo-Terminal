# @file fixTools
# utilities for automatic fixing go here!
import idaapi
import idautils

from SrchTools import srchTools, nextTools

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("TerminalModule")

import idc
from IDAItems import Function, Data, InstDecoder
import TerminalModule

def remFuncChunks():
    """
    deletes all functions that have function chunks in them
    and appends "function_chunks_" to their names
    """
    foundProblem = False
    for seg in idautils.Segments():
        for ea in idautils.Functions(start=idc.SegStart(seg), end=idc.SegEnd(seg)):
            f = idaapi.get_func(ea)
            # chunk f
            if f.tailqty > 0:
                foundProblem = True
                print("Removing chunk function @ %07X" % f.startEA)
                idaapi.del_func(f.startEA)
                name = idc.Name(f.startEA)
                if "function_chunks_" not in name:
                    newName = 'function_chunks_%s' % name
                    print("Renaming %s -> %s" % ((name, newName)))
                    idc.MakeName(f.startEA, newName)

    if foundProblem:
        print("Removed all function chunks!")
    else:
        print("No function chunks detected!")

def replNameParen():
    """
    IDA treats the presence of a paranthesis as '_'. But visually still shows '_'.
    Just replace all of those '(' and ')'s with an actual '_'
    :return:
    """
    fixedName = False
    for ea, name in idautils.Names():
        newName = name
        if '(' in name:
            newName = newName.replace('(', '_')
        if ')' in name:
            newName = newName.replace(')', '_')

        if newName != name:
            fixedName = True
            print('%07X: Replacing %s -> %s...' % (ea, name, newName))
            idc.MakeName(ea, newName)
    if fixedName:
        print("Finished replacing all parenthesis!")
    else:
        print("No parenthesis found to fix!")

def markRedundantInsts(start_ea, end_ea):
    """
    Some instructions, like add r0, r0, #0 can be optimized to add r0, #0 by assemblers.
    This gets in the way of disassembly. This attempts to fix that by replacing all such occurrances with
    purely their data format, and it also adds a comment on that line specifying the original inst.

    To specify that a data item has to be forced to data, this puts <mkdata> in its comment.
    :param start_ea: start address of the marking
    :param end_ea: end address of the marking
    """
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if d.isCode() and '<mkdata>' not in d.getComment():
            redundant = True
            # MOVS R3, R3
            content = d.getContent()
            if d.getContent() in srchTools.nextTools.next._getFakeInstructions():
                print("%07X: <mkdata>" % (ea))
            else:
                redundant = False

            if redundant:
                cmt = d.getComment()
                if cmt:
                    cmt = '<mkdata> ' + cmt
                else:
                    cmt = '<mkdata>'
                d.setComment(cmt)
        ea += d.getSize()

def makeThumb(start_ea, end_ea):
    """
    Changes all ARM within the specified range to THUMB
    :param ea: the address to start from
    :return: False if no instruction found, else True
    """
    srchNext = srchTools.nextTools.next()
    ea = int(srchNext.arm(start_ea, ui=False), 16)
    foundARM = False
    while ea <= end_ea:
        foundARM = True
        # fix arm to thumb
        print("%07X: Changing to THUMB mode" % ea)
        idc.SetRegEx(ea, "T", 1, idc.SR_user)
        ea = int(srchNext.arm(ea, ui=False), 16)
    if foundARM:
        print("Successfully changed ARM modes to THUMB!")
        return True
    else:
        print("No ARM Instructions in range [%7X, %7X) found!" % (start_ea, end_ea))
        return False

def changeASCII(start_ea, end_ea):
    """
    finds all ascii named data and changes it to bytes and removes its name
    """
    found = False
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if idc.isASCII(d._getFlags()):
            found = True
            print("%07X: Make ASCII -> Byte" % ea)
            idc.MakeByte(ea)
            idc.MakeName(ea, 'ASCII_%07X' % ea)
        ea += d.getSize()

    if found:
        print("changed all ASCII data to byte data!")
    else:
        print("no ASCII data was found!")

def removeText(start_ea, end_ea):
    """
    removes all ASCII text that is in text "..." format
    :param start_ea: start of the range to remove
    :param end_ea: end of the range to remove
    """
    found = False
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if idc.isASCII(d._getFlags()) and 'text ' in d.getOrigDisasm():
            found = True
            print("%07X: Make text -> Byte" % ea)
            idc.MakeByte(ea)
        ea += d.getSize()
    if found:
        print("changed all ASCII data to byte data!")
    else:
        print("no ASCII data was found!")

def removeStackVarUsages(self_ea, end_ea):
    madeChanges = False
    for func_ea in idautils.Functions(self_ea, end_ea):
        changedStackVar = False
        if Function.hasStackVars(func_ea):
            stackVars = Function.getStackVars(func_ea)
            # traverse data items of function and op_bin all
            ea = func_ea
            while ea < func_ea + Function.Function(func_ea).getSize(withPool=False):
                d = Data.Data(ea)
                for name, off in stackVars:
                    if name != ' s' and name in d.getOrigDisasm():
                        changedStackVar = True
                        if not madeChanges: madeChanges = True
                        idc.op_hex(d.ea, 1)
                ea += d.getSize()
            if changedStackVar:
                print('%07X: stackvars op -> hex' % func_ea)
    if madeChanges:
        print("Removed all stack variable usages!")
    else:
        print("No stack variable usages to remove!")

def makeUnkPushFuncs(start_ea, end_ea):
    """
    Finds and fixes all dead functions not declared as functions following the pattern PUSH {..., LR} POP {..., PC}
    This also only makes functions until the first occurrance of a POP {..., PC}. However, this results in a
    function range error, and that can be fixed as well.
    :param start_ea: start of the range to fix
    :param end_ea: end of the range to fix
    :return:
    """
    next = nextTools.next()
    ea, pop_ea = next.deadfunc(start_ea, end_ea, ui=False, hexOut=False)
    while ea < end_ea:
        d = Data.Data(ea)
        if d.isCode():
            print('Adding unknown push func @ %07X' % ea)
            idc.add_func(ea, pop_ea + 2)
        ea, pop_ea = next.deadfunc(pop_ea, end_ea, ui=False, hexOut=False)

def fixFunctionRanges(start_ea, end_ea):
    """
    Fixes all functions with improper returns, by finding their returns and changing their ranges
    For each function, it will ensure that it ends properly until the start of another function, or a data element
    with data xrefs to it. If it ends improperly, or there exists a matching return that is
    not part of the function, it's made part of the function
    This may not behave correctly around dead functions or null_subs. Run tools to Detect and fix those first.
    :param start_ea: start of the range to fix functions in
    :param end_ea: end of the range to fix functions in
    :return:
    """
    # only look 50 instructions ahead, for range change
    searchLimit = 50
    for func_ea in idautils.Functions(start_ea, end_ea):
        f = Function.Function(func_ea)
        # absolute end address of the function (if another function is detected or a data item with data xrefs is)
        stop_ea = f.func_ea + f.getSize()
        for i in range(stop_ea, stop_ea + searchLimit):
            if Function.isFunction(i) or Data.Data(i).getXRefsTo()[1]:
                stop_ea = i
                break
        next_tools = nextTools.next()
        # figure out the first return, and return type of this function. That should be consistent
        ret_ea = next_tools.ret(f.func_ea, ui=False, hexOut=False)
        retType = InstDecoder.Inst(ret_ea).fields['magic']
        # modify the function range to include all returns
        if Function.isFunction(ret_ea):
            ret_ea = next_tools.unkret(f.func_ea, ui=False, hexOut=False)
            # this ret_ea is not within the function, if the return type is different
            if InstDecoder.Inst(ret_ea).fields['magic'] != retType:
                continue
        while f.func_ea < ret_ea < stop_ea:
            # detected that the function range is invalid, fix range
            print('ret %07X' % ret_ea)
            ret_ea = next_tools.unkret(ret_ea, ui=False, hexOut=False)
            # this ret_ea is not within the function, if the return type is different
            if InstDecoder.Inst(ret_ea).fields['magic'] != retType:
                break

def removeFakeRedCode(start_ea, end_ea):
    """
    Removes instances of code recognized by IDA to be code, but are unlikely not to be by making them bytes.
    :param start_ea: start of the range to fix
    :param end_ea: end of the range to fix
    :return:
    """
    srchNext = srchTools.nextTools.next()
    redStart_ea, redEnd_ea = srchNext.fakered(start_ea, end_ea, ui=False, hexOut=False)
    while redStart_ea < end_ea:
        # change to bytes
        print("%07X: del fake red code (%07X, %07X)" % (redStart_ea, redStart_ea, redEnd_ea))
        idc.del_items(redStart_ea, 0, redEnd_ea - redStart_ea)
        redStart_ea, redEnd_ea = srchNext.fakered(redEnd_ea, end_ea, ui=False, hexOut=False)

def removeRedCode(start_ea, end_ea):
    """
    unconditionally removes all red code within a specified region
    :param start_ea: start of the region
    :param end_ea: end of the region
    :return:
    """
    srchNext = srchTools.nextTools.next()
    redStart_ea = redEnd_ea = srchNext.red(start_ea, end_ea, ui=False, hexOut=False)
    while redEnd_ea < end_ea:
        d = Data.Data(redEnd_ea)
        while d.isCode() and not Function.isFunction(d.ea):
            redEnd_ea += 2
            d = Data.Data(redEnd_ea)
        # change to bytes
        print("%07X: del red code (%07X, %07X)" % (redStart_ea, redStart_ea, redEnd_ea))
        idc.del_items(redStart_ea, 0, redEnd_ea - redStart_ea)
        redStart_ea = redEnd_ea = srchNext.red(redEnd_ea, end_ea, ui=False, hexOut=False)