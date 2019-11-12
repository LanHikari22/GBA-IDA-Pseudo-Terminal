# @file fixTools
# utilities for automatic fixing go here!
import idaapi
import idautils
import idc
import SrchTools.nextTools as next
import MiscTools.Operations as ops
from IDAItems import Function, Data, InstDecoder, Instruction

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

def removeMkdata(start_ea, end_ea, verbose=True):
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if d.isCode() and '<mkdata>' in d.getComment():
            comment = d.getComment()
            comment = comment.replace('<mkdata>', '', 1)
            if verbose:
                print('%07X: remove <mkdata> "%s" -> "%s"' % (ea, d.getComment(), comment))
            d.setComment(comment)
        ea += d.getSize()


def makeThumb(start_ea, end_ea):
    """
    Changes all ARM within the specified range to THUMB
    :param ea: the address to start from
    :return: False if no instruction found, else True
    """
    ea = int(next.arm(start_ea, ui=False), 16)
    foundARM = False
    while ea <= end_ea:
        foundARM = True
        # fix arm to thumb
        print("%07X: Changing to THUMB mode" % ea)
        idc.SetRegEx(ea, "T", 1, idc.SR_user)
        ea = int(next.arm(ea, ui=False), 16)
    if foundARM:
        print("Successfully changed ARM modes to THUMB!")
        return True
    else:
        print("No ARM Instructions in range [%7X, %7X) found!" % (start_ea, end_ea))
        return False

def changeASCII(start_ea, end_ea):
    """
    finds all ascii data which is not user named and changes it to bytes and removes its name
    """
    found = False
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if idc.isASCII(d.getFlags()):
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
    removes all ASCII text within range
    :param start_ea: start of the range to remove
    :param end_ea: end of the range to remove
    """
    found = False
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        if idc.isASCII(d.getFlags()):
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
        # figure out the first return, and return type of this function. That should be consistent
        ret_ea = next.ret(f.func_ea, ui=False, hexOut=False)
        retType = InstDecoder.Inst(ret_ea).fields['magic']
        # modify the function range to include all returns
        if Function.isFunction(ret_ea):
            ret_ea = next.unkret(f.func_ea, ui=False, hexOut=False)
            # this ret_ea is not within the function, if the return type is different
            if InstDecoder.Inst(ret_ea).fields['magic'] != retType:
                continue
        while f.func_ea < ret_ea < stop_ea:
            # detected that the function range is invalid, fix range
            print('ret %07X' % ret_ea)
            ret_ea = next.unkret(ret_ea, ui=False, hexOut=False)
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

def collapseUnknowns(start_ea, end_ea, verbose=True):
    """
    Changes all initial unknown heads into byte arrays until the next defined reference or next label
    :param state_ea: range start for collapsing
    :param end_ea: range end for collapsing
    :param verbose: if True, print all changes
    :return: Fix status
    """
    ea = start_ea
    ea = next.byDataElement(ea, lambda ea: idc.isUnknown(idc.GetFlags(ea)), ui=False)
    if ea >= end_ea:
        return False

    while ea < end_ea:
        if verbose:
            print('%07X: make array till reference/name' % ea)
        ops.arrTillRef(ea)
        ea = next.byDataElement(ea, lambda ea: idc.isUnknown(idc.GetFlags(ea)), ui=False)
    return True

def expandUnkArrays(start_ea, end_ea, verbose=True):
    """
    Finds all named byte_xxx and dword_xxx arrays, and turns them to unknowns.
    If an array is unnamed, and it's a byte array, it's also turned into unknowns.
    :param start_ea: start of the range
    :param end_ea: end of the range
    :param verbose: if True, print all changes
    :return: status of the expansion
    """
    d = Data.Data(start_ea)
    while d.ea < end_ea:
        if ( not idc.isAlign(d.getFlags())
               and (
                # known dummy array
                (d.getName() and (d.getName().startswith('byte_') or d.getName().startswith('dword_')))
                # byte/dword array
                or (not d.getName() and type(d.getContent()) == list and
                        (d.getSize() / len(d.getContent()) == 1 or d.getSize() / len(d.getContent()) == 4))

        )):
            if verbose: print('%07X: delete unk arr' % d.ea)
            idc.del_items(d.ea, d.getSize())
        d = Data.Data(d.ea + d.getSize())

def getUnkPointers(fileRange, verbose=True, rom=True):
    """
    reports back all suspect unknown pointers within the file
    :param fileRange:
    :param verbose:
    :return:
    """
    if verbose: print("(%07X, %07X): expand unknown arrays" % (fileRange[0], fileRange[1]))
    expandUnkArrays(*fileRange, verbose=False)

    output = []

    ea = fileRange[0]
    while ea < fileRange[1]:
        ea = next.unkptr(ea, fileRange[1], rom=rom, ui=False, hexOut=False)
        if ea != idaapi.BADADDR:
            # get data at ea
            chars = idc.get_bytes(ea, 4)
            dword = 0
            for i in range(len(chars)):
                dword += ord(chars[i]) << 8 * i
            output.append((ea, dword))

    if verbose: print("(%07X, %07X): collapsing unknowns " % (fileRange[0], fileRange[1]))
    collapseUnknowns(*fileRange, verbose=False)

    return output

def resolvePointers(fileRange, pointerRange, verbose=True):
    """

    :param fileRange: tuple of (int, int) representing the file to resolve pointers in
    :param pointerRange: tuple of (int, int) representing range of pointers to resolve
    :param verbose: if True, all changes are printed
    :return:
    """
    if verbose: print("(%07X, %07X): expand unknown arrays" % (fileRange[0], fileRange[1]))
    expandUnkArrays(*fileRange, verbose=False)

    ea = fileRange[0]
    while ea < fileRange[1]:
        ea = next.unkptr(ea, fileRange[1], rom=True, ui=False, hexOut=False)
        if ea != idaapi.BADADDR:
            # get data at ea
            chars = idc.get_bytes(ea, 4)
            dword = 0
            for i in range(len(chars)):
                dword += ord(chars[i]) << 8 * i

            if pointerRange[0] <= dword < pointerRange[1]:
                if verbose: print('%07X: %07X' % (ea, dword))
                idc.op_plain_offset(ea, 0, 0)

    if verbose: print("(%07X, %07X): collapsing unknowns " % (fileRange[0], fileRange[1]))
    collapseUnknowns(*fileRange, verbose=False)

# ---
def extendThumbFuncToLastPop(func_ea, lastInsn_ea, verbose=True):
    """
    Looks for another POP {..., PC}. Stops at the start of a new function, or at the start of
    labeled data. Otherwise, it makes sure the code is disassembled, and is thumb, and it extends the
    range of the function to the found POP {..., PC}.
    A corner case not accounted by this algorithm, is if the data is in the middle of code, but
    is jumped over.
    :param func_ea: addr to function to fix
    :param lastInsn_ea: address to the last instruction within the function, as registered in the IDB.
    :return: whether a fix ocurred or not
    """
    ea = lastPop_ea = lastInsn_ea
    while not idc.Name(ea) or not idc.isData(idc.GetFlags(ea)):
        if idc.GetReg(ea, 'T') == 0:
            idc.SetRegEx(ea, 'T', 1, idc.SR_user)

        # if idc.isData(idc.GetFlags(ea)):
        #     # if not thumb, make thumb
        #     idc.del_items(ea, 0, 2)
        #     idc.MakeCode(ea)

        if Instruction.isInsn(ea):
            insn = Instruction.Insn(ea)
            # update last POP {..., PC} detected
            if insn.itype == idaapi.ARM_pop and ((insn.getPushPopFlags() & (1<<15)) != 0):
                lastPop_ea = ea
            # stop condition, assuming no  PUSH {..., LR} in current function
            if insn.itype == idaapi.ARM_push and ((insn.getPushPopFlags() & (1<<14)) != 0):
                break

        ea += idaapi.get_item_size(ea)

    # extend last function to last pop detected
    if lastPop_ea != lastInsn_ea:
        if verbose:
            print('%07X: End -> %07X <%s>' % (func_ea, lastPop_ea, Data.Data(lastPop_ea).getDisasm()))
        idc.SetFunctionEnd(func_ea, lastPop_ea+2)
        return True
    return False


def fixThumbPushPopFuncRanges(start_ea, end_ea, verbose=True):
    """
    This is heusterical, it fixes problems that occur in the IDA anlysis.
    This fix only applies to thumb functions started with PUSH {LR}.
    Two cases are considered valid:
    - A function is cut off at a BL. Change its range to the nearest POP {PC}
    - A function is cut off at a BX, and a CPU mode change error occurs.
    - A function is cut off at a POP {PC}, but there is no PUSH {LR} before teh occurrance of the next POP{PC}
    The fixing process involves turning data into code, if needed, and changing to thumb mode until the next POP.
    :param start_ea: start of the range to look for broken functions in
    :param end_ea: end of the range to look for functions in
    :param verbose: prints info messages
    :return: fix status. False if any problems occur
    """
    ea = start_ea
    while ea < end_ea:
        if Function.isFunction(ea):
            func = Function.Function(ea)
            if func.isThumb():
                # ensure it's a PUSH/POP function
                firstInsn = Instruction.Insn(func.func_ea)
                # print(idc.GetDisasm(firstInsn.ea))
                if (firstInsn.itype == idaapi.ARM_push
                    and (firstInsn.getPushPopFlags() & (1<<14)) != 0
                ):
                    # check the last instruction. make sure it's a POP {..., PC}, BL, or BX.
                    lastInsn_ea = func.func_ea + func.getSize(withPool=False)
                    if idc.get_item_size(lastInsn_ea-4) == 4:
                        lastInsn_ea -= 4 # in case of BL, which is of size 4
                    else:
                        lastInsn_ea -= 2
                    lastInsn = Instruction.Insn(lastInsn_ea)
                    # print(idc.GetDisasm(lastInsn.ea))
                    if ( (lastInsn.itype == idaapi.ARM_pop and (lastInsn.getPushPopFlags() & (1<<15)) != 0)
                            or lastInsn.itype == idaapi.ARM_bl
                            or lastInsn.itype == idaapi.ARM_bx
                        ):
                        # print('OK')
                        extendThumbFuncToLastPop(func.func_ea,
                                                 lastInsn_ea,
                                                 verbose)

            ea += func.getSize(withPool=True)
        else:
            ea += Data.Data(ea).getSize()