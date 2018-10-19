import idaapi
import idc

from DisasmTools import Terminal
from IDAItems import Data

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")

from IDAItems import Data


def forceItemOp(ea, op, *args, **kwargs):
    """
    This forces a change to an item, like MakeWord, in the database
    :param ea: linear address of item
    :param op: the operation to apply. Expected to return a success status
    :param args: arguments to op
    :param kwargs: kwargs to op
    :return: success of op
    """
    success = op(*args, **kwargs)
    if not success:
        idc.del_items(ea)
        success = op(*args, **kwargs)
    return success


def getLZ77CompressedSize(compressed_ea):
    """
    Iterates the compressed data, and returns its size
    :param compressed_ea: the linear address of the compressed data
    :return: its size in bytes or -1 if this is an invalid format (compression type not 1)
    """
    dataHeader = 0
    chars = idc.get_bytes(compressed_ea, 4)
    for i in range(len(chars)):
        dataHeader |= ord(chars[i]) << 8*i
    decompSize = (dataHeader & ~0xFF) >> 8

    # compression type must match
    if (dataHeader & 0xF0) >> 4 != 1:
        return -1

    # iterate, and figure out the number of bytes copied
    size = 0
    ea = compressed_ea + 4
    # iterate the blocks and keep count of the data size
    while size < decompSize:
        # parse block flags (compressed or not)
        flags = ord(idc.get_bytes(ea, 1))
        ea += 1

        # iterate the blocks, MSB first.
        for i in range(7, -1, -1):
            if flags & (1<<i):
                # block i is compressed
                chars = idc.get_bytes(ea, 2)
                block = ord(chars[0]) + (ord(chars[1]) << 8)
                size += ((block & 0xF0) >> 4) + 3
                ea += 2
            else:
                # block i is uncompressed, it's just one byte
                size += 1
                ea += 1
            # we might finish decompressing while processing blocks
            if size >= decompSize:
                break
    return ea-compressed_ea


def registerUncompFile(ea, force=True):
    # type: (int) -> bool
    d = Data.Data(ea)
    compPtr = d.getContent()
    if not idc.is_dword(d._getFlags()) or type(compPtr) == list:
        if not force: return False
        print('[%07X] -> dword' % (ea))
        forceItemOp(ea, idc.create_dword, ea)
        d = Data.Data(ea)
        compPtr = d.getContent()

    # compressed pointers have the 31th bit set
    if not compPtr & (1<<31):
        return False

    compPtr = compPtr - (1<<31)

    #  make its content an array, and set a name for it, and a size
    compData = Data.Data(compPtr)
    if compData.ea != compPtr:
        idc.del_items(compData.ea)
        compData = Data.Data(compPtr)
    compSize = getLZ77CompressedSize(compPtr)
    # size must have been identified
    if compSize == -1:
        return False
    if compSize % 4 != 0:
        compSize += 4 - (compSize % 4) # must be word aligned

    if compData.getSize() != compSize:
        if not idc.del_items(compPtr, compSize):
            for i in range(compPtr, compPtr + compSize):
                idc.del_items(i, 1)
        idc.make_array(compPtr, compSize)

    if not compData.getName():
        compData.setName('comp_%07X' % compData.ea)

    idc.op_man(ea, 0, '%s + 1<<31' % compData.getName())

    # now register the compressed data as its own file
    filename = 'data/compressed/%s.lz77' % compData.getName()
    print('[%07X] addFile %s' % (ea, filename))
    dis = Terminal.DisTerminal()
    dis.addFile(filename, compPtr, compPtr + compSize)

    return True


def delShiftedContent(ea):
    d = Data.Data(ea)
    content = d.getContent()
    if (content) == list or not d.getXRefsFrom()[1] or content < 0x8000000 or not d.isPointer(content):
        return False
    dContent = Data.Data(content)
    if content == dContent.ea or dContent.isCode():
        return False
    if not idc.del_items(dContent.ea, dContent.getSize()):
        for i in range(dContent.ea, dContent.ea + dContent.getSize()):
            idc.del_items(i, 1)
    return True


def delShiftedContentRange(start_ea, end_ea):
    ea = start_ea
    while ea < end_ea:
        # print('%07X' % ea)
        d = Data.Data(ea)
        disasm = d.getDisasm()
        if delShiftedContent(ea):
            print('%07X: del content %s' % (ea, disasm))
        ea += d.getSize()


def unkRange(start_ea, end_ea):
    ea = start_ea
    for ea in range(start_ea, end_ea):
        idc.del_items(ea, 1)


def tillName(ea, f):
    d = Data.Data(ea)
    while True:
        size = d.getSize()
        f(d.ea)
        d = Data.Data(d.ea + size)
        if d.getName(): break
    return d.ea


def unkTillName(ea):
    d = Data.Data(ea)
    while True:
        size = d.getSize()
        idc.del_items(d.ea, d.getSize())
        d = Data.Data(d.ea + size)
        if d.getName(): break
    return d.ea


def arrTillName(ea):
    if not Data.Data(ea).isPointer(ea):
        return False
    name_ea = unkTillName(ea)
    idc.make_array(ea, name_ea - ea)
    return True


def unk2Arr(ea):
    start_ea = ea
    d = Data.Data(ea)
    if not d.getName() or not d.isPointer(d.ea):
        return False
    # ensure that it's all unknowns till next name
    allUnks = True
    while True:
        allUnks = idc.isUnknown(idc.GetFlags(ea))
        ea += 1
        if idc.Name(ea) or not allUnks: break
    if not allUnks:
        return False
    arrTillName(start_ea)
    return True


def unk2ArrRng(start_ea, end_ea):
    """
    converts all completely unknowns to byte arrays
    """
    d = Data.Data(start_ea)
    while d.ea < end_ea:
        if d.getName() and idc.isUnknown(idc.GetFlags(d.ea)):
            name = d.getName()
            if unk2Arr(d.ea): print('%s -> %s' % (name, d.getName()))
            d = Data.Data(d.ea)
        d = Data.Data(d.ea + d.getSize())


def unksToArrs(start_ea, end_ea):
    """
    linear addresses to pointers of the unks to turn to arrays
    """
    ea = start_ea
    while ea < end_ea:
        d = Data.Data(ea)
        ea += d.getSize()
        content = d.getContent()
        if type(content) == list or not idc.isUnknown(idc.GetFlags(content)) or not d.isPointer(content):
            continue
        print('%07X' % content)
        arrTillName(content)


def delRange(start_ea, end_ea):
    status = True
    for ea in range(start_ea, end_ea):
        idc.del_items(ea, 1)
    return status


def pointerOf(ea):
    d = Data.Data(ea)
    c = d.getContent();
    # bit 31 set for compressed pointers
    isCompressedPointer = c & (1 << 31)
    if isCompressedPointer: c -= (1 << 31)
    if type(c) != list and d.isPointer(c):
        if isCompressedPointer:
            return c + (1 << 31)
        return c
    else:
        return -1