import idaapi
import idc

from DisasmTools import Terminal
from IDAItems import Data

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")

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

