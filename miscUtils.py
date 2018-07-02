import idaapi

from Definitions import Architecture, Paths
from IDAItems import Data
idaapi.require("IDAItems.Data")

def pt_echo(msg):
    # type: (str) -> None
    """
    simply echos a message to the terminal
    :param msg: message to echo
    """
    print(msg)

def pt_plcv(ea):
    # type: (ea, bool) -> str
    """
    Converts pool to linker compatible version

    :param ea: ea of inst
    :param arm: True if arm, false if not. -8/-4 (-2 instructions due to pipeline)
    :return: string with the correct [PC, ...] format
    """
    d = Data.Data(ea)
    try:
        disasm = d._getPoolDisasm()
    except(Data.DataException):
        disasm = "N\A"
    return disasm

def pt_xrefs2str(xrefs):
    # type: (tuple[list[int], list[int]]) -> str
    """
    prints xref tuples in a good manner, with hex integer numbers in the lists
    """
    return "(" + pt_hexArr(xrefs[0]) + ", " + pt_hexArr(xrefs[1]) + ")"

def pt_hexArr(arr):
    # type: (list[int]) -> str
    """
    :param arr: array of integers
    :return: str representation of the array but with hex numbers instead
    """
    output = '['
    hasElement = False
    for i in arr:
        hasElement = True
        output += "0x%08X, " % i
    if hasElement:
        output = output[0:-2] + ']'
    else:
        output += "]"
    return output

def pt_readROM(ea, size):
    """
    Reads the size bytes of the analysis ROM at the specified address ea
    :param ea: effective address to read at
    :param size: number of bytes to read
    :raises ValueError: if ea < ROM_SEG or if size < 0
    :return: list of bytes representing the content read
    """
    # type: (int, int) -> list[int]
    if ea < Architecture.ROM_SEG or size < 0:
        raise(ValueError("Invalid ea or size to read"))
    # open binary ROM and go to EA
    fh = open(Paths.ROM_PATH, 'r')
    fh.seek(ea-Architecture.ROM_SEG)

    # read the requested bytes
    data = fh.read(size)
    # sometimes, not all of size is read
    while len(data) < size:
        data += fh.read(size - len(data))

    # close file handler and convert to byte str to bytes
    fh.close()
    bytes = []
    for char in data: bytes.append(ord(char))
    return bytes