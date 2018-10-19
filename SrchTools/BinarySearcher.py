##
# @File BinarySearcher.py
# @Author Lan
# The purpose of this module is to use IDA database capabilities to search for things in binaries (ROMS, Dumps, etc).
#
# [Features]
# - Able to search for matching functions between the ROM and binary file
##


import os
import time

import idautils
import idc_bc695

from Definitions.Architecture import ROM_SEG
from Definitions.Architecture import INSTRUCTION_WIDTH
from Definitions.Paths import ROM_PATH, IDATOOLS_PATH
from IDAItems import Function


from Command import c

# Constants  -----------------------------------------------------------------------------------------------------------
INVALID_FUNCTION = -1
RANGE_OUT_OF_ROM = -2
# Constants  -----------------------------------------------------------------------------------------------------------

class BinarySearcher:

    def __init__(self, bin):
        """
        :param bin:  str: Path to the binary to be searched
        """
        # Path to the ROM to be opened as a file. This should be identical to the ROM analyzed by IDA
        self.ROM = open(ROM_PATH, 'rb')
        binFile = open(bin, 'rb')
        self.binSize = os.path.getsize(bin)
        # Reference address within the database. This is used to address things in the DB, and ROM.
        self.ROM_start_addr = ROM_SEG
        self.binData = binFile.read()
        binFile.close()

    def closeFiles(self):
        """
        Should be called when this module is done with. This closes the ROM File.
        :return: None
        """
        self.ROM.close()

    def _get_func_data(self, func):
        """
        Returns bytes for the function
        :param func: Function.Function: Function to get data of
        :return: a byte string representing the function
        """
        start_ea, end_ea = func.getBoundaries()
        self.ROM.seek(start_ea - self.ROM_start_addr)
        data = self.ROM.read(func.getSize())
        # output = []
        # for b in data:
        #     output.append(int(ord(b)))
        # return output
        return data

    def find_function(self, func_ea):
        """
        This searches the binary for an occurrance of the hex data of this function. The hex data to be searched for
        is found in the Analysis ROM.
        :param func_ea:  long: The effective address of the function to search
        :return:  Address of occurrance of function in binary if found, or None.
                 (Error Cases)
                 - If func_ea is not found to be within a function, INVALID_FUNCTION is returned. (See constants)
                 - if func_ea < the ROM's starting addr, RANGE_OUT_OF_ROM is returned. (See constants)
        """

        # All functions to be found have to actually be within the ROM region
        if func_ea < self.ROM_start_addr: return RANGE_OUT_OF_ROM
        try:
            func = Function.Function(func_ea)
            start_ea, end_ea = func.getBoundaries()
            funcData = self._get_func_data(func)
            # Search Binary for the data
            try:
                output = self.binData.index(funcData)
            except ValueError:
                output = None
            return output
        except Function.FunctionException:
            return INVALID_FUNCTION

    def scan_for_known_functions(self):
        """
        This will scan the binary using ALL defined functions in the ROM SEGMENT in the IDA Database agaisnt the binary.
        Dictionary for each match:
        Key         Description
        Name        The name of the function in the IDA Database
        ROM_Addr    The ROM Address. This is absolute to the architecture in question, and the seg addr is added to it
        Bin_Addr    The Address in the binary file. This is relative to the binary file.
        :return: A list of Dictionaries according to the definition above, or an empty list if no matches.
        """
        output = []
        for func_ea in idautils.Functions(idc_bc695.SegStart(self.ROM_start_addr), idc_bc695.SegEnd(self.ROM_start_addr)):
            binEA = self.find_function(func_ea)
            if binEA:
                matchDict = {}
                matchDict['Name'] = idc_bc695.GetFunctionName(func_ea)
                matchDict['ROM_Addr'] = func_ea
                matchDict['Bin_Addr'] = binEA
                output.append(matchDict)
        return output



def fcmp(cmd, *args, **kwargs):
    """
    This is to be executed through the run module
    :param cmd: Not used. There because python. Thank you!
    :param args: (binaryPath)
            binaryPath: (str) the path to the binary being function compared with
    :param kwargs: (wr=True, q=False, wrPath=PYTOOLS_PATH + 'FE8.txt')
            wr: (bool) whether also to write the analysis to a file, or only return the value. Default to write.
            q: (bool) supresses info messages, False if not specified.
            wrPath: (str) path to file to output the results in. If not specified, analysis ouput is returned
    :return: Files detected within the module
    """
    binaryPath = args[0]
    wr = kwargs['wr'] if 'wr' in kwargs else True
    wrPath = ('wrPath' in kwargs and wr) and kwargs['wrPath'] or wr and IDATOOLS_PATH + 'FE8.txt' or None
    wrFile = open(wrPath, 'w') if wrPath else None
    suppressed = 'q' in kwargs and kwargs['q'] or False

    if not suppressed: print("Starting Binary Search Analysis...")

    searcher = BinarySearcher(binaryPath)

    # Perform and time Analysis
    if not suppressed:
        stopwatch = time.time()
    matchedFunctions = searcher.scan_for_known_functions()
    if not suppressed:
        stopwatch = time.time() - stopwatch
        if wrFile: wrFile.write("Analysis took %d s\n" % int(stopwatch))
        else: print("Analysis took %d s\n" % int(stopwatch))

    # Simply output all entries
    matchedFunctions_filtered = []
    for x in matchedFunctions:
        filters = [
            # x["ROM_Addr"] == ROM_seg + x["Bin_Addr"], # Detect only functions identical in content and location
            Function.Function(x["ROM_Addr"]).getSize() >= 2 * INSTRUCTION_WIDTH, # Filter out empty/weird small funcs
            'nullsub' not in x["Name"], # filter out all nullsubs, they don't give a lot of information.
            'jumpout' not in x["Name"], # jumpout functions are very small, and just support various usages of a func
            'bx_R' not in x["Name"], # Those weird 'functions' are so small and introduce noise to the analysis
        ]
        filtered = True
        for f in filters: filtered = filtered and f
        if filtered:
            if wrFile: wrFile.write(str(x["Name"]) + ": " + hex(x["Bin_Addr"]) + '\n')
            matchedFunctions_filtered.append(x)
    if wrFile: wrFile.close()
    if not suppressed: print("Binary Search Analysis Complete!")


if __name__ == '__main__':
    binPath = IDATOOLS_PATH + '..\\..\\mmbn6g.gba'
    wrPath = IDATOOLS_PATH + 'analysis.txt'
    suppressed = True
    fcmp(None, binPath, wrPath, not suppressed)

    # print(hex(0x08000000 + searcher.find_function(0x803EFCC))) # returns 0x803efcc
