import idautils
import idc
import idc_bc695
from IDAItems.Tests import Test
from Definitions import Paths
from Definitions import Architecture


class DBProblemsTest:

    def __init__(self):
        test = Test.Test("Database Test")

        # manually computed dictionary of dictionaries for test parameters
        self.testData = self.createTestData()

        test.add(Test.Test("testBasic()", self.testBasic))
        test.add(Test.Test("testNoUnknowns()", self.testNoUnknowns))
        self.test = test

    def run(self):
        self.test.run()

    def testBasic(self):
        # type: () -> None
        """
        Tests that InvalidDataException is raised if instantiated with invalid EA.
        And tests that valid data give valid behavior: ea, name, size, and comments
        :testParams: encapsulated object showing manually computed function parameters
        """
        pass

    def testNoUnknowns(self):
        for seg_ea in idautils.Segments():
            prevHead = seg_ea-1
            for head in idautils.Heads(seg_ea, idc_bc695.SegEnd(seg_ea)):
                # confirm not unknown
                f = idc.GetFlags(head)
                if idc.isUnknown(f):
                    Test.fail("Detected Unknown @ %08X" % head)

                # make sure that the next head is always 1 byte before the previous
                Test.assertEquals(head, prevHead+1, "Non-continuous heads: %08X -> %08X"
                                  % (prevHead, head))

                # remember curr state for next iteration
                prevHead = head




    def xrefs2str(self, xrefs):
        # type: (tuple[list[int], list[int]]) -> str
        """
        prints xref tuples in a good manner, with hex integer numbers in the lists
        """
        return "(" + self.hexArr(xrefs[0]) + ", " + self.hexArr(xrefs[1]) + ")"

    def hexArr(self, arr):
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

    @staticmethod
    def readROM(ea, size):
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

    def createTestData(self):
        # dictionary of test data dictionaries
        testData = dict()

        # add data to manually computed test data

        return testData


if __name__ == "__main__":
    test = DataTest()
    test.run()