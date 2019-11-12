import IDAItems.InstDecoder as InstDecoder
from IDAItems.InstDecoder import Inst
from IDAItems.Tests import Test
from IDAItems import Data
from IDAItems.Tests.DataTest import DataTest


class InstTest:

    def __init__(self):
        test = Test.Test("IDAItems.Data")

        # manually computed dictionary of dictionaries for test parameters
        self.testData = self.createTestData()

        test.add(Test.Test("testBasic()", self.testBasic))
        test.add(Test.Test("testPushPop()", self.testPushPop))

        self.test = test

    def run(self):
        self.test.run()

    def testPushPop(self):
        pass

    def testBasic(self):
        # type: () -> None
        """
        Tests that InvalidDataException is raised if instantiated with invalid EA.
        And tests that valid data give valid behavior: ea, name, size, and comments
        :testParams: encapsulated object showing manually computed function parameters
        """
        for key in self.testData.keys():
            td = self.testData[key]
            d = Data.Data(td['ea'])
            # valid EA
            Test.assertEquals(d.ea, td['ea'],
                              "%s: Data EA mistmatch: Expected=0x%08X, Actual=0x%08X" % (key, td['ea'], d.ea))
            # getName
            Test.assertEquals(d.getName(), td['name'], "%s: Data name mismatch: Expected='%s', Actual='%s'"
                              % (key, td['name'], d.getName()))
            # setName
            d.setName("t__" + td['name'])
            Test.assertEquals(d.getName(), "t__" + td['name'], "%s: setName() not working" % key)
            d.setName(td['name'])
            Test.assertEquals(d.getName(), td['name'], "%s: could not set name back to normal" % key)
            # getSize
            Test.assertEquals(d.getSize(), td['size'], "%s: invalid size. Expected=%d, Actual=%d"
                              % (key, td['size'], d.getSize()))
            # getComment
            Test.assertEquals(d.getComment(), td['cmt'],
                              "%s: Comment mismatch: Expected='%s', Actual='%s'" % (key, td['cmt'], d.getComment()))
            # setComment
            d.setComment("t__" + td['cmt'])
            Test.assertEquals(d.getComment(), "t__" + td['cmt'], "%s: setComment() not working" % key)
            d.setComment(td['cmt'])
            Test.assertEquals(d.getComment(), td['cmt'], "%s: could not set comment back to normal" % key)
            # xrefs
            Test.assertEquals(d.getXRefsTo(), td['xrefsTo'],
                              "%s: Invalid XrefsTo. Expected=%s, Actual=%s"
                              % (key, xrefs2str(td['xrefsTo']), xrefs2str(d.getXRefsTo())))
            Test.assertEquals(d.getXRefsFrom(), td['xrefsFrom'],
                              "%s: Invalid XrefsFrom. Expected=%s, Actual=%s"
                              % (key, xrefs2str(td['xrefsFrom']), xrefs2str(d.getXRefsFrom())))

        # test that when addressing in the middle of an array, the EA returned is its beginning
        td = self.testData['array']
        d = Data.Data(td['ea'] + td['size']/2)
        Test.assertEquals(td['ea'], d.ea,
                          "array: EA not fixed to beginning of array. Expected=0x%08X, Actual=0x%08X")

    def createTestData(self):
        # dictionary of test data dictionaries
        testData = dict()

        # test data 1 -- push {PC}
        d1 = dict()
        d1['inst'] = 0xB500
        d1["name"] = "PUSHPOP"
        d1["magic"] = InstDecoder.INST_PUSHPOP
        d1["op"] = 11
        d1["pop"] = 0
        d1["pc"] = 1
        d1["Rlist"] = 0

        # test data 2 -- pop {PC}
        d2 = dict()
        d2['inst'] = 0xBD00
        d2["name"] = "PUSHPOP"
        d2["magic"] = InstDecoder.INST_PUSHPOP
        d2["op"] = 11
        d2["pop"] = 1
        d2["pc"] = 1
        d2["Rlist"] = 0


        testData['push {PC}'] = d1

        return testData

def xrefs2str(xrefs):
    # type: (tuple[list[int], list[int]]) -> str
    """
    prints xref tuples in a good manner, with hex integer numbers in the lists
    """
    return "(" + hexArr(xrefs[0]) + ", " + hexArr(xrefs[1]) + ")"


def hexArr(arr):
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


if __name__ == "__main__":
    test = DataTest()
    test.run()