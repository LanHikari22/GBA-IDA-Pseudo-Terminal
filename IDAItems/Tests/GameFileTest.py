from Tests import Test
from IDAItems import GameFile, Function, Data
import idaapi
idaapi.require("Tests.Test")
idaapi.require("IDAItems.GameFile")
idaapi.require("IDAItems.Function")
idaapi.require("IDAItems.Data")


class GameFileTest:

    def __init__(self):
        test = Test.Test("IDAItems.GameFile")

        # dictionary of test data dictionaries
        self.testData = dict()

        # test data 1 -- LocalNamed File
        d1 = dict()
        d1['ea'] = 0x080E5964
        d1['name'] = "t"
        d1['size'] = 0x080E5A08 - d1['ea']
        d1['items'] = [Function.Function(0x080E5964), Data.Data(0x080E5972), Data.Data(0x080E5974),
                       Data.Data(0x080E5978), Function.Function(0x080E5988), Function.Function(0x080E59C6),
                       Function.Function(0x080E59E8), Data.Data(0x080E59F6), Data.Data(0x080E59F8),
                       Data.Data(0x080E59FC)]
        d1['mode'] = GameFile.Mode.NAME
        d1['content'] = self.readROM(d1['ea'], d1['size'])
        d1['xrefsTo'] = ([],[d1['poolFuncEA']+0x02])
        d1['xrefsFrom'] = ([], [])

        # add data to manually computed test data
        self.testData['pointer'] = d1

        test.add(Test.Test("testBasic()", self.testBasic))
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
        for key in self.testData.keys():
            td = self.testData[key]
            d = GameFile.GameFile(td['ea'])
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
                              % (key, self.xrefs2str(td['xrefsTo']), self.xrefs2str(d.getXRefsTo())))
        # test that when addressing in the middle of an array, the EA returned is its beginning
        td = self.testData['array']
        d = Data.Data(td['ea'] + td['size']/2)
        Test.assertEquals(td['ea'], d.ea,
                          "array: EA not fixed to beginning of array. Expected=0x%08X, Actual=0x%08X"
                          % (td['ea'], d.ea))


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

if __name__ == "__main__":
    test = GameFileTest()
    test.run()