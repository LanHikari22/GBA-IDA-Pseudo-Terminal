from IDAItems.Tests import Test
from IDAItems import Function, Data


class FunctionTest:
    def __init__(self):
        test = Test.Test("IDAItems.Function")

        # test function 1. no STRs, LDRs and BLs
        d1 = dict()
        d1['ea'] = 0x080471F8
        d1['name'] = "Shop_uncomp_80471F8"
        d1['cmt'] = "I use this as a test function."
        d1['size_pool'] = 0x0804722C - d1['ea']
        d1['size_nopool'] = 0x08047216 - d1['ea']
        d1['xrefsTo'] = ([0x08046D4C+0x10],[])
        d1['xrefsFrom'] = ([0x0814D8C4], [0x02029A00, 0x0873DE4C, 0x0202BA00, 0x0873ECC8,
                                          0x0202DA00])
        d1['pool'] = [Data.Data(0x08047216), Data.Data(0x08047218), Data.Data(0x0804721C),
                      Data.Data(0x08047220), Data.Data(0x08047224), Data.Data(0x08047228)]

        # test function 2.

        # append to testData
        self.testData = []
        self.testData.append(d1)

        test.add(Test.Test("testBasic()", self.testBasic))
        test.add(Test.Test("testComments()", self.testComments))
        # test.add(Test.Test("testContent()", self.testContent))
        test.add(Test.Test("testFunctionDefinition()", self.testFunctionDefinition))
        test.add(Test.Test("testXRefsTo()", self.testXRefsTo))
        test.add(Test.Test("testXRefsFrom()", self.testXRefsFrom))
        test.add(Test.Test("testPoolData()", self.testPoolData))

        self.test = test


    def run(self):
        self.test.run()

    def testBasic(self):
        # type: () -> None
        """
        Tests that InvalidFunctionException is raised if instantiated with invalid EA.
        And tests that valid functions give valid behavior
        """
        try:
            f = Function.Function(0x00)
            Test.fail("InvalidFunctionException not raised")
        except(Function.FunctionException):
            pass
        for td in self.testData:
            f = Function.Function(td['ea'])
            Test.assertEquals(f.func_ea, td['ea'], "Function EA mistmatch: 0x%08X" % f.func_ea)
            # getName()
            Test.assertEquals(f.getName(), td['name'], "Function name mismatch")
            # setName()
            f.setName(td['name'] + "0")
            Test.assertEquals(f.getName(), td['name'] + "0", "setName() not working")
            f.setName(td['name'])
            Test.assertEquals(f.getName(), td['name'], "could not set name back to normal")
            # getSize()
            Test.assertEquals(f.getSize(withPool=True), td['size_pool'], "invalid pool size")
            Test.assertEquals(f.getSize(), td['size_nopool'], "invalid no pool size")

    def testComments(self):
        # type: () -> None
        """
        Makes sure that function comments are viewable and modifiable
        """
        # there's an issue where GUI comments filter out system input comments, but
        # both exist anyway. Only one is showed in the GUI.
        for td in self.testData:
            f = Function.Function(td['ea'])
            Test.assertEquals(f.getComment(), td['cmt'], "comment mismatch: '%s'" % f.getComment())
            f.setComment(td['cmt'] + "0")
            Test.assertEquals(f.getComment(), td['cmt'] + "0", "setComment() not modifying")
            f.setComment(td['cmt'])
            Test.assertEquals(f.getComment(), td['cmt'], "comment didn't return to original")

    def testContent(self):
        # type: (int) -> None
        Test.fail("Not implemented: content is not parsed within the function")


    def testFunctionDefinition(self):
        # type: () -> None
        """
        This decompiles the function and tries to get a C-style pointer #define
        macro
        It also tests just getting the prototype. This requires decompilation.
        """
        for td in self.testData:
            f = Function.Function(td['ea'])
            macro = "#define %s ((void (*) ()) (0x%08X +1))" % (td['name'], td['ea'])
            Test.assertEquals(f.getFuncPtrCMacro(), macro,
                              "macro mismatch: %s" % f.getFuncPtrCMacro())

    def testXRefsTo(self):
        # type: () -> None
        """
        Tests valid code/data xrefs to the function
        """
        for td in self.testData:
            f = Function.Function(td['ea'])
            # testing xrefs to function
            Test.assertEquals(f.getXRefsTo(), td['xrefsTo'],
                              "XrefsTo Mismatch. Expected: '%s', Actual: '%s'"
                              % (self.xrefs2str(td['xrefsTo']), self.xrefs2str(f.getXRefsTo())))

    def testXRefsFrom(self):
        # type: () -> None
        """
        Tests valid code/data xrefs to the function
        """
        for td in self.testData:
            f = Function.Function(td['ea'])
            # testing xrefs from function
            Test.assertEquals(f.getXRefsFrom(), td['xrefsFrom'],
                              "XrefsFrom Mismatch. Expected: '%s', Actual: '%s'"
                              % (self.xrefs2str(td['xrefsFrom']), self.xrefs2str(f.getXRefsFrom())))

    def testPoolData(self):
        for td in self.testData:
            f = Function.Function(td['ea'])
            i = 0
            for data in f.getPoolData():
                Test.assertEquals(td['pool'][i].ea, data.ea,
                                  "Pool data item %d mismatch. Expected: %08X, Actual: %08X"
                                  % (i, td['pool'][i].ea, data.ea))
                Test.assertEquals(td['pool'][i].getContent(), data.getContent(),
                                  "Pool data item %d mismatch. Expected: %08X, Actual: %08X"
                                  % (i, td['pool'][i].getContent(), data.getContent()))
                i += 1

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
    test = FunctionTest()
    test.run()