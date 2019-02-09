from IDAItems.Tests import Test
from IDAItems import Data
from Definitions import Paths
from Definitions import Architecture


class DataTest:

    def __init__(self):
        test = Test.Test("IDAItems.Data")

        # manually computed dictionary of dictionaries for test parameters
        self.testData = self.createTestData()

        test.add(Test.Test("testBasic()", self.testBasic))
        test.add(Test.Test("testContent()", self.testContent))
        test.add(Test.Test("testDefinition()", self.testDefinition))
        test.add(Test.Test("testDisassembly()", self.testDisassembly))
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
                              % (key, self.xrefs2str(td['xrefsTo']), self.xrefs2str(d.getXRefsTo())))
            Test.assertEquals(d.getXRefsFrom(), td['xrefsFrom'],
                              "%s: Invalid XrefsFrom. Expected=%s, Actual=%s"
                              % (key, self.xrefs2str(td['xrefsFrom']), self.xrefs2str(d.getXRefsFrom())))

        # test that when addressing in the middle of an array, the EA returned is its beginning
        td = self.testData['array']
        d = Data.Data(td['ea'] + td['size']/2)
        Test.assertEquals(td['ea'], d.ea,
                          "array: EA not fixed to beginning of array. Expected=0x%08X, Actual=0x%08X"
                          % (td['ea'], d.ea))

    def testContent(self):
        """
        ensures that the content of the data object is identical to that in the database
        """
        for key in self.testData.keys():
            td = self.testData[key]
            d = Data.Data(td['ea'])
            Test.assertEquals(d.getContent(), td['content'],
                              "%s: Invalid Content. Expected='%s', Actual='%s'" % (key, td['content'], d.getContent()))

            if key == "array":
                print("IDA")
                print(self.hexArr(d.getContent()))
                romData = self.readROM(td['ea'], td['size'])
                print("NO LOADER")
                print(self.hexArr([4, 255, 3, 42, 0, 255, 34, 9, 3, 3, 81, 78, 1, 3, 4, 54, 131, 4,
                                   20, 32, 3, 4, 12, 38, 4, 4, 11, 1, 4, 4, 14, 0, 4, 4, 27, 80, 4,
                                   4, 17, 36, 0, 4, 33, 8, 4, 4, 24, 3, 4, 4, 82, 22, 1, 4, 1, 11,
                                   1, 4, 19, 37, 1, 4, 32, 62, 1, 4, 31, 19, 1, 4, 13, 20, 1, 4, 0,
                                   10, 1, 4, 80, 67, 1, 4, 16, 72, 1, 4, 10, 75, 1, 4, 25, 35, 1, 4,
                                   28, 18, 2, 4, 69, 79, 2, 4, 45, 26, 2, 4, 43, 21, 2, 4, 47, 29, 2,
                                   4, 61, 64, 2, 4, 49, 31, 2, 4, 65, 70, 2, 4, 64, 69, 2, 4, 40, 14]))
                print("ROM")
                print(self.hexArr(Data.Data._combineBytes(romData, 4)))
            Test.assertEquals(d.getContent(bin=True), self.readROM(td['ea'], td['size']),
                              "%s: Invalid Bin Content. Expected='%s', Actual='%s'"
                              % (key, self.readROM(td['ea'], td['size']), d.getContent(bin=True)))

    def testDefinition(self):
        """
        ensures that the computed type and definition is consistent with what is manually computed from the database
        """
        for key in self.testData.keys():
            td = self.testData[key]
            d = Data.Data(td['ea'])
            Test.assertEquals(td['typeName'], d.getTypeName(),
                              "%s: Invalid Type Name. Expected='%s', Actual='%s'"
                              % (key, td['typeName'], d.getTypeName()))
            Test.assertEquals(td['def'], d.getDefinition(),
                              "%s: Invalid Definition. Expected='%s', Actual='%s'"
                              % (key, td['def'], d.getDefinition()))

    def testDisassembly(self):
        """
        ensures that the disassembly, both original and converted, are identical to that manually computed from
        the database
        """
        for key in self.testData.keys():
            td = self.testData[key]
            d = Data.Data(td['ea'])
            Test.assertEquals(td['origDisasm'], d.getOrigDisasm(),
                              "%s: Invalid origDisasm. Expected='%s', Actual='%s'"
                              % (key, td['origDisasm'], d.getOrigDisasm()))
            Test.assertEquals(td['disasm'], d.getDisasm(),
                              "%s: Invalid Disassembly. Expected='%s', Actual='%s'"
                              % (key, td['disasm'], d.getDisasm()))


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

        # test data 1 -- pointer
        d1 = dict()
        d1['ea'] = 0x0800094C
        d1['name'] = "CpuSet_800094C"
        d1['cmt'] = "pool data"
        d1['size'] = 4
        d1['content'] = 0x04000000
        d1['origDisasm'] = "DCD LCDControl"
        d1['disasm'] = ".word LCDControl"
        d1['typeName'] = "void*"
        d1['def'] = "#define %s ((%s*)0x%08X)" % (d1['name'], d1['typeName'], d1['ea'])
        d1['isPool'] = True
        d1['poolFuncEA'] = 0x0800093C
        d1['xrefsTo'] = ([], [d1['poolFuncEA'] + 0x02])
        d1['xrefsFrom'] = ([], [0x04000000])

        # test data 2 -- array
        d2 = dict()
        d2['ea'] = 0x0812851C
        d2['name'] = "t__dword_812851C"
        d2['cmt'] = ""
        d2['size'] = 132
        d2['content'] = [0x2A03FF04, 0x922FF00, 0x4E510303, 0x36040301, 0x20140483,
                         0x260C0403, 0x10B0404, 0xE0404, 0x501B0404, 0x24110404,
                         0x8210400, 0x3180404, 0x16520404, 0xB010401, 0x25130401,
                         0x3E200401, 0x131F0401, 0x140D0401, 0xA000401, 0x43500401,
                         0x48100401, 0x4B0A0401, 0x23190401, 0x121C0401, 0x4F450402,
                         0x1A2D0402, 0x152B0402, 0x1D2F0402, 0x403D0402, 0x1F310402,
                         0x46410402, 0x45400402, 0xE280402]
        d2['origDisasm'] = ("DCD 0x2A03FF04, 0x922FF00, 0x4E510303, 0x36040301, 0x20140483" +
                            "\n\tDCD 0x260C0403, 0x10B0404, 0xE0404, 0x501B0404, 0x24110404" +
                            "\n\tDCD 0x8210400, 0x3180404, 0x16520404, 0xB010401, 0x25130401" +
                            "\n\tDCD 0x3E200401, 0x131F0401, 0x140D0401, 0xA000401, 0x43500401" +
                            "\n\tDCD 0x48100401, 0x4B0A0401, 0x23190401, 0x121C0401, 0x4F450402" +
                            "\n\tDCD 0x1A2D0402, 0x152B0402, 0x1D2F0402, 0x403D0402, 0x1F310402" +
                            "\n\tDCD 0x46410402, 0x45400402, 0xE280402")
        d2['disasm'] = (".word 0x2A03FF04, 0x922FF00, 0x4E510303, 0x36040301, 0x20140483" +
                        "\n\t.word 0x260C0403, 0x10B0404, 0xE0404, 0x501B0404, 0x24110404" +
                        "\n\t.word 0x8210400, 0x3180404, 0x16520404, 0xB010401, 0x25130401" +
                        "\n\t.word 0x3E200401, 0x131F0401, 0x140D0401, 0xA000401, 0x43500401" +
                        "\n\t.word 0x48100401, 0x4B0A0401, 0x23190401, 0x121C0401, 0x4F450402" +
                        "\n\t.word 0x1A2D0402, 0x152B0402, 0x1D2F0402, 0x403D0402, 0x1F310402" +
                        "\n\t.word 0x46410402, 0x45400402, 0xE280402")
        d2['typeName'] = "u32[%d]" % len(d2['content'])
        d2['def'] = "#define %s ((%s)0x%08X)" % (d2['name'], d2['typeName'], d2['ea'])
        d2['isPool'] = True  # TODO but is it?
        d2['poolFuncEA'] = 0x08128500
        d2['xrefsTo'] = ([], [0x081279A8 + 0x24, 0x081279F4, 0x08127EF4 + 0x26, 0x08127F50,
                              0x081283A0 + 0x36, 0x08128484, 0x081284B4 + 0x16, 0x081284FC])
        d2['xrefsFrom'] = ([], [])

        # data 3 -- jumptable
        d3 = dict()
        d3['ea'] = 0x08128744
        d3['name'] = "MenuControl_jt_KeyItem"
        d3['cmt'] = "keyitem jumptable"
        d3['size'] = 12
        d3['content'] = [0x08128750 + 1, 0x081287B4 + 1, 0x081288E4 + 1]
        d3['origDisasm'] = "DCD sub_8128750+1\n\tDCD loc_81287B4+1\n\tDCD sub_81288E4+1"
        d3['disasm'] = ".word sub_8128750+1\n\t.word loc_81287B4+1\n\t.word sub_81288E4+1"
        d3['typeName'] = "void*[3]"
        d3['def'] = "#define %s ((%s)0x%08X)" % (d3['name'], d3['typeName'], d3['ea'])
        d3['isPool'] = True
        d3['poolFuncEA'] = 0x08128730
        d3['xrefsTo'] = ([], [d3['poolFuncEA'] + 0x02, 0x08128740])
        d3['xrefsFrom'] = ([], [0x08128751, 0x081287B5, 0x081288E5])

        # data 4 -- primitive
        d4 = dict()
        d4['ea'] = 0x08128A28
        d4['name'] = "t__dword_8128A28"
        d4['cmt'] = ""
        d4['size'] = 4
        d4['content'] = 0xDE
        d4['origDisasm'] = "DCD 0xDE"
        d4['disasm'] = ".word 0xDE"
        d4['typeName'] = "u32"
        d4['def'] = "#define %s ((%s*)0x%08X)" % (d4['name'], d4['typeName'], d4['ea'])
        d4['isPool'] = True
        d4['poolFuncEA'] = 0x081289C4
        d4['xrefsTo'] = ([], [d4['poolFuncEA'] + 0x04])
        d4['xrefsFrom'] = ([], [])

        # data 5 -- asm line
        d5 = dict()
        d5['ea'] = 0x08128A20
        d5['name'] = ""
        d5['cmt'] = ""
        d5['size'] = 2
        d5['content'] = 0xDBEB
        d5['origDisasm'] = "BLT loc_81289FA"
        d5['disasm'] = "BLT loc_81289FA"
        d5['typeName'] = "code"
        d5['def'] = ""
        d5['isPool'] = False
        d5['poolFuncEA'] = None
        d5['xrefsTo'] = ([d5['ea'] - 2], [])
        d5['xrefsFrom'] = ([0x081289FA], [])

        # data 6 -- unnamedUnknown
        d6 = dict()
        d6['ea'] = 0x081F0170
        d6['name'] = ""
        d6['cmt'] = "test comment, beep!"
        d6['size'] = 1
        d6['content'] = 0x20
        d6['origDisasm'] = "DCB 0x20"
        d6['disasm'] = ".byte 0x20"
        d6['typeName'] = "u8"
        d6['def'] = ""
        d6['isPool'] = False
        d6['poolFuncEA'] = None
        d6['xrefsTo'] = ([], [])
        d6['xrefsFrom'] = ([], [])

        # data 7 -- named_unknown
        d7 = dict()
        d7['ea'] = 0x081F0171
        d7['name'] = "t__namedUnknown"
        d7['cmt'] = ""
        d7['size'] = 1
        d7['content'] = 0x00
        d7['origDisasm'] = "DCB 0"
        d7['disasm'] = ".byte 0"
        d7['typeName'] = "u8"
        d7['def'] = "#define %s ((%s*)0x%08X)" % (d7['name'], d7['typeName'], d7['ea'])
        d7['isPool'] = False
        d7['poolFuncEA'] = None
        d7['xrefsTo'] = ([], [])
        d7['xrefsFrom'] = ([], [])

        # data 8 -- struct # TODO: incomplete
        d8 = dict()
        d8['ea'] = 0x081F0172
        d8['name'] = "t__testStruct"
        d8['cmt'] = "this is a test struct"
        d8['size'] = 0x98
        d8['content'] = {
            'invisCollSwitch': ('u8', 0x00),
            'unk_01': ('u8', 0x00)
        }
        d8['origDisasm'] = "DCB 0; invisCollSwitch\nDCB 0; unk_01"
        d8['disasm'] = ".byte 0 // invisCollSwitch\n.byte 0 // unk_01"
        d8['typeName'] = "NPC"
        d8['def'] = "#define %s ((%s*)0x%08X)" % (d8['name'], d8['typeName'], d8['ea'])
        d8['isPool'] = False
        d8['poolFuncEA'] = None
        d8['xrefsTo'] = ([], [])
        d8['xrefsFrom'] = ([], [])

        # data 9 -- pool inst
        # TODO: add pool test data

        # data 10 -- align
        # TODO: add align test data

        # add data to manually computed test data
        testData['pointer'] = d1
        testData['array'] = d2
        testData['jumptable'] = d3
        testData['primitive'] = d4
        testData['code'] = d5
        testData['unnamedUnknown'] = d6
        testData['namedUnknown'] = d7
        # testData['struct'] = d8
        return testData


if __name__ == "__main__":
    test = DataTest()
    test.run()