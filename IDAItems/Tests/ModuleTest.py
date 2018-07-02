from Definitions.Paths import OTHER_VERSION_BIN_PATH
from IDAItems.Module import Module, ModuleException
from IDAItems import GameFile, Function
from Tests import Test
import idaapi
idaapi.require("IDAItems.Module")
idaapi.require("IDAItems.GameFile")
idaapi.require("Tests.Test")

def testInit():
    # type: () -> None
    """
    Hard coded test through MMBN6F IDB
    This tests initialization logic. Makes sure that initializing through a a nameEA or a module name is valid
    and that both representations contain a valid file that is tested against!
    :return: test success
    """
    moduleName = 'reqBBS'
    # make sure that we can find the module through name and item Ea
    m0 = Module.fromName(moduleName)
    Test.assertEquals(m0.name, moduleName, "fromName: module name doesn't match!")
    m1 = Module.fromEA(0x0813F65C)
    Test.assertEquals(m1.name, moduleName, "fromEA: module name doesn't match!")

    # confirm that some of the files are present
    reqBBSFile = GameFile.GameFile.fromRange(0x0813E0A4, 0x0813E534)
    sameEA = False
    for file in m0.files:
        if file.start_ea == reqBBSFile.start_ea and file.end_ea == reqBBSFile.end_ea:
            sameEA = True
    Test.assertTrue(sameEA, "recognized file was not detected by module")
    sameEA = False
    for file in m1.files:
        if file.start_ea == reqBBSFile.start_ea and file.end_ea == reqBBSFile.end_ea:
            sameEA = True
    Test.assertTrue(sameEA, "recognized file was not detected by module")

def testModuleFinding():
    # type () -> ()
    """
    Tests that a module is strictly defined as '<moduleName>_' then something.
    :return:  None
    """
    # should fail if the module name contains a '_'
    try:
        m = Module.fromName('_')
        Test.fail("ModuleException not thrown: '_' in name")
    except ModuleException:
        pass
    except Exception as e:
        # TODO: it catches e as the type ModuleException, yet comes here???
        # TODO: type(e) != Exception, but prints to the same thing
        pass

    # MMBN6F contains a module called 'Battle' and a module called 'BattleMenu'...
    # the module 'Battle' should NOT contain files from the 'BattleMenu' module!
    # all files in fact must contain "Battle_" at their start!
    battle = Module.fromName("Battle")
    for file in battle.files:
        for ea, name in file.getNames():
            if '_' not in name:
                Test.fail("name must contain '<modulename>_'")
            modulename = name[0:name.index('_')]
            Test.assertEquals(modulename, "Battle", "Not all items are part of the module")

def testVersionSegregatedModuleFuncs():
    """
    Basic test to assert that the correct functions are identified within the specified module
    """
    module_name = "Battle"
    m = Module(module_name)
    funcs_version, funcs_shared, funcs_unique = m.getVersionSegregatedModuleFuncs(OTHER_VERSION_BIN_PATH)

    # go through each function. Make sure they all have "battle_" in them.
    for f, otherversion_ea in funcs_version:
        name = f.getName()
        if module_name + "_" not in name:
            Test.fail("version: Found a function outside module")
    for f in funcs_shared:
        name = f.getName()
        if "Battle_" not in name:
            Test.fail("shared: Found a function outside module")
    for f in funcs_unique:
        name = f.getName()
        if "Battle_" not in name:
            Test.fail("unique: Found a function outside module")


def createTests():
    # type: () -> Test
    """
    Creates all of the tests for the IDAItems.Module module
    :return: A test containing all nested tests for the IDAItems.Module module!
    """
    moduleTest = Test.Test("IDAItems.Module")
    moduleTest.add(Test.Test("testInit()", testInit))
    moduleTest.add(Test.Test("testModuleFinding()", testModuleFinding))
    moduleTest.add(Test.Test("testVersionSegregatedModuleFuncs()", testVersionSegregatedModuleFuncs))
    return moduleTest

if __name__ == "__main__":
    createTests().run()
