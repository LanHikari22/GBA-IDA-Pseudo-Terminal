##
# @Author Lan
# This represents the concept of modulized functions/data. A set of functions may be related, or were belonging to
# A single file or set of files when compiled together.
# This encapsulates all Names that begin with <ModuleName> and count them as belonging to the same module.
##
import idaapi
import idautils
import idc_bc695

idaapi.require('BinarySearcher')
idaapi.require('Definitions.Architecture')
idaapi.require('IDAItems.GameFile')
idaapi.require('IDAItems.Function')

from BinarySearcher import BinarySearcher
from Definitions.Architecture import ROM_SEG
from IDAItems.GameFile import GameFile
from IDAItems import Function

class ModuleException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)


class Module:
    def __init__(self, *args):
        """
        Creates a module with the name moduleName. This could be exported from the database, or it could be a new
        module to include in the database!
        :param *args:
            fromName(moduleName:str)
                :moduleName: name of the module, '<moduleName>_' will be used to identify names within it.
                Because of this, the name is NOT allowed to have a '_' in it.
            fromEA(nameEA:int)
                Extracts the name of the module from the item specified by moduleEA. the name is the item name
                up until the first '_'.
                :moduleEA: an EA of a Name within the module
        :raise ModuleException: if more than one arg is passed or name contains '_' in it!
                                if a moduleEA has no name associated with it,
                                or if the name associated with moduleEA has no '_' in it!
        """
        if len(args) > 1:
            raise(ModuleException("incompatible *args passed"))
        if type(args[0]) == str:
            self.name = args[0]
            if '_' in self.name:
                raise(ModuleException("passed Module name must not contain '_' in it"))
        elif type(args[0]) == int:
            self.name = idaapi.get_name(args[0])
            if '_' not in self.name:
                raise(ModuleException("Invalid nameEA passed, or not part of any module"))
            self.name = self.name[0:self.name.index('_')]
        else:
            raise(ModuleException("incompatible *args passed"))
        self.files = self.getModuleFiles()

    @classmethod
    def fromName(cls, moduleName):
        # type: (str) -> Module
        return cls(moduleName)

    @classmethod
    def fromEA(cls, moduleEA):
        # type: (int) -> Module
        return cls(moduleEA)


    def _getModuleFileChunks(self):
        """
        When performing context analysis, many functions all over the place could be associated with a module.
        Say, anything that only seems to have to do with the Battle engine, maybe called as 'Battle_08040000' or
        'Battle_Start', 'Battle_IncreaseHP', etc. They are named that, simply because they
        in some sense were thought to have something to do with 'Battle'.
        They have to be named '<moduleName>_'... to count as part of the module.

        This function identifies a list of lists of Names starting with moduleName, each list would reperesent
        a collection of names that identify as one chunk. If they are cut by other defined names,
        other chunks are appended.
        :return: (list(list(long, str)) All Module-defined Names, seperated out in chunks such that each chunk
        represents a valid GameFile.
        """
        namesLists = []
        listCsr = 0

        foundFirstName = False
        foundLastName = False
        # First get all names within the module
        for name_ea, name in idautils.Names():
            # starts with '<moduleName>_'
            inModule = len(name) >= len(self.name)+1 and name[0:len(self.name)+1] == self.name + '_'
            # filter everything not in the module
            if inModule:
                # one file chunk was completed, look for the next
                if foundFirstName and foundLastName:
                    listCsr += 1
                    # Repeat the process for the next field...
                    foundFirstName = False
                    foundLastName = False
                # a new file chunk has been identified
                if not foundFirstName:
                    namesLists.append([])
                    foundFirstName = True
                # add name to the currently identified file chunk
                namesLists[listCsr].append((name_ea, name))

            # we have exited the file chunk. Flag as completed.
            elif foundFirstName and not foundLastName:
                # we have entered the filename field, yet it was not detected in Names...
                foundLastName = True

        return namesLists

    def getModuleFiles(self):
        """
        :return: list(GameFile) list of files of this modules
        """
        file_chunks = self._getModuleFileChunks() # list[list[tuple(long, str)]]
        files = []
        for names in file_chunks: # each file chunk contain a list of names
            # each name is a tuple (name_ea, name)
            first_ea = names[0][0] # ea of the first name in the file
            last_ea = names[-1][0] # ea of the last name in the file
            file = GameFile(first_ea, last_ea)
            files.append(file)
        return files

    def getModuleFunctions(self):
        """
        This traverses all segments, and all defined modules to retrieve all functions with that module name.
        :return: a list of Functions that are in this module, saved in the database.
        """
        output = []
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(idc_bc695.SegStart(seg_ea), idc_bc695.SegEnd(seg_ea)):
                func = Function.Function(func_ea)
                # if the function starts with '<moduleName>'...
                funcName = func.getName()
                inModel = len(funcName) >= len(self.name)+1 and funcName[0:len(self.name)+1] == self.name + '_'
                if inModel:
                    output.append(func)
        return output

    def getVersionSegregatedModuleFuncs(self, otherVersionBinPath):
        """
        This not only searches for function modules, but recognizes functions that are:
        1) Version Dependent functions
        2) Shared by both versions
        3) Functions unique ONLY to this version

        Please note that this has an inherent limitation of only being able to search ROM.
        This means that some 'unique' functions might just exist in RAM, or IRAM, or any non-ROM segments.
        :return: A tuple of the three lists of functions mentioned above: (VersionDependent, Shared, Unique)
        """
        # type: (str) -> tuple(list[tuple(Function, long)], list[Function], list[Function])
        searcher = BinarySearcher(otherVersionBinPath)

        moduleFunctions = self.getModuleFunctions()

        # Search for each function in the other binary!
        matchedFunctions = [] # list of tuples of function in this version, and its match in the other.
        UniqueFunctions = [] # Unique to this version.
        for func in moduleFunctions:
            func_ea = searcher.find_function(func.func_ea)
            if func_ea >= 0:
                matchedFunctions.append((func, ROM_SEG + func_ea)) # found func_ea's are file-relative
            else: # Those are functions unique to THIS version!
                UniqueFunctions.append(func)

        # Those are all of the matches, Find both the VERSION and SHARED Functions!
        SharedFunctions = [] # Same location in both versions
        VersionFunctions = [] # Different locations, but present in both. This is matchedFunctions - SharedFunctions
        for func, otherVersion_func_ea in matchedFunctions:
            if func.func_ea == otherVersion_func_ea: # SHARED!
                SharedFunctions.append(func)
            else: # VERSION DEPENDENT!
                VersionFunctions.append( (func, otherVersion_func_ea) )

        # Close the searcher! good job, searcher-san!
        searcher.closeFiles()

        return VersionFunctions, SharedFunctions, UniqueFunctions


if __name__ == '__main__':
    pass