import idautils
import idaapi
import idc
import idc_bc695

import Definitions
from Definitions.Architecture import ROM_SEG
from IDAItems.Function import Function, FunctionException, isFunction


# CONSTANTS ------------------------------------------------------------------------------------------------------------
class Mode:
    INVALID  = 0
    RANGE    = 1
    NAME     = 2
INFO_SUPPRESSED = True # This toggles debugging info messages

# ----------------------------------------------------------------------------------------------------------------------

class InvalidGameFileException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)


class InvalidModeException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)

def info(msg, suppressed):
    """
    A little function to display info messages for debugging
    :param msg:
    :param suppressed:
    :return:
    """
    if not suppressed: print (msg)


class GameFile:
    def __init__(self, *args):
        """
        Depending on the method of initiating the GameFile, it will operate on different modes. A File defined based on
        purely a range, cannot have a unified 'filename' for example.
        :raises InvalidGameFileException: if file boundaries could not be determined
        :param args: Below is a list of different ways to instantiate a game file
        fromRange(start_ea, end_ea)
            Instantiates a Gamefile object based on the boundaries given. This will override any
            heuristics used to identify game files. The file is all elements within the specified boundary. Period.
            Mode: Mode.RANGE
            :param start_ea: (int) The absolute start address of the file;
            :param end_ea: (int) The absolute end address of the file
        fromName(fileName)
            A heuristic that assumes the file boundaries based on the defined name of the file. Other modules can
            perform their own logic and rename functions to indicate they belong to the same file.
            The filename specification is that all named items must begin with '<fileName>_'
            Mode: Mode.RANGE | Mode.NAME
            :param fileName: (str) The name of the file to scan for.
            :raises InvalidGameFileException This exception is raised when the fileName is detected in multiple
            places, but is cut by another fileName in the middle.
            For example: if there are two subroutines in a Battle GameFile, their names could be something like
            Battle_08040000 and Battle_08090000. The ea of the lowest Battle subroutine, and the highest one will be
            used, and linearly swept to determine the boundaries of the file.
            Function heads, location heads that are not within a function, and data heads from minEA to maxEA
            must have a name that begins with 'Battle_', or this exception will be raised.
        fromEA(ea)
            This relies on the naming convention found at the specified region in ea
            A region with a unique file naming convention is identified at the specified ea
            ea can be anywhere within the range, the search is bidirectional.
            For example: if the address space [0x50, 0x100] contains the naming convention icecream_*,
            then specifying ea=0x75 will return a file with the range [0x50, 0x100]
            :param ea: An effective address within the local name range
        """
        # Case: GameFile(start_ea, end_ea)
        if len(args) == 2 and (type(args[0]) == long and type(args[1]) == long or
        type(args[0]) == int and type(args[1]) == int):
            info('init GameFile(start_ea, end_ea)', suppressed=INFO_SUPPRESSED)
            self.mode = Mode.RANGE # Only RANGE mode enabled
            self.start_ea = args[0]
            self.end_ea = args[1]
        # Case: GameFile(fileName)
        elif len(args) == 1 and type(args[0]) == str:
            info('init GameFile(fileName)', suppressed=INFO_SUPPRESSED)
            self.mode = Mode.RANGE | Mode.NAME # Both range, and a unified filename is available to work with.
            self.name = args[0]
            prev_ea = -1
            last_name = ''
            foundFirstName = False
            foundLastName = False
            for name_ea, name in idautils.Names():
                # a name is in a file with the name <filename> if it starts with '<filename>_'
                inFile = len(name) > len(self.name) and name[0:len(self.name)+1] == self.name + '_'
                if inFile:
                    # Just found the first name with the filename, every next name should contain it until EOF!
                    if not foundFirstName:
                        self.start_ea = name_ea
                        foundFirstName = True
                    # Even though we finished investigating, we found a name belonging to our file... Oops.
                    if foundFirstName and foundLastName:
                        raise FunctionException("Name '%s' found after last file name @ 0x%08X: %s" % (name, self.end_ea, last_name))
                # we have entered the filename field, yet it was not detected in Names...
                elif foundFirstName and not foundLastName:
                    self.end_ea = prev_ea # The last input was valid! We're done! (Or so we hope)
                    last_name = name
                    foundLastName = True
                # This'll be needed to retrieve the last entry. It's a none-casual system!
                prev_ea = name_ea
        else:
            raise Exception('Invalid Parameters passed to constructor')

        # If we couldn't determine boundaries, this isn't a valid file
        try:
            self.start_ea, self.end_ea
        except AttributeError:
            raise InvalidGameFileException('GameFile boundaries could not be determined')

        # a function's contents are also part of the boundary! This part auto-adjusts self.end_ea
        # if idc.isCode(idc.get_func_flags(self.end_ea)) != -1: # TODO: doesn't fail when Function fails sometimes?
        try:
            func = Function(self.end_ea)
            self.end_ea += func.getSize()
        except FunctionException as e:
            pass
        except Exception as e:
            # TODO: for whatever reason needed when e being InvalifFunctionException is not caught anyway
            pass

        # Cache list of names involved for further operation
        self.names = []
        for name_ea, name in idautils.Names():
            if self.start_ea <= name_ea < self.end_ea:
                self.names.append((name_ea, name))

    @classmethod
    def fromRange(cls, start_ea, end_ea):
        # type: (int,int) -> GameFile
        return cls(start_ea, end_ea)

    @classmethod
    def fromName(cls, filename):
        # type: (str) -> GameFile
        return cls(filename)

    @ classmethod
    def fromLocalNsme(cls, ea, filename):
        # type: (int, str) -> GameFile
        return cls(ea, filename)

    def hasName(self):
        return self.mode & Mode.NAME != 0

    def getName(self):
        """
        Only operable if in Mode.NAME mode. Check __init__ for more details.
        When calling, Always check first with hasName()
        :raises InvalidModeException: if self.mode does not contain within it Mode.NAME
        :return: The name of the GameFile
        """
        if self.mode & Mode.NAME == 0: raise InvalidModeException('The GameFile does not operate based on file names')
        return self.name

    def setName(self, newFilename, suppressed=True):
        """
        Only operable if in Mode.NAME mode. Check __init__ for more details.
        :raises InvalidModeException: if self.mode does not contain within it Mode.NAME
        :param newFilename: Filename to rename all Names within the file boundaries based on
        :param suppressed: suppress info prints about what is being renamed to what
        """
        if self.mode & Mode.NAME == 0: raise InvalidModeException('The GameFile does not operate based on file names')
        info('Renaming GameFile %s to %s...' % (self.name, newFilename), suppressed)
        for name_ea, name in self.names:
            newName = newFilename + name[len(self.name):]
            idc.set_name(name_ea, newName)
            info('Renamed %s to %s' % (name, newName), suppressed)

        info('Renaming Complete!', suppressed)

    def getSize(self, withPool=False):
        """
        Computes the size of the file the first time this is called, and caches that computation for later
        :param withPool: (bool) If end_ea is a function, compute its size including its pool if it has any
        :return:  Returns the size of the file in bytes: EndEA + itemSize - StartEA
        """
        if isFunction(self.end_ea):
            return self.end_ea + Function(self.end_ea).getSize(withPool=withPool) - self.start_ea
        return (self.end_ea + idc.get_item_size(self.end_ea) - self.start_ea)

    def getNames(self):
        """
        :return: All of the names contained within the file: a tuple of the item's address then its name
        """
        # type: () -> (long, str)
        return self.names


if __name__ == '__main__':
    # file = GameFile(idc.SegStart(ROM_SEG), idc.SegEnd(ROM_SEG))
    # file = GameFile('StartScreen')
    pass
