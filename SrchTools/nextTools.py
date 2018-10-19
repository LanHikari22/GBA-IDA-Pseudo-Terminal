# @file next
# tools for finding the next occurrance of something
import idaapi
import idautils

idaapi.require("IDAItems.Data")
idaapi.require("IDAItems.Function")
idaapi.require("IDAItems.InstDecoder")
idaapi.require("TerminalModule")

from Definitions import Architecture, Paths

import idc
from IDAItems import Function, Data, InstDecoder
import TerminalModule


class next:
    """
    A collection of tools that find the next occurrance of a specific type of item
    """

    def __init__(self):
        """
        This module is responsible for printing disassemblies and necessary compoents
        of disassemblies
        """
        # figure out the very last ea reachable
        self.end_ea = 0
        for seg in idautils.Segments():
            if idc.SegEnd(seg) > self.end_ea:
                self.end_ea = idc.SegEnd(seg)

        # TODO: fix return type to just be output int, not str


    def arm(self, ea, ui=True):
        # type: (int) -> str
        """
        Finds the next ARM item, which has a Segment register value 'T' of 0
        :param ea: address to start searching from
        :param ui: if True, jump to address automatically
        :return: the address (in str) of the next ARM instruction
        """
        # don't count this item
        ea += Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # detect next code32
            if idc.GetReg(ea, 'T') == 0:
                output = ea
                break
            ea += d.getSize()
        return '%07X' % output

    def ascii(self, ea, ui=True):
        # type: (int) -> str
        """
        returns the next data item containing ascii characters (seems valid for utf too)
        :param ea: the address to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted str of the address of the next ascii item
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if idc.isASCII(d._getFlags()):
                output = ea
                break
            ea += d.getSize()
        if ui: idaapi.jumpto(output)
        return '%07X' % output

    def fakeinst(self, ea, ui=True):
        # type: (int) -> str
        """
        returns the next code item which is registered as a potential fake instruction.
        Those may also be redundant instructions, which get encoded differently outside of IDA
        the found instructions may also be pure data
        :param ea: address to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted ea
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            # ARM, unless it's a branch
            if d.isCode() and d.getContent() in self._getFakeInstructions():
                output = ea
                break
            ea += d.getSize()
        # trigger the gui to jump to the hypothetical next fake instruction
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    @staticmethod
    def _getFakeInstructions():
        """
        a list of detected instructions with different encoding using arm-none-eabi gcc
        :return: list of opcodes
        """
        # TODO: super clumsy, replace this with logical detection. (I don't want to because, incidentally this is a
        # TODO: good way of detecting false code)
        return [0x0, 0x1, 0x2, 0x3, 0x4, 0x09, 0xA, 0x19, 0x1B, 0x22, 0x1C00, 0x1C09, 0x1C12, 0x1C1B, 0x1F9B, 0x4425,
                0xB85D, 0xB88B, 0xB8A3]


    def name(self, ea, ui=True, hexOut=True, reverse=False):
        """
        Finds the next ea with which a name exists
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :param hexOut: output hex formatted ea if True
        :return: ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if d.getName():
                output = ea
                break
            ea += d.getSize()
        if ui: idaapi.jumpto(ea)
        if hexOut:
            return '%07X' % output
        return output

    def known(self, ea, ui=True):
        """
        Finds the next ea of an item that is not unknown
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if not idc.isUnknown(d._getFlags()):
                output = ea
                break
            ea += d.getSize()
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    def bin(self, ea, ui=True):
        """
        Finds the next big blob of data. The heuristic is it has to be at least sizeLimitHeuristic in size
        UI jumps to start_ea automatically.
        :param ea: ea to search from
        :param ui: if True, jump to address automatically
        :return: tuple hex format of the bin range and the size: (%07X, %07X, 0x$X)
        """
        sizeLimitHeuristic = 0x1000

        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()

        # range params
        start_ea = idaapi.BADADDR
        end_ea = idaapi.BADADDR
        size = 0

        # state machine of finding range
        st_start = 0
        st_traverse = 1
        st_end = 2
        state = st_start

        while ea < self.end_ea:
            d = Data.Data(ea)

            if not d.isCode():
                if state == st_start:
                    start_ea = ea
                    size = 0
                    state = st_traverse
                if state == st_traverse:
                    size += d.getSize()
                if state == st_end:
                    raise(Exception('entered invalid state'))

            if d.isCode():
                # only end if valid size
                if state == st_traverse:
                    if size >= sizeLimitHeuristic:
                        state = st_end
                    else:
                        state = st_start
                if state == st_end:
                    end_ea = ea
                    break

            ea += d.getSize()
        idaapi.jumpto(start_ea)
        return '0x%07X, 0x%07X, 0x%X' % (start_ea, end_ea, size)

    def red(self, ea, end_ea=None, ui=True, hexOut=True):
        """
        Looks for code items outside function items. The first detected is returned
        :param ea: ea to start searching from
        :param end_ea: the last address of the search range, or default if None
        :param ui: if True, jump to address automatically
        :param hexOut: output hex formatted ea range instead
        :return: ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        if not end_ea: end_ea = self.end_ea
        while ea < end_ea:
            d = Data.Data(ea)
            if d.isCode() and not Function.isFunction(d.ea):
                output = ea
                break
            ea += d.getSize()
        if ui: idaapi.jumpto(ea)
        if hexOut: return '%07X' % output
        return output

    def immref(self, ea, ui=True):
        """
        Finds the next occurrance of an immediate value being a reference, like
        ldr r2, [r2,#(dword_809EEF4+0x1F8 - 0x809f0e4)]
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :return: hex formatted ea of next name
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        while ea < self.end_ea:
            d = Data.Data(ea)
            if d.isCode() and '#' in d.getOrigDisasm():
                disasm = d.getOrigDisasm()
                # check out the xrefs from the data, see if it references to them
                xrefs = d.getXRefsFrom()
                for xref in xrefs[0]:
                    if Data.Data(xref).getName() in disasm:
                        output = ea
                        break
                for xref in xrefs[1]:
                    if Data.Data(xref).getName() in disasm:
                        output = ea
                        break
                if output != idaapi.BADADDR:
                    break
            ea += d.getSize()
        if ui: idaapi.jumpto(ea)
        return '%07X' % output

    def ret(self, ea, end_ea=None, ui=True, hexOut=True):
        """
        Looks for the next data item that encodes a function return
        - BX LR
        - MOV PC, LR
        - PUSH {..., LR} [Up to instLimit gap insts] POP {..., LR} (regLists must be matching)
        - POP {R<X>} [Up to instLimit gap insts] BX R<X>
        :param ea: ea to start searching from
        :param end_ea: the last address to look for
        :param ui: if True, jump to address automatically
        :param hexOut: output hex formatted ea instead
        :return: ea of next ret
        """
        # state machine states for differnt return types that take more than one instruction
        ST_NONE = 0
        ST_PUSH = 1
        ST_BX = 2
        # current state is instruction-by-instruction. We haven't detected anything that could be part of return
        state = ST_NONE
        # count before state resets back due to the right combination not being found
        instTimer = 0
        instLimit = 150
        # those need to be maintanied so that they're compared against an identical POP PC
        pushRegs = []
        # register number needs to match in POP, BX pattern
        bxReg = -1
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        output = idaapi.BADADDR
        # use default end_ea, if no search limit is provided
        if not end_ea: end_ea = self.end_ea
        while ea < end_ea:
            currInst = InstDecoder.Inst(ea).fields
            if currInst and (currInst['magic'] == InstDecoder.INST_MOV_PC_LR or
                             currInst['magic'] == InstDecoder.INST_BX and currInst['reg'] == 14):
                output = ea
                break
            if state == ST_NONE:
                if currInst and currInst['magic'] == InstDecoder.INST_PUSHPOP:
                    regs = InstDecoder.getPushPopRegisters(currInst['Rlist'])
                    # PUSH {PC. ...}
                    if not currInst['pop'] and currInst['lr']:
                        state = ST_PUSH
                        pushRegs = regs
                    # POP {R<X>}
                    elif currInst['pop'] and not currInst['lr'] and len(regs) == 1:
                        state = ST_BX
                        bxReg = regs[0]

            # look for a matching  POP {..., PC}
            elif state == ST_PUSH:
                if (currInst and currInst['magic'] == InstDecoder.INST_PUSHPOP and
                    currInst['pop'] and currInst['lr']):
                    regs = InstDecoder.getPushPopRegisters(currInst['Rlist'])
                    if pushRegs == regs:
                        output = ea
                        break

            # look for a matching BX R<X>
            elif state == ST_BX:
                if currInst and currInst['magic'] == InstDecoder.INST_BX and currInst['reg'] == bxReg:
                    output = ea
                    break

            # advance time limit for pattern match, must be within instLimit instructions
            if state == ST_PUSH or state == ST_BX:
                # reset and go back to default state
                if instTimer == instLimit:
                    instTimer = 0
                    state = ST_NONE
                # advance timer
                else:
                    instTimer += 1
            # advance to the next hypothetical thumb instruction
            ea += 2
        if ui: idaapi.jumpto(ea)
        if hexOut: return '%07X' % output
        return output

    def unkret(self, ea, end_ea=None, ui=True, hexOut=True):
        """
        Thhs finds the next return based on the next.ret function, that is not already defined within a function.
        This counts red code, unknown bytes, and returns hidden within data.
        :param ea: ea to start searching from
        :param end_ea: the last address to look for
        :param ui: if True, jump to address automatically
        :param hexOut: output hex formatted ea instead
        :return: ea of next unknown return
        """
        ea = self.ret(ea, end_ea, ui=False, hexOut=False)
        output = idaapi.BADADDR
        if not end_ea: end_ea = self.end_ea
        while ea < end_ea:
            d = Data.Data(ea)
            if not Function.isFunction(d.ea):
                output = ea
                break
            ea = self.ret(ea, end_ea, ui=False, hexOut=False)
        if ui: idc.jumpto(output)
        if hexOut: return '%07X' % output
        return output

    def deadfunc(self, ea, end_ea=None, ui=True, hexOut=True):
        """
        This finds the next occurrance of a dead function not recognized as a function (ie, red code or data)
        This can only find functions ranges it can guarantee, ie, only PUSH {..., LR} POP {..., PC} patterns.
        :param ea: ea to start searching from
        :param end_ea: the last address of the search range
        :param ui: if True, jump to address automatically
        :param hexOut: output hex formatted ea range instead
        :return: range of ea of next dead function
        """
        # don't count this item
        ea = Data.Data(ea).ea + Data.Data(ea).getSize()
        foundPush = False
        push_ea = idaapi.BADADDR
        pop_ea = idaapi.BADADDR
        push_regs = None
        if not end_ea: end_ea = self.end_ea
        while ea < end_ea:
            # the current item must not belong to a function, or have any data xrefs
            if not Function.isFunction(ea) and not Data.Data(ea).getXRefsTo()[1]:
                inst = InstDecoder.Inst(ea).fields
                # if PUSH {..., LR}
                if inst and inst['magic'] == InstDecoder.INST_PUSHPOP and not inst['pop'] and inst['lr']:
                    foundPush = True
                    push_ea = ea
                    push_regs = inst['Rlist']
                # detected a POP {..., PC} after the PUSH {..., LR}, and the registers match
                if (foundPush and inst and inst['magic'] == InstDecoder.INST_PUSHPOP and inst['pop'] and inst['lr']
                        and inst['Rlist'] == push_regs):
                    pop_ea = ea
                    break
            else:
                foundPush = False
            ea += 2

        if ui: idc.jumpto(push_ea)
        if hexOut: return '(%07X, %07X)' % (push_ea, pop_ea)
        return (push_ea, pop_ea)

    def fakered(self, ea, end_ea=None, ui=True, hexOut=True):
        """
        This finds the next occurrance of a not a red code segment that has no return pattern to it, making it unlikely
        to belong to a function.
        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :param end_ea: the last address of the search range. If not specified, default is used.
        :param hexOut: output hex formatted ea range instead
        :return: range of ea of next fake red code segment
        """
        # TODO: change implementation to be based on return patterns?
        ea = self.red(ea, end_ea, ui=False, hexOut=False)
        start_ea = ea
        end_red_ea = idaapi.BADADDR
        # flag for when the whole red segment is finished and we can go to the next red code segment
        finishedSegment = False
        # condition for if the segment has already been invalidated before reaching its end
        isFake = True

        if not end_ea: end_ea = self.end_ea
        while ea < end_ea:
            d = Data.Data(ea)
            inst = InstDecoder.Inst(ea).fields

            # traverse red code, and find the end of the red segment
            if Function.isFunction(ea) and d.isCode() or not d.isCode():
                # update region end to this red code region
                end_red_ea = ea
                # confirm if the return is within range, then this isn't fake code. Find the next red!
                if isFake : # or start_ea <= self.unkret(start_ea-instLimit, end_ea, ui=False, hexOut=False) < end_ea:
                    break
                # search the next red region
                isFake = True
                start_ea = ea = self.red(end_red_ea, end_ea, ui=False, hexOut=False)

            # advance through the red code
            else:
                # simple function pattern,s, if it sorta looks like it can be a function, don't count it as fake.
                # this includes return patterns, and push/pop.
                if inst and (inst['magic'] == InstDecoder.INST_MOV_PC_LR or
                                         inst['magic'] == InstDecoder.INST_BX and inst['reg'] == 14 or
                                         inst['magic'] == InstDecoder.INST_PUSHPOP and inst['lr']):
                    isFake = False
                ea += d.getSize()
        if ui: idc.jumpto(end_red_ea - 2)
        if hexOut: return '(%07X, %07X)' % (start_ea, end_red_ea)
        return (start_ea, end_red_ea)

    def unkptr(self, ea, end_ea=0x08800000, rom=True, ui=True, hexOut=True):
        """

        :param ea: ea to start searching from
        :param ui: if True, jump to address automatically
        :param end_ea: the last address of the search range. If not specified, default is used.
        :param hexOut: output hex formatted ea range instead
        :return: range of ea of next unknown/unexplored pointer
        """

        output = idaapi.BADADDR

        # advance an element so multiple calls to this function can chain
        d = Data.Data(ea)
        ea += d.getSize()
        # ea must be divisible by 4, since all pointers are 32-bit
        if ea % 4 != 0:
            ea += 4 - (ea % 4)

        while ea < end_ea:
            d = Data.Data(ea)
            chars = idc.get_bytes(ea, 4)
            dword = 0
            for i in range(len(chars)):
                dword += ord(chars[i]) << 8*i
            # compressed pointers may have bit 31 set, so remove it.
            # if dword % (1<<31):
            #     dword -= 1<<31

            # check if dword is a valid pointer
            if rom:
                inRange = 0x08000000 <= dword < 0x08800000 #0x09FFFFFF
            else:
                inRange = (0x02000000 <= dword < 0x02040000 or
                           0x03000000 <= dword < 0x03008000 or
                           0x08000000 <= dword < 0x08800000)
            if (inRange):
                if not d.isCode() and not d.getXRefsFrom()[1]:
                    output = ea
                    if hexOut: print('%07X: %07X <%s>' % (ea, dword, Data.Data(dword).getName()))
                    break
            if d.getXRefsFrom()[1]:
                ea += d.getSize()
                ea += 4 - (ea % 4) if ea % 4 != 0 else 0
            else:
                ea += 4

        if ui: idc.jumpto(output)
