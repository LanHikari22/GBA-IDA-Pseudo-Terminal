"""
The type of instruction can be gotten from Insn().insn.itype. Those can be checked against instrunction macros
in ida_allins: NN_*
"""
import idaapi
import ida_ua
import idc

class InstructionException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)

def isInsn(insn_ea):
    return ida_ua.can_decode(insn_ea)

def isPoolLDR(insn_ea):
    ida_ua.decode_insn(insn_ea)
    hasPool = idaapi.cmd.ops[1].type == ida_ua.o_mem
    return idaapi.cmd.itype == idaapi.NN_cdq and hasPool


class Insn:
    def __init__(self, insn_ea):
        """

        :param insn_ea:
        """
        if not ida_ua.can_decode(insn_ea):
            raise InstructionException("Cannot decode instruction @ %07X" % insn_ea)

        self.size = ida_ua.decode_insn(insn_ea)
        self.insn = idaapi.cmd
        self.ops = self.insn.ops
        self.itype = self.insn.itype
        self.ea = self.insn.ea

    def isDataInsn(self):
        """
        :return: True if the instruction is computational. This includes MOV, ADD, MUL, LSL, etc.
        """
        type = self.insn.itype
        return type in [idaapi.ARM_mov, idaapi.ARM_add, idaapi.ARM_sub, idaapi.ARM_mul, idaapi.ARM_lsl,
                        idaapi.ARM_lsl, idaapi.ARM_and, idaapi.ARM_not, idaapi.ARM_orr, idaapi.ARM_eor,
                        idaapi.ARM_cmp, idaapi.ARM_tst, idaapi.ARM_bic]

    def isComputationalInsn(self):
        """
        All instructions in which first op is a destination register
        :return:
        """
        type = self.insn.itype
        output = self.insn.ops[0].type == ida_ua.o_reg
        output = (output and type in [idaapi.ARM_mov, idaapi.ARM_add, idaapi.ARM_sub, idaapi.ARM_mul, idaapi.ARM_lsl,
                        idaapi.ARM_lsl, idaapi.ARM_and, idaapi.ARM_not, idaapi.ARM_orr, idaapi.ARM_eor,
                        idaapi.ARM_bic,
                        idaapi.ARM_str, idaapi.ARM_ldr, idaapi.ARM_ldrpc])
        return output



    def isMemInsn(self):
        """
        TODO: find ldr
        Includes LDR, STR, PC-relative LDR, PUSH, POP,
        :return: True if it's a memory instruction
        """
        type = self.insn.itype
        return type in [idaapi.ARM_str, idaapi.ARM_ldr, idaapi.ARM_ldrpc]

    def isCtrlInsn(self):
        type = self.insn.itype
        raise(NotImplemented())

    def isPoolLDR(self):
        """
        :return: True if the current instruction is a PC-relative load
        """
        type = self.insn.itype
        hasPool = self.insn.ops[1].type == ida_ua.o_mem
        return type == idaapi.NN_cdq and hasPool

    def getMnem(self):
        """
        Returns the mnem of the instruction, like 'BL' in 'BL sub_8040000'
        :return:
        """
        return idc.GetMnem(self.ea)

    def numOperands(self):
        for i in range(0, ida_ua.UA_MAXOP):
            if self.insn.ops[i].type == ida_ua.o_void:
                return i
        return ida_ua.UA_MAXOP

    def printOperands(self):
        for i in range(0, ida_ua.UA_MAXOP):
            op = self.insn.ops[i]
            type = op.type
            if type == ida_ua.o_void:
                break
            elif type == ida_ua.o_reg:
                print('op %d: reg (R%d)' % (i, op.reg))
            elif type == ida_ua.o_imm:
                print('op %d: imm (0x%X)' % (i, op.value))
            elif type == ida_ua.o_mem:
                print('op %d: mem 0x%07X <%s>' % (i, idc.Name(op.addr)))
            elif type == ida_ua.o_phrase:
                print('op %d: phrase (R%d, R%d)' % (i, op.reg, op.specflag1)) # specflag1 has Rz in 'LDR Rx, [Ry, Rz]'
            elif type == ida_ua.o_displ:
                print('op %d: displ (R%d, 0x%X)' % (i, op.reg, op.addr))
            elif type == ida_ua.o_far:
                print('op %d: far (%s)' % (i, idc.Name(op.addr)))
            elif type == ida_ua.o_near:
                print('op %d: near (%s)' % (i, idc.Name(op.addr)))
            elif type == ida_ua.o_idpspec0:
                print('op %d: idpspec0 (0ffb=%d, value=0x%X, addr=0x%X, specval=0x%X)' %
                      (i, op.offb, op.value, op.addr, op.specval))
            elif type == ida_ua.o_idpspec1:
                print('op %d: push/pop (regFlags=0x%X)' %
                      (i, op.specval))
            else:
                print('op %d: unknown (%d)' % (i, type))

    def getPushPopFlags(self):
        # type: () -> int
        """
        Parses Push/Pop Register flags and returns them, or returns False if not a PushPop instruction
        :return: flags for each register packaged in an int
        """
        if ((self.itype == idaapi.ARM_push or self.itype == idaapi.ARM_pop)
            and self.ops[0].type == ida_ua.o_idpspec1
            ):
            return self.ops[0].specval
        return False
