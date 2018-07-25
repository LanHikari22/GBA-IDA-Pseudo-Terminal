import idaapi

# Magic to identify instructions
# LDR/STR Magic
INST_LS_IMM = 0x6000  # 0b0110_0000_0000_0000
INST_LS_IMM_H = 0x8000  # 0b1000_0000_0000_0000
INST_LS_REG = 0x5000  # 0b0101_0000_0000_0000
INST_LS_REG_H = 0x5200  # 0b0101_0010_0000_0000
# PC RELATIVE LOAD
INST_LS_PC_REL = 0x4800  # 0b0100_1000_0000_0000
# PUSH/POP Magic
INST_PUSHPOP = 0xB400  # 0b1011_0100_0000_0000
# BX magic
INST_BX = 0x4700
# MOV PC, LR
INST_MOV_PC_LR = 0x46F7
# MOV REG, #IMM
INST_MOV_IMM = 0x2000

def authInstruction(inst, magic, opSize):
    """
    Confirms that magic matches by masking the instruction with the magic
    and confirming that only the magic remains.
    It also checks if op matches.
    :param: inst the 2 bytes instruction to be authenticated
    :param: magic the magic that must be set in the instruction
    :param: opSize number of MSB bits the op is in the magic
    :return: True if all tests pass, False otherwise
    """
    op = magic >> (16 - opSize)
    output = True
    if inst & magic != magic:
        output = False
    if inst >> (16 - opSize) != op:
        output = False
    return output

def decode(inst):
    """
    Decodes the instruction and returns a dictionary of its fields. All dictionaries have the magic key,
    which is unique to one INST_XXXX constant.
    :return: dict of decoded instruction or None
    """
    output = decodeBX(inst)
    if not output: output = decodeLdrStr(inst)
    if not output: output = decodeMovImm(inst)
    if not output: output = decodePCRel(inst)
    if not output: output = decodePushPop(inst)
    if not output and inst == INST_MOV_PC_LR:
        output = {'name': 'INST_MOV_PC_LR', 'magic': INST_MOV_PC_LR}
    if output: output['inst'] = '0x%X' % inst
    return output

def decodeLdrStr(inst):
    """
    Decodes an LDR/STR instruction and returns a dictionary. Type depent on op (and magic).
    Only loads/stores of the types "str r0, [r1, r2]" and "ldr r5, [r6, 0xFF]" are decoded.
    op is found in MSB 3 bits or 4 bits.
    magic will be INST_IMM, INST_IMM_H, INST_REG, or INST_REG_H. Indicating halfword vs not, and INST_IMMediate offset vs not.
    [self.INST_IMM]
    op = 0b011: {magic, op, byte, load, offset, Rb, Rd} (byte(B)=byte, load(L)=Load, Rb=Base REG, Rd=Dest REG)
    [self.INST_IMM_H]
    op = 0b1000: {magic, op, load, offset, Rb, Rd}
    [self.INST_REG, self.INST_REG_H]
    op = 0b0101:
        [self.INST_REG]
        bit[9]=0: {magic, op, load, byte, Ro, Rb, Rd} (INST_REG str/ldr: ldr r5, [r3, r0]
        [self.INST_REG_H]
        bit[9]=1: {magic, op, H, S, Ro, Rb, Rd} (s'h' = strh, s'h = ldrh, sh' = ldsb, sh = ldsh)
    :return: a valid instruction table or None
    """
    output = None  # invalid instruction, unless one of the following matches
    Rb = 7 << 3
    Rd = 7
    if authInstruction(inst, INST_LS_IMM, 3):
        B = 1 << 12
        L = 1 << 11
        off5 = 31 << 6
        output = dict()
        output["name"] = "LS_IMM"
        output["magic"] = INST_LS_IMM
        output["op"] = INST_LS_IMM >> 13
        output["byte"] = (inst & B) >> 12
        output["load"] = (inst & L) >> 11
        if output["byte"]:
            output["offset"] = (inst & off5) >> 6
        else:  # if B': Off7 will be Off5<<2 from inst
            output["offset"] = ((inst & off5) >> 6) << 2

        output["Rb"] = (inst & Rb) >> 3
        output["Rd"] = inst & Rd
    elif authInstruction(inst, INST_LS_IMM_H, 4):
        L = 1 << 11
        off6 = 31 << 6
        output = dict()
        output["name"] = "LS_IMM_H"
        output["magic"] = INST_LS_IMM_H
        output["op"] = INST_LS_IMM_H >> 12
        output["load"] = (inst & L) >> 11
        output["offset"] = ((inst & off6) >> 6) << 1
        output["Rb"] = (inst & Rb) >> 3
        output["Rd"] = inst & Rd
    elif authInstruction(inst, INST_LS_REG_H, 4):  # TODO: placement of this 'if' is necessary
        # TODO: test
        H = 1 << 11
        S = 1 << 10
        Ro = 7 << 6
        output = dict()
        output["name"] = "LS_REG_H"
        output["magic"] = INST_LS_REG_H
        output["op"] = INST_LS_REG_H >> 12
        output["H"] = (inst & H) >> 11
        output["S"] = (inst & S) >> 10
        output["Ro"] = (inst & Ro) >> 6
        output["Rb"] = (inst & Rb) >> 3
        output["Rd"] = inst & Rd
    elif authInstruction(inst, INST_LS_REG, 4):
        # TODO: test
        L = 1 << 11
        B = 1 << 10
        Ro = 7 << 6
        output = {}
        output["name"] = "LS_REG"
        output["magic"] = INST_LS_REG
        output["op"] = INST_LS_REG >> 12
        output["load"] = (inst & L) >> 11
        output["byte"] = (inst & B) >> 10
        output["Ro"] = (inst & Ro) >> 6
        output["Rb"] = (inst & Rb) >> 3
        output["Rd"] = inst & Rd

    return output



def decodePushPop(inst):
    """
        Decodes a push/pop instruction and returns a table with fields from the inst.
        op can be found to be the 4 MSB in the instruction.
        All keys are strings.
        op = 0b1011: {magic, op, pop, pc, Rlist}
        pop (L): (0 - push), (1 - pop).
        lr (R): (0 - do not store LR/load PC), (1 - store LR/load PC)
        Rlist: This will be 7 bits. Each are flags for the registers r0-r7 to be pushed/popped.
        ex: Rlist=0b01010001 pushes or pops r0, r4, and r6.
        :return: a valid instruction table or None
    """
    output = None  # invalid instruction, unless one of the following matches

    if authInstruction(inst, INST_PUSHPOP, 4):
        L = 1 << 11
        R = 1 << 8
        Rlist = 0xFF
        output = dict()
        output["name"] = "PUSHPOP"
        output["magic"] = INST_PUSHPOP
        output["op"] = INST_PUSHPOP >> 12
        output["pop"] = (inst & L) >> 11
        output["lr"] = (inst & R) >> 8
        output["Rlist"] = inst & Rlist
    return output



def decodeBX(inst):
    """
    If this is a BX instruction, this will return a dictionary containing its magic (INST_BX), and reg number
    or None, if it's not a BX
    :return: {magic, reg} if it's a BX instruction or None
    """
    output = None
    if (inst & 0xFF00) == INST_BX:
        output = {'name': 'BX',
                  'magic': INST_BX,
                  'reg': (inst - INST_BX) / 8}
    return output



def decodeMovImm(inst):
    """
    returns None or {magic=MOV_IMM, Rd, imm}
    """
    output = None
    # Magic must match, and the instruction only allows destination register up to r7
    if inst & INST_MOV_IMM == INST_MOV_IMM and inst < INST_MOV_IMM + 0x800:
        output = {"name": "MOV_IMM",
                  "magic": INST_MOV_IMM,
                  "Rd": (inst & 0x700) >> 8,
                  "imm": inst & 0xFF}
    return output



def decodePCRel(inst):
    """
    returns nil or {magic=PC_REL, Rd, pc_offset}
    When trying to access the actual data loaded given the address the instruction is at, pc:
    The address is always at the next work from pc + pc_offset.
    If pc is word-aligned, it would be (pc+4) + pc_offset , if it's halfword-aligned, it would be (pc+2) + pc_offset
    """
    output = None
    Rd = 0x0700  # bits[10:8] of inst
    word8 = 0xFF  # bits[7:0] of inst
    if inst & 0xF800 == INST_LS_PC_REL:
        output = {"name": "LS_PC_REL",
                  "magic": INST_LS_PC_REL,
                  "Rd": (inst & Rd) >> 8,
                  "pc_offset": 4 * (inst & word8)}  # it's 4 times because this is a word offset
    return output

def getPushPopRegisters(Rlist):
    """
    Returns the list of registers from regList for PUSH/POP instructions
    :param Rlist: flags field found in the instruction
    :return: list of integers representing register numbers
    """
    i = 1
    regNo = 0
    output = []
    while i != 1<<8:
        if Rlist & i:
            output.append(regNo)
        i <<= 1
        regNo += 1
    return output

class Inst:
    def __init__(self, inst, isContent=False):
        # type: (int, bool) -> ()
        """
        Loads the content at the specified address inst. if isContent, inst itself is taken as the content
        :param inst: linear address of instuction item, or the content itself
        :param isContent: whether inst is a linear address or content
        """
        if isContent:
            self.inst = inst
        else:
            self.inst = idaapi.get_bytes(inst, 2)
            self.inst = ord(self.inst[0]) + (ord(self.inst[1]) << 8)
            # TODO: if it's a BL, it's 4 bytes, figure that out here
        self.fields = decode(self.inst)