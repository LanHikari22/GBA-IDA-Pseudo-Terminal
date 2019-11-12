
# ROM Addresses are absolute, not file relative. Configure the start address for ROM
ROM_SEG = 0x08000000

# ARM Cortex-M4 Thumb mode instruction width in bytes
# TODO: reove this, you can find out through the IDAPython API
INSTRUCTION_WIDTH = 2

# ARM Cortex-M4 Thumb mode Instruction that is actually 4 bytes
LONG_INSTRUCTION = 'BL'

