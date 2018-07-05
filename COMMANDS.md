This file contains documentation for all of the modules and commands available through the pt (PseudoTerminal) object.
# Modules
**dis** (Disassembly utils)

# misc
Commands available directly through pt.
- `echo(msg)` This simply prints the message sent to it.
- `clear()` "Clears" the IDA python output window. Actually just prints new lines 32 times.
# dis
This module contains utilities that help with disassembly exporting from IDA.
The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
- `rng(start_ea, end_ea)` This will disassemble from the specified range (if a function item is in the range, 
it will be disassembled completely, even if it exceeds that range).
- `rngext(start_ea, end_ea)` This will scan all external references used in the specified range, and compute a list of `.equ`s for them
