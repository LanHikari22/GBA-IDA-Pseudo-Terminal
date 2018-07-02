# GBA-IDA-Pseudo-Terminal
This is a collection of tools that uses the IDAPython API to execute commands for IDB analysis, data exportion, or database manipulation

# Usage
- Run pt.py as a script in python, if successful, the echo command should run with a message in the python output window.
- To view the list of commands (and modules containing commands), execute `pt.help` in the python output window.
- To execute a command, run it like a function: `pt.echo("beep beep!")`. You can also view its docs: `pt.echo.help`.
- There are modules inside pt that are clearly distinguished from commands when executing `pt.help`.
- To access them, simply refer to them from pt: `pt.dis.rng(0x8000000, 0x80000200)`. 
- The module can also display its list of commands and modules: `pt.dis.help`.
- The general rule is, every module and command should have the member help defined in it. Use help on a command for maximum detail.

# Modules
**dis** (Disassembly utils)
- `rng(start_ea, end_ea)` This will disassemble from the specified range (if a function item is in the range, it will be disassembled completely, even if it exceeds that range). The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
- `rngext(start_ea, end_ea)` This will scan all external references used in the specified range, and compute a list of `.equ`s for them
