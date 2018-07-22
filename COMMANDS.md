This file contains documentation for all of the modules and commands available through the pt (PseudoTerminal) object.
# Main Terminal
- **misc** (tools of all kind)
- **dis** (disassembly tools)
- **fix** (emergency room tools for your IDB)
- **srch** (database/binary search tools)
- `help (command/module)` Displays the help docs for a command or module
- `fmt (command/module)` Displays the arguments passed to the command, or a one-line summary of the module
- `echo (msg)` Prints the message
- `time (func, func_args)` Times the passed function
- `clear (n=32)` prints a few lines to make the output window look clear!
- `env (key=Val)` Sets the value `val` to the environmental variable `key` in env. Multiple keys can be assigned with this (key1=val1, key2=val2, ...)
- `clrenv ()` Clears the environment by setting all environmental variables back to their uninitialized state

# dis
This module contains utilities that help with disassembly exporting from IDA.
The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
- `push ()` Disassembles all code file found in env['gameFiles'] and defines header files for them and exports to the project path specified.
- `extract ()` Extracts all binary files found in env['gameFiles'] to the project path specified.
- `checkExtractedCode ()` Makes sure that all extracted binaries contain no code inside them
- `rng (start_ea, end_ea)` This will disassemble from the specified range (if a function item is in the range, 
it will be disassembled completely, even if it exceeds that range).
- `rngExterns (start_ea, end_ea)` Reports back all external symbols used by the specified range
- `rngSyncedExterns (start_ea, end_ea)` Reports back all external symbols, but also specifies includes that expose those symbols from other env['gameFile'] ranges
- `rngInc (start_ea, end_ea)` Reports back the exposed (or public) symbols of the range


# misc
Commands available directly through pt.
- `echo(msg)` This simply prints the message sent to it.
- `clear()` "Clears" the IDA python output window. Actually just prints new lines 32 times.
