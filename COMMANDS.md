This file contains documentation for all of the modules and commands available through the pt (PseudoTerminal) object.

# Main Terminal
Contains all of the other terminal modules, as well as essential commands
- **misc** (tools of all kind)
- **dis** (disassembly tools)
- **fix** (emergency room tools for your IDB)
- **srch** (database/binary search tools)
- `help (command/module)` 
- `fmt (command/module)` 
- `echo (msg)` simply echos a message to the terminal
        
- `time (func, func_args)` Calls and times the passed in function in ms
        
- `clear (n=32)` prints n new lines
- `env (key=Val)` changes the value of an environmental variable within pt.
        Those environmental variables are used by other commands and modules, and must be configured

        
- `clrenv ()` sets the Environment back to its original state

# misc
Different kinds of commands and tools go here. No label. Just take a look, OK?
- `gendocs (terminalModule)` Actually generates the docs for this file!
        
- `test (_)` This is just a scratchpad!
        
- `fnrepl (start_ea, end_ea, oldstr, newstr)` replace a string once if detected in the names of all functions within range
        
- `plcv (ea)` Converts pool to linker compatible version

        
- `nlrepl (oldStr, newStr)` Replaces string from all names in the global name list
        
- `rngmkd (start_ea, end_ea)` Turns the data in the range to words. If not aligned with words, turns into bytes instead
        

# dis
This module contains utilities that help with disassembly exporting from IDA.
    The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
- `push ()` Automatcally generates disassembly, header, and external symbols for all asmFiles specified
        in env['asmFiles'] and updates the files in the project folder specified
- `extract ()` Extracts all binary ranges specified in env['binFiles'] into *.bin files in the folder env['binPath']
- `checkExtractedCode ()` Checks if any gameFile that is not disassembled has any code in it
        All code must be disassembled, and data should be extracted
        If code is contained within extracted binaries, they are reported back
        
- `rng (start_ea, end_ea)` disassembles all data elements within a range
        if a function is detected within the range, the function itself is disassembled
        as a whole item. (meaning it could surpass end_ea, but it would be the last item)
        
- `rngExterns (start_ea, end_ea)` creates .equs for all external symbols used in the range
        
- `rngSyncedExterns (start_ea, end_ea)` The same as rngext(), except, where it can, it includes header files too!
        This is based on the asmFiles found in env['asmFiles']
        when a header file is included, used symbols from the header file are shown commented out after it
        
- `rngInc (start_ea, end_ea)` Reports back the exposed (or public) symbols of the range
        The symbols are .extern forwarded, and represent the symbols defined within the range
        

# fix
This module contains tools to run on the database to fix problems all throughout the database
    or over a range
- `remFuncChunks ()` deletes all functions that have function chunks in them
        and appends "function_chunks_" to their names
- `replNameParen ()` IDA treats the presence of a paranthesis as '_'. But visually still shows '_'.
        Just replace all of those '(' and ')'s with an actual '_'
        
- `markRedundantInsts (start_ea, end_ea)` Some instructions, like add r0, r0, #0 can be optimized to add r0, #0 by assemblers.
        This gets in the way of disassembly. This attempts to fix that by replacing all such occurrances with
        purely their data format, and it also adds a comment on that line specifying the original inst.

        To specify that a data item has to be forced to data, this puts <mkdata> in its comment.
        
- `makeThumb (start_ea, end_ea)` Changes all ARM within the specified range to THUMB
        
- `changeASCII ()` finds all ascii named data and changes it to bytes and removes its name
- `removeStackVarUsages (start_ea, end_ea)` 

# srch

- **next** (occurrence of something tools)

# next

- `arm (search_ea, ui=True)` Finds the next ARM item, which has a Segment register value 'T' of 0
        
- `ascii (search_ea, ui=True)` returns the next data item containing ascii characters (seems valid for utf too)
        
- `fakeinst (search_ea, ui=True)` returns the next code item which is registered as a potential fake instruction.
        Those may also be redundant instructions, which get encoded differently outside of IDA
        the found instructions may also be pure data
        
- `name (search_ea, ui=True)` Finds the next ea with which a name exists
        
- `known (search_ea, ui=True)` Finds the next ea with which a name exists
        
- `bin (search_ea, ui=True)` Finds the next big blob of data. The heuristic is it has to be at least sizeLimitHeuristic in size
        UI jumps to start_ea automatically.
        
- `red (search_ea, ui=True)` Looks for code items outside function items. The first detected is returned
        
- `immref (search_ea, ui=True)` Finds the next occurrance of an immediate value being a reference, like
        ldr r2, [r2,#(dword_809EEF4+0x1F8 - 0x809f0e4)]
        
- `ret (search_ea, ui=True)` Looks for the next data item that encodes a function return
        - BX LR
        - POP {..., PC} [Up to 50 gap insts] PUSH {..., LR}
        - POP {R<X>} [Up to 5 gap insts] BX R<X>
