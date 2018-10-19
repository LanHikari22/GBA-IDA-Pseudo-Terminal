This file contains documentation for all of the modules and commands available through the pt (PseudoTerminal) object.

# Main Terminal
Contains all of the other terminal modules, as well as essential commands
- **dis** (disassembly tools)
- **srch** (database/binary search tools)
- **fix** (emergency room tools for your IDB)
- **misc** (tools of all kind)
- `help (command/module)` 
- `fmt (command/module)` 
- `echo (msg)` simply echos a message to the terminal
        
- `time (func, func_args)` Calls and times the passed in function in ms
        
- `clear (n=32)` prints n new lines
- `env (key=Val)` changes the value of an environmental variable within pt.
        Those environmental variables are used by other commands and modules, and must be configured

        
- `clrenv ()` sets the Environment back to its original state

# dis
This module contains utilities that help with disassembly exporting from IDA.
    The disassembly is in a format compatible with the none-arm-eabi-gcc assembler.
- `push()` Automatcally generates disassembly, header, and external symbols for all asmFiles specified
        in env['asmFiles'] and updates the files in the project folder specified
- `extract()` Extracts all binary ranges specified in env['binFiles'] into *.bin files in the folder env['binPath']
- `checkExtractedCode()` Checks if any gameFile that is not disassembled has any code in it
        All code must be disassembled, and data should be extracted
        If code is contained within extracted binaries, they are reported back
        
- `rng(start_ea, end_ea)` disassembles all data elements within a range
        if a function is detected within the range, the function itself is disassembled
        as a whole item. (meaning it could surpass end_ea, but it would be the last item)
        
- `rngExterns(start_ea, end_ea)` creates .equs for all external symbols used in the range
        
- `rngSyncedExterns(start_ea, end_ea)` The same as rngext(), except, where it can, it includes header files too!
        This is based on the asmFiles found in env['asmFiles']
        when a header file is included, used symbols from the header file are shown commented out after it
        
- `rngInc(start_ea, end_ea)` Reports back the exposed (or public) symbols of the range
        The symbols are .global forwarded, and represent the symbols defined within the range
        
- `romIncs()` creates the .incs and .incbin as per the gamefiles defined.
        This defines how all of the files are included together to make the final rom image. That is only true
        if the range in gameFiles actually cover the entire ROM
        
- `addFile(filename, start_ea, end_ea)` Adds in a file, and recomputes the chunks if it's found within another file.
        
- `formatGameFiles()` Outputs the game files in a good format. This allows for the dynamic modification of game files
        

# srch
This contains search tools for items and conditions found in the database, as well as binary files and
    comparisons
- **next** (occurrence of something tools)
- `getSymTable(elfPath)` This creates temporary files and deletes them immediately after for interacting with arm-none-eabi-readelf
    It displays the symbol table of the elf file, and searches for the specified symbol
    
- `listUpdatedSymbols(elfPath)` Searches through the symtable in the elfPath, and computes a list of name_eas, and their
    new names
    

# next
A collection of tools that find the next occurrance of a specific type of item
- `arm(search_ea, ui=True)` Finds the next ARM item, which has a Segment register value 'T' of 0
        
- `ascii(search_ea, ui=True)` returns the next data item containing ascii characters (seems valid for utf too)
        
- `fakeinst(search_ea, ui=True)` returns the next code item which is registered as a potential fake instruction.
        Those may also be redundant instructions, which get encoded differently outside of IDA
        the found instructions may also be pure data
        
- `name(search_ea, ui=True, hexOut=True)` Finds the next ea with which a name exists
        
- `known(search_ea, ui=True)` Finds the next ea of an item that is not unknown
        
- `bin(search_ea, ui=True)` Finds the next big blob of data. The heuristic is it has to be at least sizeLimitHeuristic in size
        UI jumps to start_ea automatically.
        
- `red(search_ea, ui=True)` Looks for code items outside function items. The first detected is returned
        
- `immref(search_ea, ui=True)` Finds the next occurrance of an immediate value being a reference, like
        ldr r2, [r2,#(dword_809EEF4+0x1F8 - 0x809f0e4)]
        
- `ret(search_ea, ui=True, hexOut=True)` Looks for the next data item that encodes a function return
        - BX LR
        - MOV PC, LR
        - PUSH {..., LR} [Up to instLimit gap insts] POP {..., LR} (regLists must be matching)
        - POP {R<X>} [Up to instLimit gap insts] BX R<X>
        
- `unkret(search_ea, ui=True, hexOut=True)` Thhs finds the next return based on the next.ret function, that is not already defined within a function.
        This counts red code, unknown bytes, and returns hidden within data.
        
- `deadfunc(ea, ui=True, hexOut=True)` This finds the next occurrance of a dead function not recognized as a function (ie, red code or data)
        This can only find functions ranges it can guarantee, ie, only PUSH {..., LR} POP {..., PC} patterns.
        
- `fakered(ea, ui=True, hexOut=True)` This finds the next occurrance of a not a red code segment that has no return pattern to it, making it unlikely
        to belong to a function.
        
- `unkptr(self, ea, end_ea=0x8800000, ui=True, hexOut=True)` 

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
    
- `changeASCII (start_ea, end_ea)` finds all ascii named data and changes it to bytes and removes its name
- `removeText (start_ea, end_ea)` removes all ASCII text that is in text "..." format
    
- `removeStackVarUsages (start_ea, end_ea)` 
- `makeUnkPushFuncs (start_ea, end_ea)` Finds and fixes all dead functions not declared as functions following the pattern PUSH {..., LR} POP {..., PC}
    This also only makes functions until the first occurrance of a POP {..., PC}. However, this results in a
    function range error, and that can be fixed as well.
    
- `fixFunctionRanges (start_ea, end_ea)` Fixes all functions with improper returns, by finding their returns and changing their ranges
    For each function, it will ensure that it ends properly until the start of another function, or a data element
    with data xrefs to it. If it ends improperly, or there exists a matching return that is
    not part of the function, it's made part of the function
    This may not behave correctly around dead functions or null_subs. Run tools to Detect and fix those first.
    
- `removeFakeRedCode (start_ea, end_ea)` Removes instances of code recognized by IDA to be code, but are unlikely not to be by making them bytes.
    
- `removeRedCode (start_ea, end_ea)` unconditionally removes all red code within a specified region
    

# misc
Different kinds of commands and tools go here. No label. Just take a look, OK?
- **ops** (Operations to perform to IDB)
- **memar** (MemAccessScanner protocol reader)
- `gendocs(terminalModule)` Actually generates the docs for this file!
        
- `ea2gf(ea)` Return the game file the ea belongs to
    
- `sizeTillName(ea, blockSize=1)` 
- `getLZ77CompressedSize(compressed_ea)` Iterates the compressed data, and returns its size
    
- `findMostUsedFunctions(count, notModified=False, disp=True)` Returns the functions with the highest count of xrefsTo. if notModified, only those that are in the format
    *_xxxxxxx are returned. if disp, the output is formatted and printed as well
    
- `fnrepl(start_ea, end_ea, oldstr, newstr)` replace a string once if detected in the names of all functions within range
    
- `plcv(ea)` Converts pool to linker compatible version

    
- `nlrepl(oldStr, newStr)` Replaces string from all names in the global name list
    
- `rngmkd(start_ea, end_ea)` Turns the data in the range to words. If not aligned with words, turns into bytes instead
    

# ops
This contains search tools for items and conditions found in the database, as well as binary files and
        comparisons
- `registerUncompFile(ea)` 

# memar

- `read(accesses_path)` Reads in the memory accesses defined by the MemAccessScanner protocol
        
- `formatAccessSources()` 