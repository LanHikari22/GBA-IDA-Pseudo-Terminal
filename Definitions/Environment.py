# This file defines  environmental variables used throughout the project.
# To modify environmental variables, run pt.env(). Maintain a local file with pt.env() calls to set the
# environment correctly. (or modify this file, if you want...)

try:
    # hacky header-like behavior. This is because the environment is rewritten by
    # external scripts, but modules rely on it existing upon initiation, so they import this.
    # So the external script should define env, otherwise the default is this.
    env
except NameError:
    env = dict()

    ## ROM Paths
    env['ROMPath'] = ''
    env['elfPath'] = ''

    ## search utils
    env['compareBinPath'] = ''

    ## decomp path
    env['decompPath'] = ''

    ## disassembly utils
    env['dismProjPath'] = ''
    # the path to put header *.inc files for the disassembly
    env['incPath'] = ''
    # aliases for file extensions of files to be binary extracted, not disassembled
    env['binAliases'] = None
    # dictionary of filename and tuple of addresses: (Ex: {"start.s":(0x8000000, 0x80002CC)}
    # The file extension determines the type disassembled.
    # file.s    | Code is disassembled
    # file.bin  | The binary content is extracted. Applies to all extentions in binAliases.
    env['gameFiles'] = None

    # FIXME: I modified this after initiating pt and Hotkeys, and it wouldn't recognize the change. Had to restart IDA.