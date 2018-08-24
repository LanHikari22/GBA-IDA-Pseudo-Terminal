# This file defines  environmental variables used throughout the project.
# To modify environmental variables, run pt.env(). Maintain a local file with pt.env() calls to set the
# environment correctly. (or modify this file, if you want...)

env = dict()

## ROM Paths
env['ROMPath'] = ''

## search utils
env['compareBinPath'] = ''

## disassembly utils
env['dismProjPath'] = ''
# the path to put header *.inc files for the disassembly
env['incPath'] = ''

# dictionary of filename and tuple of addresses: (Ex: {"start.s":(0x8000000, 0x80002CC)}
# The file extension determines the type disassembled.
# file.s    | Code is disassembled
# file.bin  | The binary content is extracted
env['gameFiles'] = None
# TODO: Not supported yet
# this includes the specific gameFiles to be updated. Set this to an empty dictionary, and all gameFiles are updated.
# When working no specific files, set them here, and only those files and their dependencies are updated.
# This can speed up disassembly operations
# env['gameFilesUpdate'] = None
