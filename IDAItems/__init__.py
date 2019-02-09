import os
import sys
os.chdir('..')
if os.getcwd() not in sys.path: sys.path.append(os.getcwd())

import idaapi

def require_package():
    idaapi.require('IDAItems')
    idaapi.require('IDAItems.Data')
    idaapi.require('IDAItems.Function')
    idaapi.require('IDAItems.GameFile')
    idaapi.require('IDAItems.InstDecoder')
    idaapi.require('IDAItems.Instruction')
    idaapi.require('IDAItems.Module')

    idaapi.require('IDAItems.Tests.Test')