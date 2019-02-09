import os
import sys
os.chdir('..')
if os.getcwd() not in sys.path: sys.path.append(os.getcwd())

import idaapi

def require_package():
    idaapi.require('Definitions')
    idaapi.require('Definitions.Architecture')
    idaapi.require('Definitions.Environment')
    idaapi.require('Definitions.Paths')