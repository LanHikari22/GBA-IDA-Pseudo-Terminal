import os
import sys
if os.getcwd() not in sys.path: sys.path.append(os.getcwd())

import idaapi
import Definitions, DisasmTools, FixTools, IDAItems, MiscTools, SrchTools

def require_project():
    Definitions.require_package()
    DisasmTools.require_package()
    FixTools.require_package()
    IDAItems.require_package()
    MiscTools.require_package()
    SrchTools.require_package()