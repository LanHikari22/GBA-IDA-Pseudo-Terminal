import idaapi

def require_package():
    idaapi.require('DisasmTools')
    idaapi.require('DisasmTools.AsmConstParser')
    idaapi.require('DisasmTools.AsmStructParser')
    idaapi.require('DisasmTools.GNUDisassembler')
    idaapi.require('DisasmTools.Terminal')