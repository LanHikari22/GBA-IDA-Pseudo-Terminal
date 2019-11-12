import idaapi

def require_package():
    idaapi.require('Definitions')
    idaapi.require('Definitions.Architecture')
    idaapi.require('Definitions.Environment')
    idaapi.require('Definitions.Paths')