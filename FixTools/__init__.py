import idaapi

def require_package():
    idaapi.require('FixTools')
    idaapi.require('FixTools.fixTools')
    idaapi.require('FixTools.Terminal')