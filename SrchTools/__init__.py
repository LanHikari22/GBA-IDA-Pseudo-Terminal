import idaapi

def require_package():
    idaapi.require('SrchTools.BinarySearcher')
    idaapi.require('SrchTools.nextTools')
    idaapi.require('SrchTools.srchTools')
    idaapi.require('SrchTools.Terminal')