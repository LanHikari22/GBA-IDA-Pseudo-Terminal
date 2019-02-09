import idaapi

def require_package():
    idaapi.require('MiscTools.FuncAnalyzer')
    idaapi.require('MiscTools.MemAccessReader')
    idaapi.require('MiscTools.miscTools')
    idaapi.require('MiscTools.Operations')
    idaapi.require('MiscTools.Terminal')
    idaapi.require('MiscTools.TimeProfiler')
    idaapi.require('MiscTools.TraceCommands')