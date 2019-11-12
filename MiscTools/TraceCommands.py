def getJumpTablesFromFunc(func_ea):
    """
    Runs through the function, and identifies all xrefsFrom that are jumptables
    :param func_ea: address of the function
    :return: a list of all jumptables referenced by this function
    """

def processJumpTable(jt_ea):
    """
    Gets all xrefs from a jump table
    :param jt_ea:
    :return:
    """

def recursiveTraceJumptablese(ea, function=False):
    """
    This takes a jumptable of functions, and traces all jumptables present in the functions recursively
    It then returns a list of lists of ... of symbols representing the entire tree of symbols
    :param jt_ea: effective address of the jumptable if not Function
                    if Function, then the jump table is first procesed.
    :return: tree list of all symbols in all jumptables
    """
