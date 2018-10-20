import idaapi
import idc
import time

import IDAItems

idaapi.require('IDAItems.Data')

from IDAItems import Data

def new():
    output = IDAItems.Data.Data(idc.here()).getDisasm()
    # output = IDAItems.Data.Data(here())._getPoolDisasm()
    return output


def old():
    try:
        output = IDAItems.Data.Data(idc.here())._OLDgetPoolDisasm()
    except Exception as e:
        output = "Exception: %s" % str(e)
    return output


def time_us(func, *args, **kwargs):
    stopwatch_us = int(round(time.time() * 1000))
    for i in range(1000):
        output = func(*args, **kwargs)
    stopwatch_us = int(round(time.time() * 1000)) - stopwatch_us
    return stopwatch_us


def runTimeTest(n, name, func, *args, **kwargs):
    t = 0
    for i in range(n):
        t += time_us(func, *args, **kwargs)
    t /= n
    print("%s: %d us" % (name, t))


def runTimeTests(n=10):
    """
    Performs time profiling tests for optimization purposes
    :param n: number of times to sample the time. Result is the average of all samples
    """
    x = lambda: Data.Data(idc.here())._lowerCode(idc.GetDisasm(idc.here()))
    y = lambda: Data.Data(idc.here())._lowerCodeOLD(idc.GetDisasm(idc.here()))
    print(x())
    runTimeTest(n, 'new _lowerCode', x)
    print(y())
    runTimeTest(n, 'old _lowerCode', y)