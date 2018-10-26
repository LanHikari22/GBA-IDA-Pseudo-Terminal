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
    """
    Times a function in the microseconds by executing it a thousand times.
    This is because time.time() is only accurate to the millisecond.
    :param func: the function to run
    :param args: any arguments to the function
    :param kwargs: any keyworded arguments to the function
    :return: a tuple of execution time in us and the output of the function
    """
    stopwatch_us = int(round(time.time() * 1000))
    for i in range(1000):
        func(*args, **kwargs)
    stopwatch_us = int(round(time.time() * 1000)) - stopwatch_us
    return (stopwatch_us, func(*args, **kwargs))

def avgTime_us(numSamples, func, *args, **kwargs):
    """
    Runs time_us numSamples times, and averages the results
    :param numSamples: the number of times to run the tests and get an average
    :param func: the function to run
    :param args: any arguments to the function
    :param kwargs: any keyworded arguments to the function
    :return: a tuple of the average time for execution in us and the output of the function
    """
    t = 0
    for i in range(numSamples):
        t += time_us(func, *args, **kwargs)[0]
    t /= numSamples
    return (t, func(*args, **kwargs))

def runTimeTest(n, name, func, *args, **kwargs):
    print("%s: %d us" % (name, avgTime_us(n, func, *args, **kwargs)[0]))


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