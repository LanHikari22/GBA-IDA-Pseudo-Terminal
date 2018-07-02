# This encapsulates one Test. A test can in fact have multiple tests within it!
# Tests can be added and this will handle formatting and running the tests

class FailedTestException(Exception):
    def __init__(self, s):
        super(Exception, self).__init__(s)

class Test:
    def __init__(self, testName, testFunc=None, *fArgs):
        # type: (str, function, list(Test)) -> None
        """
        Creates a test with a name, some test func to run, and arguments to the function
        A test can have its own test code, or be a container for multiple tests to run.
        Nested tests can be added using the add() method.
        :param testName: name of the test to be run
        :param testFunc: This must and is expected to return bool, whether the tests succeeds.
        :param *fArgs: nested tests to run as well.
        """
        self.testName = testName
        self.testFunc = testFunc
        if fArgs: self.fArgs = fArgs
        else: self.fArgs = None
        self.tests = []

    def run(self, tabLevel=0):
        # type: (int) -> (bool, str)
        """
        The tests within the Test run first, and then if there's a test function associated with this object, it runs.
        The test is normally returned as a string, but if it's a tab level of 0, it's printed too!
        :raise TypeError: if tabLevel < 0
        :return: the collective status of all run tests
        """
        if tabLevel < 0: raise(TypeError("Tab level must be unsigned"))
        status = True
        errorMsg = ''
        log = tabLevel*'  ' + "Testing %s... " % (self.testName)
        testsLog = ''
        for test in self.tests:
            testStatus, testLog = test.run(tabLevel + 1)
            status = status and testStatus
            testsLog += testLog

        if self.testFunc:
            try:
                if self.fArgs:
                    self.testFunc(*self.fArgs)
                else:
                    self.testFunc()
            except FailedTestException as e:
                status = False
                errorMsg = " (" + e.message + ")"
        log += "OK!\n" if status else "FAILED!%s\n" % errorMsg
        log += testsLog

        # if this function is run with tab of 0, print
        if tabLevel == 0:
            print(log)
        return status, log

    def add(self, test):
        # type: (Test) -> None
        """
        Adds a test to the list of tests.
        :param test: A test object to add.
        :return: None
        """
        self.tests.append(test)


def assertTrue(a, errorMsg):
    # type: (bool) -> None
    if not a:
        raise(FailedTestException(errorMsg))


def assertFalse(a, errorMsg):
    # type: (bool) -> None
    if a:
        raise(FailedTestException(errorMsg))


def assertEquals(a, b, errorMsg):
    if a != b:
        raise(FailedTestException(errorMsg))

def fail(errorMsg):
    # type: (str) -> None
    raise(FailedTestException(errorMsg))