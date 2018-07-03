import idaapi
idaapi.require("miscUtils")
idaapi.require("disasmUtils")
idaapi.require("TerminalModule")
import miscUtils
import disasmUtils
import TerminalModule


class PseudoTerminal(TerminalModule.TerminalModule, object):
    def __init__(self):
        # the module itelf also has a summary format, this is created by TerminalModule
        super(type(self),self).__init__("[+] pt (top module)")

        # eaach commznd in the module is added to the module help, and its __doc__ is
        # given the member alias help instead
        self.echo = miscUtils.pt_echo
        self.echo.help = self.echo.__doc__
        self.echo.fmt = "<msg>"
        self.help += self._get_format("echo", self.echo) + '\n'

        self.clear = miscUtils.pt_clear
        self.clear.help = self.clear.__doc__
        self.clear.fmt = ""
        self.help += self._get_format("clear", self.clear) + '\n'

        self.plcv = miscUtils.pt_plcv
        self.plcv.help = self.plcv.__doc__
        self.plcv.fmt = "<ea>"
        self.help += self._get_format("plcv", self.plcv) + '\n'

        # __init__ of modules should set up things similarly to pt
        self.dis = disasmUtils.dis()
        self.help += self.dis.fmt + '\n'


if __name__ == '__main__':
    pt = PseudoTerminal()
    pt.echo("beep beep!")