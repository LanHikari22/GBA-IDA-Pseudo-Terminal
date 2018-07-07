# GBA-IDA-Pseudo-Terminal
This is a collection of tools that uses the IDAPython API to execute commands for IDB analysis, data exportion, or database manipulation

# Usage
- Run pt.py as a script in python, if successful, the echo command should run with a message in the output window.
- To view the list of commands (and modules containing commands), simpy print `pt` in the output window.
- To execute a command, run it as a function: `pt.echo("beep beep!")`. You can also view its docs: `pt.help(pt.echo)`.
- There are modules inside pt that are clearly distinguished from command when running `pt`.
- To access them, simply refer to them from pt: `pt.dis.rng(0x8000000, 0x80000200)`. 
- The module can also display its list of commands and modules when printed: `pt.dis`.
- The pseudoterminal has an environment to host paths and needed variables.
- Every module and command should have docs and one-line summaries: `pt.help(pt.dis.rng)', `pt.fmt(pt.dis)`
- Run `pt.clrenv()` then a series of `pt.env(key=val)` commands to fill them. (Not all utilities need environmental variables)
- The necessary environmental variables to fill can be found in `Definition/Environment.py`

To view the documentation for commands, see [COMMANDS.md](COMMANDS.md).
