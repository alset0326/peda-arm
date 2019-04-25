#
#       PEDA - Python Exploit Development Assistance for GDB
#
#       Copyright (C) 2012 Long Le Dinh <longld at vnsecurity.net>
#
#       License: see LICENSE file for details
#

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import shlex
import time
import fcntl
import termios
import traceback
import gdb  # for ide

from .six.moves import range
from .six.moves import cPickle as pickle
from .six.moves import input

from .utils import *
from . import config

__all__ = ['PEDA', 'PEDACmd', 'PEDACmdAlias', 'PluginCommand', 'Alias', 'pedaGDBCommand', 'AsmBase']


class AsmBase:
    def objdump_disasm_search(self, name, search):
        """for xref used"""
        raise NotImplemented()


###########################################################################
class PEDA(object):
    """
    Class for actual functions of PEDA commands
    """

    def __init__(self, registers, asm):
        self.SAVED_COMMANDS = {}  # saved GDB user's commands
        self.registers = registers  # for parse and eval used
        self.asm = asm  # for xref used

    ####################################
    #   GDB Interaction / Misc Utils   #
    ####################################
    @staticmethod
    def execute(gdb_command):
        """
        Wrapper for gdb.execute, catch the exception so it will not stop python script

        Args:
            - gdb_command (String)

        Returns:
            - True if execution succeed (Bool)
        """
        try:
            gdb.execute(gdb_command)
            return True
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
            return False

    @staticmethod
    def execute_redirect(gdb_command):
        """
        Execute a gdb command and capture its output

        Args:
            - gdb_command (String)

        Returns:
            - output of command (String)
        """
        result = None
        try:
            result = gdb.execute(gdb_command, to_string=True)
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
        if config.Option.get("verbose") == "on":
            msg(result)
        return result

    def parse_and_eval(self, exp):
        """
        Work around implementation for gdb.parse_and_eval with enhancements

        Args:
            - exp: expression to evaluate (String)

        Returns:
            - value of expression
        """

        regs = sum(self.registers.values(), [])
        for r in regs:
            if "$" + r not in exp and "e" + r not in exp and "r" + r not in exp:
                exp = exp.replace(r, "$%s" % r)

        p = re.compile("(.*)\[(.*)\]")  # DWORD PTR [esi+eax*1]
        matches = p.search(exp)
        if not matches:
            p = re.compile("(.*).s:(0x.*)")  # DWORD PTR ds:0xdeadbeef
            matches = p.search(exp)

        if matches:
            mod = "w"
            if "BYTE" in matches.group(1):
                mod = "b"
            elif "QWORD" in matches.group(1):
                mod = "g"
            elif "DWORD" in matches.group(1):
                mod = "w"
            elif "WORD" in matches.group(1):
                mod = "h"

            out = PEDA.execute_redirect("x/%sx %s" % (mod, matches.group(2)))
            if not out:
                return None
            else:
                return out.split(":\t")[-1].strip()

        else:
            out = PEDA.execute_redirect("print %s" % exp)
        if not out:
            return None
        else:
            out = gdb.history(0).__str__()
            out = out.encode('ascii', 'ignore')
            out = decode_string_escape(out)
            return out.strip()

    def string_to_argv(self, str):
        """
        Convert a string to argv list, pre-processing register and variable values

        Args:
            - str: input string (String)

        Returns:
            - argv list (List)
        """
        try:
            str = str.encode('ascii', 'ignore')
        except:
            pass
        str = decode_string_escape(str)
        args = shlex.split(str)
        # need more processing here
        for idx, a in enumerate(args):
            a = a.strip(",")
            if a.startswith("$"):  # try to get register/variable value
                v = self.parse_and_eval(a)
                if v is not None and v != "void":
                    if v.startswith("0x"):  # int
                        args[idx] = v.split()[0]  # workaround for 0xdeadbeef <symbol+x>
                    else:  # string, complex data
                        args[idx] = v
            elif a.startswith("+"):  # relative value to prev arg
                adder = to_int(self.parse_and_eval(a[1:]))
                if adder is not None:
                    args[idx] = "%s" % to_hex(to_int(args[idx - 1]) + adder)
            elif is_math_exp(a):
                try:
                    v = eval("%s" % a)
                    # XXX hack to avoid builtin functions/types
                    if not isinstance(v, six.string_types + six.integer_types):
                        continue
                    args[idx] = "%s" % (to_hex(v) if to_int(v) != None else v)
                except:
                    pass
        if config.Option.get("verbose") == "on":
            msg(args)
        return args

    ################################
    #   GDB User-Defined Helpers   #
    ################################
    def save_user_command(self, cmd):
        """
        Save user-defined command and deactivate it

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to save (Bool)
        """
        commands = PEDA.execute_redirect("show user %s" % cmd)
        if not commands:
            return False

        commands = "\n".join(commands.splitlines()[1:])
        commands = "define %s\n" % cmd + commands + "end\n"
        self.SAVED_COMMANDS[cmd] = commands
        tmp = tmpfile()
        tmp.write("define %s\nend\n" % cmd)
        tmp.flush()
        result = PEDA.execute("source %s" % tmp.name)
        tmp.close()
        return result

    @staticmethod
    def define_user_command(cmd, code):
        """
        Define a user-defined command, overwrite the old content

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to define (Bool)
        """
        commands = "define %s\n" % cmd + code + "\nend\n"
        tmp = tmpfile(is_binary_file=False)
        tmp.write(commands)
        tmp.flush()
        result = PEDA.execute("source %s" % tmp.name)
        tmp.close()
        return result

    @staticmethod
    def append_user_command(cmd, code):
        """
        Append code to a user-defined command, define new command if not exist

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to append (Bool)
        """

        commands = PEDA.execute_redirect("show user %s" % cmd)
        if not commands:
            return PEDA.define_user_command(cmd, code)
        # else
        commands = "\n".join(commands.splitlines()[1:])
        if code in commands:
            return True

        commands = "define %s\n" % cmd + commands + code + "\nend\n"
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = PEDA.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def restore_user_command(self, cmd):
        """
        Restore saved user-defined command

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to restore (Bool)
        """
        if cmd == "all":
            commands = "\n".join(self.SAVED_COMMANDS.values())
            self.SAVED_COMMANDS = {}
        else:
            if cmd not in self.SAVED_COMMANDS:
                return False
            else:
                commands = self.SAVED_COMMANDS[cmd]
                self.SAVED_COMMANDS.pop(cmd)
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = PEDA.execute("source %s" % tmp.name)
        tmp.close()

        return result

    @staticmethod
    def run_gdbscript_code(code):
        """
        Run basic gdbscript code as it is typed in interactively

        Args:
            - code: gdbscript code, lines are splitted by "\n" or ";" (String)

        Returns:
            - True if success to run (Bool)
        """
        tmp = tmpfile()
        tmp.write(code.replace(";", "\n"))
        tmp.flush()
        result = PEDA.execute("source %s" % tmp.name)
        tmp.close()
        return result

    #########################
    #   Debugging Helpers   #
    #########################
    @memoized
    def is_target_remote(self):
        """
        Check if current target is remote

        Returns:
            - True if target is remote (Bool)
        """
        out = PEDA.execute_redirect("info program")
        if out and "serial line" in out:  # remote target
            return True
        return False

    @memoized
    def getfile(self):
        """
        Get exec file of debugged program

        Returns:
            - full path to executable file (String)
        """
        result = None
        out = PEDA.execute_redirect('info files')
        if out and '"' in out:
            if self.is_target_remote():
                p = re.compile(".*exec file:\s*`target:(.*)'")
            else:
                p = re.compile(".*exec file:\s*`(.*)'")
            m = p.search(out)
            if m:
                result = m.group(1)
            else:  # stripped file, get symbol file
                p = re.compile("Symbols from \"([^\"]*)")
                m = p.search(out)
                if m:
                    result = m.group(1)

        return result

    @staticmethod
    def get_status():
        """
        Get execution status of debugged program

        Returns:
            - current status of program (String)
                STOPPED - not being run
                BREAKPOINT - breakpoint hit
                SIGXXX - stopped by signal XXX
                UNKNOWN - unknown, not implemented
        """
        status = "UNKNOWN"
        out = PEDA.execute_redirect("info program")
        for line in out.splitlines():
            if line.startswith("It stopped"):
                if "signal" in line:  # stopped by signal
                    status = line.split("signal")[1].split(",")[0].strip()
                    break
                if "breakpoint" in line:  # breakpoint hit
                    status = "BREAKPOINT"
                    break
            if "not being run" in line:
                status = "STOPPED"
                break
        return status

    @memoized
    def getpid(self):
        """
        Get PID of the debugged process

        Returns:
            - pid (Int)
        """
        return gdb.selected_inferior().pid

    def getos(self):
        """
        Get running OS info

        Returns:
            - os version (String)
        """
        vpath = "/proc/version"
        if self.is_target_remote():  # remote target
            out = self.read_from_remote(vpath)
        else:  # local target
            out = open(vpath).read()

        return out.split(' ')[0]

    @memoized
    def getarch(self):
        """
        Get architecture of debugged program

        Returns:
            - tuple of architecture info (arch (String), bits (Int))
        """
        arch = gdb.selected_frame().architecture().name()
        bits = 32
        if "64" in arch:
            bits = 64
        return arch, bits

    @memoized
    def getbits(self):
        return self.getarch()[1]

    def intsize(self):
        """
        Get dword size of debugged program

        Returns:
            - size (Int)
                + intsize = 4/8 for 32/64-bits arch
        """

        (arch, bits) = self.getarch()
        return bits // 8

    @staticmethod
    def getregs(reglist=None):
        """
        Get value of some or all registers

        Returns:
            - dictionary of {regname(String) : value(Int)}
        """
        if reglist:
            reglist = reglist.replace(",", " ")
        else:
            reglist = ""
        regs = PEDA.execute_redirect("info registers %s" % reglist)
        if not regs:
            return None

        result = {}
        if regs:
            for r in regs.splitlines():
                r = r.split()
                if len(r) > 1 and to_int(r[1]) is not None:
                    result[r[0]] = to_int(r[1])

        return result

    @staticmethod
    def getreg(register):
        """
        Get value of a specific register

        Args:
            - register: register name (String)

        Returns:
            - register value (Int)
        """
        r = register.lower()
        regs = PEDA.execute_redirect("info registers %s" % r)
        if regs:
            regs = regs.splitlines()
            if len(regs) > 1:
                return None
            else:
                result = to_int(regs[0].split()[1])
                return result

        return None

    @staticmethod
    def getpc():
        """
        Get value of pc

        Returns: pc (int)

        """
        try:
            return gdb.selected_frame().pc()
        except:
            return PEDA.getreg('pc')

    @staticmethod
    def set_breakpoint(location, temp=None, hard=None):
        """
        Wrapper for GDB break command
            - location: target function or address (String ot Int)

        Returns:
            - True if can set breakpoint
        """
        cmd = "break"
        if hard:
            cmd = "h" + cmd
        if temp:
            cmd = "t" + cmd

        if to_int(location) is not None:
            return PEDA.execute("%s *0x%x" % (cmd, to_int(location)))
        else:
            return PEDA.execute("%s %s" % (cmd, location))

    @staticmethod
    def set_breakpoint_redirect(location, temp=False, hard=False):
        """
        Wrapper for GDB break command
            - location: target function or address (String ot Int)

        Returns:
            - True if can set breakpoint
        """
        cmd = "break"
        if hard:
            cmd = "h" + cmd
        if temp:
            cmd = "t" + cmd

        if to_int(location) is not None:
            return PEDA.execute_redirect("%s *0x%x" % (cmd, to_int(location)))
        else:
            return PEDA.execute_redirect("%s %s" % (cmd, location))

    @staticmethod
    def get_breakpoint(num):
        """
        Get info of a specific breakpoint
        TODO: support catchpoint, watchpoint

        Args:
            - num: breakpoint number

        Returns:
            - tuple (Num(Int), Type(String), Disp(Bool), Enb(Bool), Address(Int), What(String), commands(String))
        """
        out = PEDA.execute_redirect("info breakpoints %d" % num)
        if not out or "No breakpoint" in out:
            return None

        lines = out.splitlines()[1:]
        # breakpoint regex
        # 1       breakpoint     keep y   0xb6cb6342 <__libc_init+22>\n
        p = re.compile("^(\d+) +(.*breakpoint) +(keep|del) +([yn]) +(0x[^ ]*) +(.*)")
        m = p.match(lines[0])
        if not m:
            # catchpoint/watchpoint regex
            p = re.compile("^(\d*) +(.*point) +(keep|del) +([yn]) +(.*)")
            m = p.match(lines[0])
            if not m:
                return None
            else:
                (num, type, disp, enb, what) = m.groups()
                addr = ''
        else:
            (num, type, disp, enb, addr, what) = m.groups()

        disp = True if disp == "keep" else False
        enb = True if enb == "y" else False
        addr = to_int(addr)
        m = re.match("in.*at(.*:\d*)", what)
        if m:
            what = m.group(1)
        else:
            if addr:  # breakpoint
                what = ""

        commands = ""
        if len(lines) > 1:
            for line in lines[1:]:
                if "already hit" in line: continue
                commands += line + "\n"

        return num, type, disp, enb, addr, what, commands.rstrip()

    @staticmethod
    def get_breakpoints():
        """
        Get list of current breakpoints

        Returns:
            - list of tuple (Num(Int), Type(String), Disp(Bool), Nnb(Bool), Address(Int), commands(String))
        """
        result = []
        out = PEDA.execute_redirect("info breakpoints")
        if not out:
            return []

        bplist = []
        for line in out.splitlines():
            m = re.match("^(\d*).*", line)
            if m and to_int(m.group(1)):
                bplist += [to_int(m.group(1))]

        for num in bplist:
            r = PEDA.get_breakpoint(num)
            if r:
                result += [r]
        return result

    @staticmethod
    def save_breakpoints(filename):
        """
        Save current breakpoints to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        # use built-in command for gdb 7.2+
        result = PEDA.execute_redirect("save breakpoints %s" % filename)
        if result == '':
            return True

        bplist = PEDA.get_breakpoints()
        if not bplist:
            return False

        try:
            fd = open(filename, "w")
            for (num, type, disp, enb, addr, what, commands) in bplist:
                m = re.match("(.*)point", type)
                if m:
                    cmd = m.group(1).split()[-1]
                else:
                    cmd = "break"
                if "hw" in type and cmd == "break":
                    cmd = "h" + cmd
                if "read" in type:
                    cmd = "r" + cmd
                if "acc" in type:
                    cmd = "a" + cmd

                if not disp:
                    cmd = "t" + cmd
                if what:
                    location = what
                else:
                    location = "*0x%x" % addr
                text = "%s %s" % (cmd, location)
                if commands:
                    if "stop only" not in commands:
                        text += "\ncommands\n%s\nend" % commands
                    else:
                        text += commands.split("stop only", 1)[1]
                fd.write(text + "\n")
            fd.close()
            return True
        except:
            return False

    def get_config_filename(self, name):
        filename = self.getfile()
        if not filename:
            filename = self.getpid()
            if not filename:
                filename = 'unknown'

        filename = os.path.basename("%s" % filename)
        tmpl_name = config.Option.get(name)
        if tmpl_name:
            return tmpl_name.replace("#FILENAME#", filename)
        else:
            return "peda-%s-%s" % (name, filename)

    def save_session(self, filename=None):
        """
        Save current working gdb session to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        session = ""
        if not filename:
            filename = self.get_config_filename("session")

        # exec-wrapper
        out = PEDA.execute_redirect("show exec-wrapper")
        if out is not None:
            wrapper = out.split('"')[1]
            if wrapper:
                session += "set exec-wrapper %s\n" % wrapper

        try:
            # save breakpoints
            self.save_breakpoints(filename)
            fd = open(filename, "a+")
            fd.write("\n" + session)
            fd.close()
            return True
        except:
            return False

    def restore_session(self, filename=None):
        """
        Restore previous saved working gdb session from file

        Args:
            - filename: source file (String)

        Returns:
            - True if success to restore (Bool)
        """
        if not filename:
            filename = self.get_config_filename("session")

        # temporarily save and clear breakpoints
        tmp = tmpfile()
        self.save_breakpoints(tmp.name)
        PEDA.execute("delete")
        result = PEDA.execute("source %s" % filename)
        if not result:
            PEDA.execute("source %s" % tmp.name)
        tmp.close()
        return result

    @staticmethod
    def disassemble(*arg):
        """
        Wrapper for disassemble command
            - arg: args for disassemble command

        Returns:
            - text code (String)
        """
        code = ""
        modif = ""
        arg = list(arg)
        if len(arg) > 1:
            if "/" in arg[0]:
                modif = arg[0]
                arg = arg[1:]
        if len(arg) == 1 and to_int(arg[0]) != None:
            arg += [to_hex(to_int(arg[0]) + 32)]

        out = PEDA.execute_redirect("disassemble %s %s" % (modif, ",".join(arg)))
        if not out:
            return None
        else:
            code = out

        return code

    @memoized
    def prev_inst(self, address, count=1):
        """
        Get previous instructions at an address

        Args:
            - address: address to get previous instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - list of tuple (address(Int), code(String))
        """
        disassemble = gdb.selected_frame().architecture().disassemble
        result = []
        backward = 4 + 4 * count
        if self.getpid() and not self.is_address(address - backward):
            return None
        codes = disassemble(address - backward, address)
        if codes[-1].get('addr') != address or len(codes) <= count:
            return None
        for code in codes[-count - 1:-1]:
            result.append((code.get('addr'), code.get('asm')))
        return result

    @memoized
    def current_inst(self, address):
        """
        Parse instruction at an address

        Args:
            - address: address to get next instruction (Int)

        Returns:
            - tuple of (address(Int), code(String))
        """
        out = PEDA.execute_redirect("x/i 0x%x" % address)
        if not out:
            return None

        (addr, code) = out.split(":", 1)
        addr = re.search("(0x[^ ]*)", addr).group(1)
        addr = to_int(addr)
        code = code.strip()

        return (addr, code)

    @memoized
    def next_inst(self, address, count=1):
        """
        Get next instructions at an address

        Args:
            - address: address to get next instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - - list of tuple (address(Int), code(String))
        """
        result = []
        code = PEDA.execute_redirect("x/%di 0x%x" % (count + 1, address))
        if not code:
            return None

        lines = code.strip().splitlines()
        for i in range(1, count + 1):
            (addr, code) = lines[i].split(":", 1)
            addr = re.search("(0x[^ ]*)", addr).group(1)
            result += [(to_int(addr), code)]
        return result

    @memoized
    def disassemble_around(self, address, count=8):
        """
        Disassemble instructions nearby current PC or an address

        Args:
            - address: start address to disassemble around (Int)
            - count: number of instructions to disassemble

        Returns:
            - text code (String)
        """
        count = min(count, 256)
        pc = address
        if pc is None:
            return None

        # check if address is reachable
        if not PEDA.execute_redirect("x/x 0x%x" % pc):
            return None

        prev_code = self.prev_inst(pc, count // 2 - 1)
        if prev_code:
            start = prev_code[0][0]
        else:
            start = pc
        if start == pc:
            count //= 2

        code = PEDA.execute_redirect("x/%di 0x%x" % (count, start))
        if "0x%x" % pc not in code:
            code = PEDA.execute_redirect("x/%di 0x%x" % (count // 2, pc))

        return code.rstrip()

    @memoized
    def xrefs(self, search="", filename=None):
        """
        Search for all call references or data access to a function/variable

        Args:
            - search: function or variable to search for (String)
            - filename: binary/library to search (String)

        Returns:
            - list of tuple (address(Int), asm instruction(String))
        """
        result = []
        if not filename:
            filename = self.getfile()

        if not filename:
            return None
        vmap = self.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0

        if to_int(search) is not None:
            search = "%x" % to_int(search)

        search_data = 1
        if search == "":
            search_data = 0
        # tode
        tmpfd = None
        if self.is_target_remote():
            tmpfd = tmpfile(is_binary_file=True)
            PEDA.execute('remote get %s %s' % (filename, tmpfd.name))
            if not os.path.exists(tmpfd.name):
                tmpfd.write('something')
                tmpfd.close()
                return result
            name = tmpfd.name
        else:
            name = filename

        out = self.asm.objdump_disasm_search(name, search)
        if self.is_target_remote():
            tmpfd.close()

        for line in out.splitlines():
            if not line:
                continue
            addr = to_int("0x" + line.split()[0].strip())
            if not addr:
                continue

            # update with runtime values
            if addr < elfbase:
                addr += elfbase
            out = PEDA.execute_redirect("x/i 0x%x" % addr)
            if out:
                line = out
                p = re.compile("\s*(0x[^ ]*).*?:\s*([^ ]*)\s*(.*)")
            else:
                p = re.compile("(.*?)\s*<.*?>\s*([^ ]*)\s*(.*)")

            m = p.search(line)
            if m:
                (address, opcode, opers) = m.groups()
                if "b" in opcode and search in opers:
                    result += [(addr, line.strip())]
                if search_data:
                    if "mov" in opcode and search in opers:
                        result += [(addr, line.strip())]

        return result

    @memoized
    def backtrace_depth(self, sp=None):
        """
        Get number of frames in backtrace

        Args:
            - sp: stack pointer address, for caching (Int)

        Returns:
            - depth: number of frames (Int)
        """
        backtrace = PEDA.execute_redirect("backtrace")
        return backtrace.count("#")

    def stepuntil(self, inst, mapname=None, depth=None):
        """
        Step execution until next "inst" instruction within a specific memory range

        Args:
            - inst: the instruction to reach (String)
            - mapname: name of virtual memory region to check for the instruction (String)
            - depth: backtrace depth (Int)

        Returns:
            - tuple of (depth, instruction)
                + depth: current backtrace depth (Int)
                + instruction: current instruction (String)
        """

        if not self.getpid():
            return None

        maxdepth = to_int(config.Option.get("tracedepth"))
        if not maxdepth:
            maxdepth = 0xffffffff

        maps = self.get_vmmap()
        binname = self.getfile()
        if mapname is None:
            mapname = binname
        mapname = mapname.replace(" ", "").split(",") + [binname]
        targetmap = []
        for m in mapname:
            targetmap += self.get_vmmap(m)
        # binmap = self.get_vmmap("binary")

        current_instruction = ""
        pc = self.getpc()

        if depth is None:
            current_depth = self.backtrace_depth(self.getreg("sp"))
        else:
            current_depth = depth
        old_status = self.get_status()

        while True:
            status = self.get_status()
            if status != old_status:
                # todo
                if "SIG" in status and status[3:] not in ["TRAP"] and not to_int(
                        status[3:]):  # ignore TRAP and numbered signals
                    current_instruction = "Interrupted: %s" % status
                    call_depth = current_depth
                    break
                if "STOP" in status:
                    current_instruction = "End of execution"
                    call_depth = current_depth
                    break

            call_depth = self.backtrace_depth(self.getreg("sp"))
            current_instruction = PEDA.execute_redirect("x/i $pc")
            if not current_instruction:
                current_instruction = "End of execution"
                break

            p = re.compile(".*?(0x[^ :]*)")
            addr = p.search(current_instruction).group(1)
            addr = to_int(addr)
            if addr is None:
                break

            # p = re.compile(".*?:\s*([^ ]*)")
            p = re.compile(".*?:\s*(.*)")
            code = p.match(current_instruction).group(1)
            found = 0
            for i in inst.replace(",", " ").split():
                if re.match(i.strip(), code.strip()):
                    if self.is_address(addr, targetmap) and addr != pc:
                        found = 1
                        break
            if found != 0:
                break
            PEDA.execute_redirect("stepi")
            if not self.is_address(addr, targetmap) or call_depth > maxdepth:
                PEDA.execute_redirect("finish")
            pc = 0

        return (call_depth - current_depth, current_instruction.strip())

    def eval_target(self, inst):
        """
        Evaluate target address of an instruction, used for jumpto decision

        Args:
            - inst: ASM instruction text (String)

        Returns:
            - target address (Int)
        """
        # tode
        target = None
        inst = inst.strip()
        p = re.compile(".*:\s*\S*\s*(0x\S*)")
        m = p.search(inst)
        if m:
            target = m.group(1)
        else:
            p = re.compile(".*:\s*\S*\s*(\S*)")
            m = p.search(inst)
            target = self.parse_and_eval("%s" % m.group(1))

        return to_int(target)

    def take_snapshot(self):
        """
        Take a snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - dictionary of snapshot data
        """
        if not self.getpid():
            return None

        maps = self.get_vmmap()
        if not maps:
            return None

        snapshot = {}
        # get registers
        snapshot["reg"] = self.getregs()
        # get writable memory regions
        snapshot["mem"] = {}
        for (start, end, perm, _) in maps:
            if "w" in perm:
                snapshot["mem"][start] = self.dumpmem(start, end)

        return snapshot

    def save_snapshot(self, filename=None):
        """
        Save a snapshot of current process to file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - filename: target file to save snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        snapshot = self.take_snapshot()
        if not snapshot:
            return False
        # dump to file
        fd = open(filename, "wb")
        pickle.dump(snapshot, fd, pickle.HIGHEST_PROTOCOL)
        fd.close()

        return True

    def give_snapshot(self, snapshot):
        """
        Restore a saved snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - Bool
        """
        if not snapshot or not self.getpid():
            return False

        # restore memory regions
        for (addr, buf) in snapshot["mem"].items():
            self.writemem(addr, buf)

        # restore registers, SP will be the last one
        for (r, v) in snapshot["reg"].items():
            PEDA.execute("set $%s = 0x%x" % (r, v))
            if r.endswith("sp"):
                sp = v
        PEDA.execute("set $sp = 0x%x" % sp)

        return True

    def restore_snapshot(self, filename=None):
        """
        Restore a saved snapshot of current process from file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - file: saved snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        fd = open(filename, "rb")
        snapshot = pickle.load(fd)
        return self.give_snapshot(snapshot)

    @staticmethod
    def read_from_remote(path):
        tmp = tmpfile()
        PEDA.execute("remote get %s %s" % (path, tmp.name))
        tmp.seek(0)
        out = tmp.read()
        tmp.close()
        return out

    #########################
    #   Memory Operations   #
    #########################
    @memoized
    def get_vmmap(self, name=None):
        """
        Get virtual memory mapping address ranges of debugged process

        Args:
            - name: name/address of binary/library to get mapping range (String)
                + name = "binary" means debugged program
                + name = "all" means all virtual maps

        Returns:
            - list of virtual mapping ranges (start(Int), end(Int), permission(String), mapname(String))

        """

        def _get_offline_maps():
            name = self.getfile()
            if not name:
                return None
            headers = self.elfheader()
            binmap = []
            hlist = [x for x in headers.items() if x[1][2] == 'code']
            hlist = sorted(hlist, key=lambda x: x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rx-p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'rodata']
            hlist = sorted(hlist, key=lambda x: x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "r--p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'data']
            hlist = sorted(hlist, key=lambda x: x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rw-p", name)]

            return binmap

        def _get_allmaps_freebsd(pid, remote=False):
            maps = []
            mpath = "/proc/%s/map" % pid
            # 0x8048000 0x8049000 1 0 0xc36afdd0 r-x 1 0 0x1000 COW NC vnode /path/to/file NCH -1
            pattern = re.compile("0x([0-9a-f]*) 0x([0-9a-f]*)(?: [^ ]*){3} ([rwx-]*)(?: [^ ]*){6} ([^ ]*)")

            if remote:  # remote target, not yet supported
                return maps
            else:  # local target
                try:
                    out = open(mpath).read()
                except:
                    error("could not open %s; is procfs mounted?" % mpath)

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    if start[:2] in ["bf", "7f", "ff"] and "rw" in perm:
                        mapname = "[stack]"
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "-":
                        if start == maps[-1][1] and maps[-1][-1][0] == "/":
                            mapname = maps[-1][-1]
                        else:
                            mapname = "mapped"
                    maps += [(start, end, perm, mapname)]
            return maps

        def _get_allmaps_linux(pid, remote=False):
            maps = []
            mpath = "/proc/%s/maps" % pid
            # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
            pattern = re.compile("^([0-9a-f]+)-([0-9a-f]+) ([-rwxps]+)(?: \S+){3} *(.*)$", re.MULTILINE)

            if remote:  # remote target
                out = self.read_from_remote(mpath)
            else:  # local target
                out = open(mpath).read()

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "":
                        mapname = "mapped"
                    maps.append((start, end, perm, mapname))
            return maps

        result = []
        pid = self.getpid()
        if not pid:  # not running, try to use elfheader()
            return _get_offline_maps()

        # retrieve all maps
        target_os = self.getos()
        rmt = self.is_target_remote()
        maps = []
        try:
            if target_os == "FreeBSD":
                maps = _get_allmaps_freebsd(pid, rmt)
            elif target_os == "Linux":
                maps = _get_allmaps_linux(pid, rmt)
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg("Exception: %s" % e)
                traceback.print_exc()

        # select maps matched specific name
        if name == "binary":
            name = self.getfile()
            # if remote then maybe gdb use local path
            if name is not None and self.is_target_remote():
                name = os.path.basename(name)
        if name is None or name == "all":
            name = ""

        if to_int(name) is None:
            for (start, end, perm, mapname) in maps:
                if name in mapname:
                    result.append((start, end, perm, mapname))
        else:
            addr = to_int(name)
            for (start, end, perm, mapname) in maps:
                if start <= addr < end:
                    result.append((start, end, perm, mapname))

        return result

    @memoized
    def get_vmrange(self, address, maps=None):
        """
        Get virtual memory mapping range of an address

        Args:
            - address: target address (Int)
            - maps: only find in provided maps (List)

        Returns:
            - tuple of virtual memory info (start, end, perm, mapname)
        """
        if address is None:
            return None
        if maps is None:
            maps = self.get_vmmap()
        if maps:
            for (start, end, perm, mapname) in maps:
                if start <= address < end:
                    return start, end, perm, mapname
        # failed to get the vmmap
        else:
            try:
                gdb.selected_inferior().read_memory(address, 1)
                start = address & 0xfffffffffffff000
                end = start + 0x1000
                return start, end, 'rwx', 'unknown'
            except:
                return None

    @memoized
    def is_executable(self, address, maps=None):
        """
        Check if an address is executable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to an executable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "x" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_writable(self, address, maps=None):
        """
        Check if an address is writable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to a writable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "w" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_address(self, value, maps=None):
        """
        Check if a value is a valid address (belongs to a memory region)

        Args:
            - value (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if value belongs to an address range (Bool)
        """
        vmrange = self.get_vmrange(value, maps)
        return vmrange is not None

    @memoized
    def get_disasm(self, address, count=1):
        """
        Get the ASM code of instruction at address

        Args:
            - address: address to read instruction (Int)
            - count: number of code lines (Int)

        Returns:
            - asm code (String)
        """
        code = PEDA.execute_redirect("x/%di 0x%x" % (count, address))
        return code.rstrip()

    @staticmethod
    def dumpmem(start, end):
        """
        Dump process memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)

        Returns:
            - memory content (raw bytes)
        """
        mem = None
        logfd = tmpfile(is_binary_file=True)
        logname = logfd.name
        out = PEDA.execute_redirect("dump memory %s 0x%x 0x%x" % (logname, start, end))
        if out is not None:
            logfd.flush()
            mem = logfd.read()
            logfd.close()

        return mem

    @staticmethod
    def readmem(address, size):
        """
        Read content of memory at an address

        Args:
            - address: start address to read (Int)
            - size: bytes to read (Int)

        Returns:
            - memory content (raw bytes)
        """
        # try fast dumpmem if it works
        mem = PEDA.dumpmem(address, address + size)
        if mem is not None:
            return mem

        # failed to dump, use slow x/gx way
        mem = ""
        out = PEDA.execute_redirect("x/%dbx 0x%x" % (size, address))
        if out:
            for line in out.splitlines():
                bytes = line.split(":\t")[-1].split()
                mem += "".join([chr(int(c, 0)) for c in bytes])

        return mem

    def read_int(self, address, intsize=None):
        """
        Read an interger value from memory

        Args:
            - address: address to read (Int)
            - intsize: force read size (Int)

        Returns:
            - mem value (Int)
        """
        if not intsize:
            intsize = self.intsize()
        value = self.readmem(address, intsize)
        if value:
            value = to_int("0x" + codecs.encode(value[::-1], 'hex'))
            return value
        else:
            return None

    def read_long(self, address):
        """
        Read a long long value from memory

        Args:
            - address: address to read (Int)

        Returns:
            - mem value (Long Long)
        """
        return self.read_int(address, 8)

    def writemem(self, address, buf):
        """
        Write buf to memory start at an address

        Args:
            - address: start address to write (Int)
            - buf: data to write (raw bytes)

        Returns:
            - number of written bytes (Int)
        """
        out = None
        if not buf:
            return 0

        if self.getpid():
            # try fast restore mem
            tmp = tmpfile(is_binary_file=True)
            tmp.write(buf)
            tmp.flush()
            out = PEDA.execute_redirect("restore %s binary 0x%x" % (tmp.name, address))
            tmp.close()
        if not out:  # try the slow way
            i = None
            for i in range(len(buf)):
                if not PEDA.execute("set {char}0x%x = 0x%x" % (address + i, ord(buf[i]))):
                    return i
            return i + 1
        elif "error" in out:  # failed to write the whole buf, find written byte
            for i in range(0, len(buf), 1):
                if not self.is_address(address + i):
                    return i
        else:
            return len(buf)

    def write_int(self, address, value, intsize=None):
        """
        Write an interger value to memory

        Args:
            - address: address to read (Int)
            - value: int to write to (Int)
            - intsize: force write size (Int)

        Returns:
            - Bool
        """
        if not intsize:
            intsize = self.intsize()
        buf = hex2str(value, intsize).ljust(intsize, "\x00")[:intsize]
        saved = self.readmem(address, intsize)
        if not saved:
            return False

        ret = self.writemem(address, buf)
        if ret != intsize:
            self.writemem(address, saved)
            return False
        return True

    def write_long(self, address, value):
        """
        Write a long long value to memory

        Args:
            - address: address to read (Int)
            - value: value to write to

        Returns:
            - Bool
        """
        return self.write_int(address, value, 8)

    def cmpmem(self, start, end, buf):
        """
        Compare contents of a memory region with a buffer

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - buf: raw bytes

        Returns:
            - dictionary of array of diffed bytes in hex (Dictionary)
            {123: [("A", "B"), ("C", "C"))]}
        """
        line_len = 32
        if end < start:
            (start, end) = (end, start)

        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        length = min(len(mem), len(buf))
        result = {}
        lineno = 0
        for i in range(length // line_len):
            diff = 0
            bytes_ = []
            for j in range(line_len):
                offset = i * line_len + j
                bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
                if mem[offset] != buf[offset]:
                    diff = 1
            if diff == 1:
                result[start + lineno] = bytes_
            lineno += line_len

        bytes_ = []
        diff = 0
        for i in range(length % line_len):
            offset = lineno + i
            bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
            if mem[offset] != buf[offset]:
                diff = 1
        if diff == 1:
            result[start + lineno] = bytes_

        return result

    def xormem(self, start, end, key):
        """
        XOR a memory region with a key

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - key: XOR key (String)

        Returns:
            - xored memory content (raw bytes)
        """
        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        if to_int(key) != None:
            key = hex2str(to_int(key), self.intsize())
        mem = list(bytes_iterator(mem))
        for index, char in enumerate(mem):
            key_idx = index % len(key)
            mem[index] = chr(ord(char) ^ ord(key[key_idx]))

        buf = b"".join([to_binary_string(x) for x in mem])
        bytes = self.writemem(start, buf)
        return buf

    def searchmem(self, start, end, search, mem=None):
        """
        Search for all instances of a pattern in memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string or python regex pattern (String)
            - mem: cached mem to not re-read for repeated searches (raw bytes)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))

        """

        result = []
        if end < start:
            (start, end) = (end, start)

        if mem is None:
            mem = self.dumpmem(start, end)

        if not mem:
            return result

        if isinstance(search, six.string_types) and search.startswith("0x"):
            # hex number
            search = search[2:]
            if len(search) % 2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
            search = re.escape(search)

        # Convert search to bytes if is not already
        if not isinstance(search, bytes):
            search = search.encode('utf-8')

        try:
            p = re.compile(search)
        except:
            search = re.escape(search)
            p = re.compile(search)

        found = list(p.finditer(mem))
        for m in found:
            index = 1
            if m.start() == m.end() and m.lastindex:
                index = m.lastindex + 1
            for i in range(0, index):
                if m.start(i) != m.end(i):
                    result += [(start + m.start(i), codecs.encode(mem[m.start(i):m.end(i)], 'hex'))]

        return result

    def searchmem_by_range(self, mapname, search):
        """
        Search for all instances of a pattern in virtual memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of virtual memory range (String)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))
        """

        result = []
        ranges = self.get_vmmap(mapname)
        if ranges:
            for (start, end, perm, name) in ranges:
                if "r" in perm:
                    result += self.searchmem(start, end, search)

        return result

    @memoized
    def search_reference(self, search, mapname=None):
        """
        Search for all references to a value in memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of target virtual memory range (String)

        Returns:
            - list of found result: (address(int), hex encoded value(String))
        """

        maps = self.get_vmmap()
        ranges = self.get_vmmap(mapname)
        result = []
        search_result = []
        for (start, end, perm, name) in maps:
            if "r" in perm:
                search_result += self.searchmem(start, end, search)

        for (start, end, perm, name) in ranges:
            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a))

        return result

    @memoized
    def search_address(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid addresses in memory ranges

        Args:
            - searchfor: memory region to search for addresses (String)
            - belongto: memory region that target addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        result = []
        maps = self.get_vmmap()
        if maps is None:
            return result

        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]:  # dirty trick, to search in rw-p mem first
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i + step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr, belongto_ranges):
                    result += [(start + i, addr)]

        return result

    @memoized
    def search_pointer(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid pointers in memory ranges

        Args:
            - searchfor: memory region to search for pointers (String)
            - belongto: memory region that pointed addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        search_result = []
        result = []
        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]:
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i + step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr):
                    (v, t, vn) = self.examine_mem_value(addr)
                    if t != 'value':
                        if self.is_address(to_int(vn), belongto_ranges):
                            if (to_int(v), v) not in search_result:
                                search_result += [(to_int(v), v)]

            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a), mem)

        return result

    @staticmethod
    def search_substr(start, end, search, mem=None):
        """
        Search for substrings of a given string/number in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string to search for (String)
            - mem: cached memory (raw bytes)

        Returns:
            - list of tuple (substr(String), address(Int))
        """

        def substr(s1, s2):
            "Search for a string in another string"
            s1 = to_binary_string(s1)
            s2 = to_binary_string(s2)
            i = 1
            found = 0
            while i <= len(s1):
                if s2.find(s1[:i]) != -1:
                    found = 1
                    i += 1
                    if s1[:i - 1][-1:] == b"\x00":
                        break
                else:
                    break
            if found == 1:
                return i - 1
            else:
                return -1

        result = []
        if end < start:
            start, end = end, start

        if mem is None:
            mem = PEDA.dumpmem(start, end)

        if search[:2] == "0x":  # hex number
            search = search[2:]
            if len(search) % 2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
        search = to_binary_string(decode_string_escape(search))
        while search:
            l = len(search)
            i = substr(search, mem)
            if i != -1:
                sub = search[:i]
                addr = start + mem.find(sub)
                if not check_badchars(addr):
                    result.append((sub, addr))
            else:
                result.append((search, -1))
                return result
            search = search[i:]
        return result

    @memoized
    def examine_mem_value(self, value):
        """
        Examine a value in memory for its type and reference

        Args:
            - value: value to examine (Int)

        Returns:
            - tuple of (value(Int), type(String), next_value(Int))
        """

        def examine_data(value, bits=32):
            out = PEDA.execute_redirect("x/%sx 0x%x" % ("g" if bits == 64 else "w", value))
            if out:
                v = out.split(":\t")[-1].strip()
                if is_printable(int2hexstr(to_int(v), bits // 8)):
                    out = PEDA.execute_redirect("x/s 0x%x" % value)
            return out

        result = (None, None, None)
        if value is None:
            return result

        # maps = self.get_vmmap()
        binmap = self.get_vmmap("binary")

        (arch, bits) = self.getarch()
        if not self.is_address(value):  # a value
            result = (to_hex(value), "value", "")
            return result
        else:
            (_, _, _, mapname) = self.get_vmrange(value)

        # check for writable first so rwxp mem will be treated as data
        if self.is_writable(value):  # writable data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "data", out.split(":", 1)[1].strip())

        elif self.is_executable(value):  # code/rodata address
            if self.is_address(value, binmap):
                headers = self.elfheader()
            else:
                headers = self.elfheader_solib(mapname)

            if headers:
                headers = sorted(headers.items(), key=lambda x: x[1][1])
                for (k, (start, end, type)) in headers:
                    if start <= value < end:
                        if type == "code":
                            out = self.get_disasm(value)
                            p = re.compile(".*?0x[^ ]*?\s(.*)")
                            m = p.search(out)
                            result = (to_hex(value), "code", m.group(1))
                        else:  # rodata address
                            out = examine_data(value, bits)
                            result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                        break

                if result[0] is None:  # not fall to any header section
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())

            else:  # not belong to any lib: [heap], [vdso], [vsyscall], etc
                out = self.get_disasm(value)
                if "(bad)" in out:
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                else:
                    p = re.compile(".*?0x[^ ]*?\s(.*)")
                    m = p.search(out)
                    result = (to_hex(value), "code", m.group(1))

        else:  # readonly data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
            else:
                result = (to_hex(value), "rodata", "MemError")

        return result

    @memoized
    def examine_mem_reference(self, value):
        """
        Deeply examine a value in memory for its references

        Args:
            - value: value to examine (Int)

        Returns:
            - list of tuple of (value(Int), type(String), next_value(Int))
        """
        result = []
        (v, t, vn) = self.examine_mem_value(value)
        count = 0
        while vn is not None and count < 8:
            result += [(v, t, vn)]
            if v == vn or to_int(v) == to_int(vn):  # point to self
                break
            if to_int(vn) is None:
                break
            if to_int(vn) in [to_int(v) for (v, _, _) in result]:  # point back to previous value
                break
            (v, t, vn) = self.examine_mem_value(to_int(vn))
            count += 1

        return result

    @memoized
    def format_search_result(self, result, display=256):
        """
        Format the result from various memory search commands

        Args:
            - result: result of search commands (List)
            - display: number of items to display

        Returns:
            - text: formatted text (String)
        """

        text = ""
        if not result:
            text = "Not found"
        else:
            maxlen = 0
            maps = self.get_vmmap()
            shortmaps = []
            for (start, end, perm, name) in maps:
                shortname = os.path.basename(name)
                if shortname.startswith("lib"):
                    shortname = shortname.split("-")[0]
                shortmaps += [(start, end, perm, shortname)]

            count = len(result)
            if display != 0:
                count = min(count, display)
            text += "Found %d results, display max %d items:\n" % (len(result), count)
            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                maxlen = max(maxlen, len(vmrange[3]))

            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                chain = self.examine_mem_reference(addr)
                text += "%s : %s" % (vmrange[3].rjust(maxlen), format_reference_chain(chain) + "\n")

        return text

    ##########################
    #     Exploit Helpers    #
    ##########################
    @memoized
    def elfentry(self):
        """
        Get entry point address of debugged ELF file

        Returns:
            - entry address (Int)
        """
        out = PEDA.execute_redirect("info files")
        p = re.compile("Entry point: (\S*)")
        if out:
            m = p.search(out)
            if m:
                return to_int(m.group(1))
        return None

    @memoized
    def elfheader(self, name=None):
        """
        Get headers information of debugged ELF file

        Args:
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): (start(Int), end(Int), type(String))}
        """
        elfinfo = {}
        elfbase = 0
        if self.getpid():
            binmap = self.get_vmmap("binary")
            elfbase = binmap[0][0] if binmap else 0

        out = PEDA.execute_redirect("maintenance info sections")
        if not out:
            return {}

        p = re.compile("^ *\S+ +(0x[^-]+)->(0x[^ ]+) at (\S+): +(\S+) +(.*)$", re.M)
        matches = p.findall(out)

        for (start, end, offset, hname, attr) in matches:
            start, end, offset = to_int(start), to_int(end), to_int(offset)
            # skip unuseful header
            if start < offset:
                continue
            # if PIE binary, update with runtime address
            if start < elfbase:
                start += elfbase
                end += elfbase

            if "CODE" in attr:
                htype = "code"
            elif "READONLY" in attr:
                htype = "rodata"
            else:
                htype = "data"

            elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfheader_solib(self, solib=None, name=None):
        """
        Get headers information of Shared Object Libraries linked to target

        Args:
            - solib: shared library name (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): start(Int), end(Int), type(String))
        """
        # hardcoded ELF header type
        # todo
        header_type = {"code": [".text", ".fini", ".init", ".plt", "__libc_freeres_fn"],
                       "data": [".dynamic", ".data", ".ctors", ".dtors", ".jrc", ".got", ".got.plt",
                                ".bss", ".tdata", ".tbss", ".data.rel.ro", ".fini_array",
                                "__libc_subfreeres", "__libc_thread_subfreeres"]
                       }

        @memoized
        def _elfheader_solib_all():
            out = PEDA.execute_redirect("info files")
            if not out:
                return None

            p = re.compile("^ *(0x\S+) - (0x\S+) is (\.\S+) in (\S+)")
            soheaders = p.findall(out)

            result = []
            for (start, end, hname, libname) in soheaders:
                start, end = to_int(start), to_int(end)
                result += [
                    (start, end, hname, os.path.realpath(libname))]  # tricky, return the realpath version of libraries
            return result

        elfinfo = {}

        headers = _elfheader_solib_all()
        if not headers:
            return {}

        if solib is None:
            return headers

        vmap = self.get_vmmap(solib)
        elfbase = vmap[0][0] if vmap else 0

        for (start, end, hname, libname) in headers:
            if solib in libname:
                # if PIE binary or DSO, update with runtime address
                if start < elfbase:
                    start += elfbase
                if end < elfbase:
                    end += elfbase
                # determine the type
                htype = "rodata"
                if hname in header_type["code"]:
                    htype = "code"
                elif hname in header_type["data"]:
                    htype = "data"
                elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfsymbols(self, pattern=None):
        """
        Get all non-debugging symbol information of debugged ELF file

        Returns:
            - dictionary of (address(Int), symname(String))
        """
        headers = self.elfheader()
        if ".plt" not in headers:  # static binary
            return {}

        binmap = self.get_vmmap("binary")
        elfbase = binmap[0][0] if binmap else 0

        # get the .dynstr header
        headers = self.elfheader()
        if ".dynstr" not in headers:
            return {}
        (start, end, _) = headers[".dynstr"]
        mem = self.dumpmem(start, end)
        if not mem and self.getfile():
            # todo remote
            if self.is_target_remote():
                return {}
            fd = open(self.getfile())
            fd.seek(start, 0)
            mem = fd.read(end - start)
            fd.close()

        # Convert names into strings
        dynstrings = [name.decode('utf-8') for name in mem.split(b"\x00")]

        if pattern:
            dynstrings = [s for s in dynstrings if re.search(pattern, s)]

        # get symname@plt info
        symbols = {}
        for symname in dynstrings:
            if not symname:
                continue
            symname += "@plt"
            out = PEDA.execute_redirect("info functions %s" % symname)
            if not out: continue
            m = re.findall(".*(0x[^ ]*)\s*%s" % re.escape(symname), out)
            for addr in m:
                addr = to_int(addr)
                if self.is_address(addr, binmap):
                    if symname not in symbols:
                        symbols[symname] = addr
                        break

        # if PIE binary, update with runtime address
        for (k, v) in symbols.items():
            if v < elfbase:
                symbols[k] = v + elfbase

        return symbols

    @memoized
    def elfsymbol(self, symname=None):
        """
        Get non-debugging symbol information of debugged ELF file

        Args:
            - symname: target function name (String), special cases:
                + "data": data transfer functions
                + "exec": exec helper functions

        Returns:
            - if exact name is not provided: dictionary of tuple (symname, plt_entry)
            - if exact name is provided: dictionary of tuple (symname, plt_entry, got_entry, reloc_entry)
        """
        datafuncs = ["printf", "puts", "gets", "cpy"]
        execfuncs = ["system", "exec", "mprotect", "mmap", "syscall"]
        result = {}
        if not symname or symname in ["data", "exec"]:
            symbols = self.elfsymbols()
        else:
            symbols = self.elfsymbols(symname)

        if not symname:
            result = symbols
        else:
            sname = symname.replace("@plt", "") + "@plt"
            if sname in symbols:
                plt_addr = symbols[sname]
                result[sname] = plt_addr  # plt entry
                out = self.get_disasm(plt_addr, 2)
                for line in out.splitlines():
                    # todo ??
                    if "jmp" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1].split()[0])
                        result[sname.replace("@plt", "@got")] = addr  # got entry
                    if "push" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1])
                        result[sname.replace("@plt", "@reloc")] = addr  # reloc offset
            else:
                keywords = [symname]
                if symname == "data":
                    keywords = datafuncs
                if symname == "exec":
                    keywords = execfuncs
                for (k, v) in symbols.items():
                    for f in keywords:
                        if f in k:
                            result[k] = v

        return result

    @memoized
    def main_entry(self):
        """
        Get address of main function of stripped ELF file

        Returns:
            - main function address (Int)
        """
        # todo not __libc_start_main@plt?
        refs = self.xrefs("__libc_start_main@plt")
        if refs:
            inst = self.prev_inst(refs[0][0])
            if inst:
                addr = re.search(".*(0x.*)", inst[0][1])
                if addr:
                    return to_int(addr.group(1))
        return None


###########################################################################
class PEDACmd(object):
    """
    Class for PEDA commands that interact with GDB
    """
    MSG_LEGEND = "Legend: %s, %s, %s, value" % (red("code"), blue("data"), green("rodata"))
    commands = []

    def __init__(self, peda, running_file_path, asm):
        self.peda = peda
        self.pedafile = running_file_path  # for reload
        self.asm = asm  # for asm support
        # list of all available commands
        self.commands = [c for c in dir(self) if callable(getattr(self, c)) and not c.startswith("_")]
        self.width = 78
        self.plugins = {}

    ##################
    #   Misc Utils   #
    ##################
    def _missing_argument(self):
        """
        Raise exception for missing argument, for internal use
        """
        text = "missing argument"
        error(text)
        raise Exception(text)

    def _is_running(self):
        """
        Check if program is running, for internal use
        """
        pid = self.peda.getpid()
        if pid is None:
            text = "not running or attach"
            warning(text)
            return None
            # raise Exception(text)
        else:
            return pid

    def _update_width(self, fd=1):
        """
        update width

        Args:
            fd: int defaults to the main terminal

        Returns: None

        """
        # first 2 shorts (4 byte) of struct winsize
        raw = fcntl.ioctl(fd, termios.TIOCGWINSZ, ' ' * 4)
        height, width = struct.unpack('hh', raw)
        self.width = int(width) - 2

    def reload(self, *arg):
        """
        Reload PEDA sources, keep current options untouch
        Usage:
            MYNAME [name]
        """
        (modname,) = normalize_argv(arg, 1)
        # save current PEDA options
        saved_opt = config.Option
        peda_path = os.path.dirname(self.pedafile) + "/peda/"
        if not modname:
            modname = "PEDA"  # just for notification
            ret = self.peda.execute("source %s" % self.pedafile)
        else:
            if not modname.endswith(".py"):
                modname += ".py"
            filepath = "%s/%s" % (peda_path, modname)
            if os.path.exists(filepath):
                ret = self.peda.execute("source %s" % filepath)
                self.peda.execute("source %s" % self.pedafile)
            else:
                ret = False

        config.Option = saved_opt
        if ret:
            info(blue("%s reloaded!" % modname))
        else:
            error("Failed to reload %s source from: %s" % (modname, peda_path))

    def _get_helptext(self, *arg):
        """
        Get the help text, for internal use by help command and other aliases
        """

        (cmd,) = normalize_argv(arg, 1)
        helptext = []
        if cmd is None:
            helptext.append(red("PEDA", "bold") + blue(" - Python Exploit Development Assistance for GDB", "bold"))
            # helptext += "For latest update, check peda project page: %s\n" % green("https://github.com/longld/peda/")
            helptext.append("List of \"peda\" subcommands, type the subcommand to invoke it:\n")
            for cmd in self.commands:
                if not cmd.startswith("_"):  # skip internal use commands
                    func = getattr(self, cmd)
                    helptext.append("%s -- %s" % (cmd, green(trim(func.__doc__.strip("\n").splitlines()[0]))))
            helptext.append('\nType "help" followed by subcommand for full documentation.')
        else:
            if cmd in self.commands:
                func = getattr(self, cmd)
                lines = trim(func.__doc__).splitlines()
                helptext.append(green(lines[0]))
                for line in lines[1:]:
                    if "Usage:" in line:
                        helptext.append(blue(line))
                    else:
                        helptext.append(line)
            else:
                for c in self.commands:
                    if not c.startswith("_") and cmd in c:
                        func = getattr(self, c)
                        helptext.append("%s -- %s" % (c, green(trim(func.__doc__.strip("\n").splitlines()[0]))))

        return '\n'.join(helptext)

    def help(self, *arg):
        """
        Print the usage manual for PEDA commands
        Usage:
            MYNAME
            MYNAME command
        """

        msg(self._get_helptext(*arg))

    help.options = commands

    def pyhelp(self, *arg):
        """
        Wrapper for python built-in help
        Usage:
            MYNAME (enter interactive help)
            MYNAME help_request
        """
        (request,) = normalize_argv(arg, 1)
        if request is None:
            self.help()
            return

        peda_methods = ["%s" % c for c in dir(PEDA) if callable(getattr(PEDA, c)) and not c.startswith("_")]

        if request in peda_methods:
            request = "peda.%s" % request
        try:
            if request.lower().startswith("peda"):
                request = eval(request)
                self.help(request)
                return

            if "." in request:
                module, _, function = request.rpartition('.')
                if module:
                    module = module.split(".")[0]
                    __import__(module)
                    mod = sys.modules[module]
                    if function:
                        request = getattr(mod, function)
                    else:
                        request = mod
            else:
                mod = sys.modules['__main__']
                request = getattr(mod, request)

            # wrapper for python built-in help
            self.help(request)
        except:  # fallback to built-in help
            try:
                self.help(request)
            except Exception as e:
                if config.Option.get("debug") == "on":
                    msg('Exception (%s): %s' % ('pyhelp', e), "red")
                    traceback.print_exc()
                warning("no Python documentation found for '%s'" % request)

    pyhelp.options = ["%s" % c for c in dir(PEDA) if callable(getattr(PEDA, c)) and not c.startswith("_")]

    # show [option | args | env]
    def show(self, *arg):
        """
        Show various PEDA options and other settings
        Usage:
            MYNAME option [optname]
            MYNAME (show all options)
            MYNAME args
            MYNAME env [envname]
        """

        # show options
        def _show_option(name=None):
            if name is None:
                name = ""
            # todo ?
            filename = self.peda.getfile()
            if filename:
                filename = os.path.basename(filename)
            else:
                filename = None
            for (k, v) in sorted(config.Option.show(name).items()):
                if filename and isinstance(v, str) and "#FILENAME#" in v:
                    v = v.replace("#FILENAME#", filename)
                msg("%s = %s" % (k, repr(v)))
            return

        # show args
        def _show_arg():
            arg = self.peda.execute_redirect("show args")
            arg = arg.split("started is ")[1][1:-3]
            arg = (self.peda.string_to_argv(arg))
            if not arg:
                msg("No argument")
            for (i, a) in enumerate(arg):
                text = "arg[%d]: %s" % ((i + 1), a if is_printable(a) else to_hexstr(a))
                msg(text)
            return

        # show envs
        def _show_env(name=None):
            if name is None:
                name = ""
            env = self.peda.execute_redirect("show env")
            for line in env.splitlines():
                (k, v) = line.split("=", 1)
                if k.startswith(name):
                    msg("%s = %s" % (k, v if is_printable(v) else to_hexstr(v)))
            return

        (opt, name) = normalize_argv(arg, 2)

        if opt is None or opt.startswith("opt"):
            _show_option(name)
        elif opt.startswith("arg"):
            _show_arg()
        elif opt.startswith("env"):
            _show_env(name)
        else:
            msg("Unknown show option: %s" % opt)

    show.options = ["option", "arg", "env"]

    # set [option | arg | env]
    def set(self, *arg):
        """
        Set various PEDA options and other settings
        Usage:
            MYNAME option name value
            MYNAME arg string
            MYNAME env name value
                support input non-printable chars, e.g MYNAME env EGG "\\x90"*1000
        """

        # set options
        def _set_option(name, value):
            if name in config.Option.options:
                config.Option.set(name, value)
                msg("%s = %s" % (name, repr(value)))
            else:
                msg("Unknown option: %s" % name)
            return

        # set args
        def _set_arg(*arg):
            cmd = "set args"
            for a in arg:
                try:
                    s = eval('%s' % a)
                    if isinstance(s, six.integer_types + six.string_types):
                        a = s
                except:
                    pass
                cmd += " '%s'" % a
            self.peda.execute(cmd)
            return

        # set env
        def _set_env(name, value):
            env = self.peda.execute_redirect("show env")
            cmd = "set env %s " % name
            try:
                value = eval('%s' % value)
            except:
                pass
            cmd += '%s' % value
            self.peda.execute(cmd)

            return

        (opt, name, value) = normalize_argv(arg, 3)
        if opt is None:
            self._missing_argument()

        if opt.startswith("opt"):
            if value is None:
                self._missing_argument()
            _set_option(name, value)
        elif opt.startswith("arg"):
            _set_arg(*arg[1:])
        elif opt.startswith("env"):
            _set_env(name, value)
        else:
            warning("Unknown set option: %s" % opt)

    set.options = ["option", "arg", "env"]

    def hexprint(self, *arg):
        """
        Display hexified of data in memory
        Usage:
            MYNAME address (display 16 bytes from address)
            MYNAME address count
            MYNAME address /count (display "count" lines, 16-bytes each)
        """
        (address, count) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        if count is None:
            count = 16

        if not to_int(count) and count.startswith("/"):
            count = to_int(count[1:])
            count = count * 16 if count else None

        bytes_ = self.peda.dumpmem(address, address + count)
        if bytes_ is None:
            warning("cannot retrieve memory content")
        else:
            hexstr = to_hexstr(bytes_)
            linelen = 16  # display 16-bytes per line
            i = 0
            text = ""
            while hexstr:
                text += '%s : "%s"\n' % (blue(to_address(address + i * linelen)), hexstr[:linelen * 4])
                hexstr = hexstr[linelen * 4:]
                i += 1
            pager(text)

    def hexdump(self, *arg):
        """
        Display hex/ascii dump of data in memory
        Usage:
            MYNAME address (dump 16 bytes from address)
            MYNAME address count
            MYNAME address /count (dump "count" lines, 16-bytes each)
        """

        def ascii_char(ch):
            if 0x20 <= ord(ch) < 0x7e:
                return chr(ord(ch))  # Ensure we return a str
            else:
                return "."

        (address, count) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        if count is None:
            count = 16

        if not to_int(count) and count.startswith("/"):
            count = to_int(count[1:])
            count = count * 16 if count else None

        bytes_ = self.peda.dumpmem(address, address + count)
        if bytes_ is None:
            warning("Cannot retrieve memory content")
        else:
            linelen = 16  # display 16-bytes per line
            i = 0
            text = ""
            while bytes_:
                buf = bytes_[:linelen]
                hexbytes = " ".join(["%02x" % ord(c) for c in bytes_iterator(buf)])
                asciibytes = "".join([ascii_char(c) for c in bytes_iterator(buf)])
                text += '%s : %s  %s\n' % (
                    blue(to_address(address + i * linelen)), hexbytes.ljust(linelen * 3), asciibytes)
                bytes_ = bytes_[linelen:]
                i += 1
            pager(text)

    def aslr(self, *arg):
        """
        Show/set ASLR setting of GDB
        Usage:
            MYNAME [on|off]
        """
        (option,) = normalize_argv(arg, 1)
        if option is None:
            out = self.peda.execute_redirect("show disable-randomization")
            if not out:
                warning("ASLR setting is unknown or not available")
                return

            if "is off" in out:
                msg("ASLR is %s" % green("ON"))
            if "is on" in out:
                msg("ASLR is %s" % red("OFF"))
        else:
            option = option.strip().lower()
            if option in ["on", "off"]:
                self.peda.execute("set disable-randomization %s" % ("off" if option == "on" else "on"))

    def xprint(self, *arg):
        """
        Extra support to GDB's print command
        Usage:
            MYNAME expression
        """
        text = ""
        exp = " ".join(list(arg))
        # todo
        m = re.search(".*\[(.*)\]|.*?s:(0x[^ ]*)", exp)
        if m:
            addr = self.peda.parse_and_eval(m.group(1))
            if to_int(addr):
                text += "[0x%x]: " % to_int(addr)

        out = self.peda.parse_and_eval(exp)
        if to_int(out):
            chain = self.peda.examine_mem_reference(to_int(out))
            text += format_reference_chain(chain)
        msg(text)

    def distance(self, *arg):
        """
        Calculate distance between two addresses
        Usage:
            MYNAME address (calculate from current $SP to address)
            MYNAME address1 address2
        """
        (start, end) = normalize_argv(arg, 2)
        if to_int(start) is None or (to_int(end) is None and not self._is_running()):
            self._missing_argument()

        sp = None
        if end is None:
            sp = self.peda.getreg("sp")
            end = start
            start = sp

        dist = end - start
        text = "From 0x%x%s to 0x%x: " % (start, " (SP)" if start == sp else "", end)
        text += "%d bytes, %d dwords%s" % (dist, dist // 4, " (+%d bytes)" % (dist % 4) if (dist % 4 != 0) else "")
        msg(text)

    def session(self, *arg):
        """
        Save/restore a working gdb session to file as a script
        Usage:
            MYNAME save [filename]
            MYNAME restore [filename]
        """
        options = ["save", "restore", "autosave"]
        (option, filename) = normalize_argv(arg, 2)
        if option not in options:
            self._missing_argument()

        if not filename:
            filename = self.peda.get_config_filename("session")

        if option == "save":
            if self.peda.save_session(filename):
                info("Saved GDB session to file %s" % filename)
            else:
                error("Failed to save GDB session")

        if option == "restore":
            if self.peda.restore_session(filename):
                info("Restored GDB session from file %s" % filename)
            else:
                error("Failed to restore GDB session")

        if option == "autosave":
            if config.Option.get("autosave") == "on":
                self.peda.save_session(filename)

    session.options = ["save", "restore"]

    #################################
    #   Debugging Helper Commands   #
    #################################
    def procinfo(self, *arg):
        """
        Display various info from /proc/pid/
        Usage:
            MYNAME [pid]
        """
        options = ["exe", "fd", "pid", "ppid", "uid", "gid"]

        if self.peda.getos() != "Linux":
            warning("this command is only available on Linux")

        (pid,) = normalize_argv(arg, 1)

        if not pid:
            pid = self.peda.getpid()

        if not pid:
            return

        info = {}
        try:
            info["exe"] = os.path.realpath("/proc/%d/exe" % pid)
        except:
            warning("cannot access /proc/%d/" % pid)
            return

        # fd list
        info["fd"] = {}
        fdlist = os.listdir("/proc/%d/fd" % pid)
        for fd in fdlist:
            rpath = os.readlink("/proc/%d/fd/%s" % (pid, fd))
            sock = re.search("socket:\[(.*)\]", rpath)
            if sock:
                spath = execute_external_command("netstat -aen | grep %s" % sock.group(1))
                if spath:
                    rpath = spath.strip()
            info["fd"][to_int(fd)] = rpath

        # uid/gid, pid, ppid
        info["pid"] = pid
        status = open("/proc/%d/status" % pid).read()
        ppid = re.search("PPid:\s*([^\s]*)", status).group(1)
        info["ppid"] = to_int(ppid) if ppid else -1
        uid = re.search("Uid:\s*([^\n]*)", status).group(1)
        info["uid"] = [to_int(id) for id in uid.split()]
        gid = re.search("Gid:\s*([^\n]*)", status).group(1)
        info["gid"] = [to_int(id) for id in gid.split()]

        for opt in options:
            if opt == "fd":
                for (fd, path) in info[opt].items():
                    msg("fd[%d] -> %s" % (fd, path))
            else:
                msg("%s = %s" % (opt, info[opt]))
        return

    # getfile()
    def getfile(self):
        """
        Get exec filename of current debugged process
        Usage:
            MYNAME
        """
        filename = self.peda.getfile()
        if filename == None:
            msg("No file specified")
        else:
            msg(filename)

    # getpid()
    def getpid(self):
        """
        Get PID of current debugged process
        Usage:
            MYNAME
        """
        pid = self._is_running()
        msg(pid)

    # disassemble()
    def pdisass(self, *arg):
        """
        Format output of gdb disassemble command with colors
        Usage:
            MYNAME "args for gdb disassemble command"
            MYNAME address /NN: equivalent to "x/NNi address"
        """
        (address, fmt_count) = normalize_argv(arg, 2)
        code = None
        if isinstance(fmt_count, str) and fmt_count.startswith("/"):
            count = to_int(fmt_count[1:])
            if not count or to_int(address) is None:
                self._missing_argument()
            else:
                code = self.peda.get_disasm(address, count)
        else:
            code = self.peda.disassemble(*arg)
        msg(format_disasm_code(code))

    # disassemble_around
    def nearpc(self, *arg):
        """
        Disassemble instructions nearby current PC or given address
        Usage:
            MYNAME [count]
            MYNAME address [count]
                count is maximum 256
        """
        (address, count) = normalize_argv(arg, 2)
        address = to_int(address)

        count = to_int(count)
        if address is not None and address < 0x40000:
            count = address
            address = None

        if address is None:
            address = self.peda.getpc()

        if count is None:
            code = self.peda.disassemble_around(address)
        else:
            code = self.peda.disassemble_around(address, count)

        if code:
            msg(format_disasm_code(code, address))
        else:
            error("invalid $pc address or instruction count")

    def waitfor(self, *arg):
        """
        Try to attach to new forked process; mimic "attach -waitfor"
        Usage:
            MYNAME [cmdname]
            MYNAME [cmdname] -c (auto continue after attached)
        """
        (name, opt) = normalize_argv(arg, 2)
        if name == "-c":
            opt = name
            name = None

        if name is None:
            filename = self.peda.getfile()
            if filename is None:
                warning("please specify the file to debug or process name to attach")
                return
            else:
                # todo
                name = os.path.basename(filename)

        info("Trying to attach to new forked process (%s), Ctrl-C to stop..." % name)
        cmd = "ps axo pid,command | grep %s | grep -v grep" % name
        getpids = []
        out = execute_external_command(cmd)
        for line in out.splitlines():
            getpids += [line.split()[0].strip()]

        while True:
            found = 0
            out = execute_external_command(cmd)
            for line in out.splitlines():
                line = line.split()
                pid = line[0].strip()
                cmdname = line[1].strip()
                if name not in cmdname: continue
                if pid not in getpids:
                    found = 1
                    break

            if found == 1:
                info("Attching to pid: %s, cmdname: %s" % (pid, cmdname))
                if self.peda.getpid():
                    self.peda.execute("detach")
                out = self.peda.execute_redirect("attach %s" % pid)
                msg(out)
                out = self.peda.execute_redirect("file %s" % cmdname)  # reload symbol file
                msg(out)
                if opt == "-c":
                    self.peda.execute("continue")
                return
            time.sleep(0.5)

    def xrefs(self, *arg):
        """
        Search for all call/data access references to a function/variable
        Usage:
            MYNAME pattern
            MYNAME pattern file/mapname
        """
        (search, filename) = normalize_argv(arg, 2)
        if search is None:
            search = ""  # search for all call references
        else:
            search = arg[0]

        if filename is not None:  # get full path to file if mapname is provided
            vmap = self.peda.get_vmmap(filename)
            if vmap:
                filename = vmap[0][3]

        result = self.peda.xrefs(search, filename)
        if result:
            if search != "":
                msg("All references to '%s':" % search)
            else:
                msg("All call references")
            for (addr, code) in result:
                msg("%s" % (code))
        else:
            msg("Not found")

    def xuntil(self, *arg):
        """
        Continue execution until an address or function
        Usage:
            MYNAME address | function
        """
        (address,) = normalize_argv(arg, 1)
        self.peda.set_breakpoint(address, temp=True)
        pc = self.peda.getpc()
        if pc is None:
            self.peda.execute("run")
        else:
            self.peda.execute("continue")

    def stepover(self, *arg):
        """
            Use tbreak to step over the current instruction.
            Usage:
                MYNAME [count]
            """
        (count,) = normalize_argv(arg, 1)
        if to_int(count) is None:
            count = 1

        if count < 1:
            count = 1

        if not self._is_running():
            return

        next_code = self.peda.next_inst(self.peda.getpc(), count)
        if not next_code:
            warning("failed to get next instructions")
            return
        next_addr = next_code[-1][0]
        self.xuntil(next_addr)

    def goto(self, *arg):
        """
        Goto an address
        Usage:
            MYNAME address
        """
        (address,) = normalize_argv(arg, 1)
        if to_int(address) is None:
            self._missing_argument()

        self.peda.execute("set $pc = 0x%x" % address)
        self.peda.execute("stop")

    def skipi(self, *arg):
        """
        Skip execution of next count instructions
        Usage:
            MYNAME [count]
        """
        (count,) = normalize_argv(arg, 1)
        if to_int(count) is None:
            count = 1

        if not self._is_running():
            return

        next_code = self.peda.next_inst(self.peda.getpc(), count)
        if not next_code:
            warning("failed to get next instructions")
            return
        last_addr = next_code[-1][0]
        self.peda.execute("set $pc = 0x%x" % last_addr)
        self.peda.execute("stop")

    # stepuntil()
    def stepuntil(self, *arg):
        """
        Step until a desired instruction in specific memory range
        Usage:
            MYNAME "inst1,inst2" (step to next inst in binary)
            MYNAME "inst1,inst2" mapname1,mapname2
        """
        (insts, mapname) = normalize_argv(arg, 2)
        if insts is None:
            self._missing_argument()

        if not self._is_running():
            return

        self.peda.save_user_command("hook-stop")  # disable hook-stop to speedup
        info("Stepping through, Ctrl-C to stop...")
        result = self.peda.stepuntil(insts, mapname)
        self.peda.restore_user_command("hook-stop")

        if result:
            self.peda.execute("stop")

    def profile(self, *arg):
        """
        Simple profiling to count executed instructions in the program
        Usage:
            MYNAME count [keyword]
                default is to count instructions inside the program only
                count = 0: run until end of execution
                keyword: only display stats for instructions matched it
        """
        (count, keyword) = normalize_argv(arg, 2)

        if count is None:
            self._missing_argument()

        if not self._is_running():
            return

        if keyword is None or keyword == "all":
            keyword = ""

        keyword = keyword.replace(" ", "").split(",")

        self.peda.save_user_command("hook-stop")  # disable hook-stop to speedup
        info("Stepping %s instructions, Ctrl-C to stop..." % ("%d" % count if count else "all"))

        if count == 0:
            count = -1
        stats = {}
        total = 0
        binmap = self.peda.get_vmmap("binary")
        try:
            while count != 0:
                pc = self.peda.getpc()
                if not self.peda.is_address(pc):
                    break
                code = self.peda.get_disasm(pc)
                if not code:
                    break
                if self.peda.is_address(pc, binmap):
                    for k in keyword:
                        if k in code.split(":\t")[-1]:
                            code = code.strip("=>").strip()
                            stats.setdefault(code, 0)
                            stats[code] += 1
                            break
                    self.peda.execute_redirect("stepi")
                else:
                    self.peda.execute_redirect("stepi")
                    self.peda.execute_redirect("finish")
                count -= 1
                total += 1
        except:
            pass

        self.peda.restore_user_command("hook-stop")
        text = "Executed %d instructions\n" % total
        text += "%s %s\n" % (blue("Run-count", "bold"), blue("Instruction", "bold"))
        for (code, count) in sorted(stats.items(), key=lambda x: x[1], reverse=True):
            text += "%8d: %s\n" % (count, code)
        pager(text)

    @msg.bufferize
    def context_code(self, *arg):
        """
        Display nearby disassembly at $PC of current execution context
        Usage:
            MYNAME [linecount]
        """
        (count,) = normalize_argv(arg, 1)

        if count is None:
            count = 8

        if not self._is_running():
            return

        pc = self.peda.getpc()
        if self.peda.is_address(pc):
            inst = self.peda.get_disasm(pc)
        else:
            inst = None

        text = blue("[%s]" % "CODE".center(self.width, "-"))
        msg(text)
        if inst:  # valid $PC
            text = self.peda.disassemble_around(pc, count)
            msg(format_disasm_code(text, pc))
        else:  # invalid $PC
            msg("Invalid $PC address: 0x%x" % pc, "red")

    @msg.bufferize
    def context_register(self, *arg):
        """
        Display register information of current execution context
        Usage:
            MYNAME
        """
        if not self._is_running():
            return

        # pc = peda.getpc()
        # display register info
        msg("[%s]" % "REGISTERS".center(self.width, "-"), "blue")
        self.xinfo("register")

    @msg.bufferize
    def context_source(self, *arg):
        """
        Display source information of current execution context
        Usage:
            MYNAME [linecount]
        """
        if not self._is_running():
            return
        (count,) = normalize_argv(arg, 1)
        sal = gdb.selected_frame().find_sal()

        if sal.line == 0:
            return

        if not os.path.exists(sal.symtab.filename) and not os.path.exists(sal.symtab.fullname()):
            return

        line_num = sal.line
        line_str = str(line_num)
        if count is None:
            out = self.peda.execute_redirect('list "%s":%s' % (sal.symtab.fullname(), line_str))
        else:
            out = self.peda.execute_redirect(
                'list "%s":%d,%d' % (sal.symtab.fullname(), line_num - count / 2, line_num + count / 2))
        if not out:
            return

        msg("[%s]" % "SOURCE".center(self.width, "-"), "blue")
        msg('/* source path at %s:%s */' % (sal.symtab.fullname(), line_str))
        for line in out.splitlines()[1:]:
            if line.startswith(line_str):
                msg(line, 'green', 'bold')
            else:
                msg(line)

    @msg.bufferize
    def context_stack(self, *arg):
        """
        Display stack of current execution context
        Usage:
            MYNAME [linecount]
        """
        (count,) = normalize_argv(arg, 1)

        if not self._is_running():
            return

        text = blue("[%s]" % "STACK".center(self.width, "-"))
        msg(text)
        sp = self.peda.getreg("sp")
        if self.peda.is_address(sp):
            self.telescope(sp, count)
        else:
            msg("Invalid $SP address: 0x%x" % sp, "red")

    def context(self, *arg):
        """
        Display various information of current execution context
        Usage:
            MYNAME [reg,source,code,stack,all] [code/stack length]
        """

        (opt, count) = normalize_argv(arg, 2)

        if to_int(count) is None:
            count = 8
        if opt is None:
            opt = config.Option.get("context")
        if opt == "all":
            opt = "register,source,code,stack"

        opt = opt.replace(" ", "").split(",")

        if not opt:
            return

        if not self._is_running():
            return

        self._update_width()

        status = self.peda.get_status()
        need_footer = False

        # display registers
        if "reg" in opt or "register" in opt:
            self.context_register()
            need_footer = True

        # display source
        if 'source' in opt:
            self.context_source(count)
            need_footer = True

        # display assembly code
        if "code" in opt:
            self.context_code(count)
            need_footer = True

        # display stack content, forced in case SIGSEGV
        if "stack" in opt:
            self.context_stack(count)
            need_footer = True

        if need_footer:
            msg('\033[;34m[%s]\033[0m' % ('\033[0m%s\033[;34m' % self.MSG_LEGEND).center(self.width + 40, "-"), "blue")

        # display stopped reason
        if "SIG" in status:
            msg("Stopped reason: %s" % red(status))

    context.options = ['code', 'stack', 'source', 'register']

    def pflush(self, *arg):
        """
            Flush msg buffer if something went wrong.
            Usage:
                MYNAME
        """

        try:
            msg.flush()
        except ValueError:
            info("Buffer is empty")

    #################################
    #   Memory Operation Commands   #
    #################################
    # get_vmmap()
    def vmmap(self, *arg):
        """
        Get virtual mapping address ranges of section(s) in debugged process
        Usage:
            MYNAME [mapname] (e.g binary, all, libc, stack)
            MYNAME address (find mapname contains this address)
            MYNAME (equiv to cat /proc/pid/maps)
        """

        (mapname,) = normalize_argv(arg, 1)
        if not self._is_running():
            maps = self.peda.get_vmmap()
        elif to_int(mapname) is None:
            maps = self.peda.get_vmmap(mapname)
        else:
            addr = to_int(mapname)
            maps = []
            allmaps = self.peda.get_vmmap()
            if allmaps is not None:
                for (start, end, perm, name) in allmaps:
                    if addr >= start and addr < end:
                        maps += [(start, end, perm, name)]

        if maps is not None and len(maps) > 0:
            l = 10 if self.peda.intsize() == 4 else 18
            msg("%s %s %s\t%s" % ("Start".ljust(l, " "), "End".ljust(l, " "), "Perm", "Name"), "blue", "bold")
            for (start, end, perm, name) in maps:
                color = "red" if "rwx" in perm else None
                msg("%s %s %s\t%s" % (to_address(start).ljust(l, " "), to_address(end).ljust(l, " "), perm, name),
                    color)
        else:
            warning("not found or cannot access procfs")

    # writemem()
    def patch(self, *arg):
        """
        Patch memory start at an address with string/hexstring/int
        Usage:
            MYNAME address (multiple lines input)
            MYNAME address "string"
            MYNAME from_address to_address "string"
            MYNAME (will patch at current $pc)
        """

        (address, data, byte) = normalize_argv(arg, 3)
        address = to_int(address)
        end_address = None
        if address is None:
            address = self.peda.getpc()

        if byte is not None and to_int(data) is not None:
            end_address, data = to_int(data), byte
            if end_address < address:
                address, end_address = end_address, address

        if data is None:
            data = ""
            while True:
                line = input("patch> ")
                if line.strip() == "": continue
                if line == "end":
                    break
                user_input = line.strip()
                if user_input.startswith("0x"):
                    data += hex2str(user_input)
                else:
                    data += eval("%s" % user_input)

        if to_int(data) is not None:
            data = hex2str(to_int(data), self.peda.intsize())

        data = to_binary_string(data)
        data = data.replace(b"\\\\", b"\\")
        if end_address:
            data *= (end_address - address + 1) // len(data)
        bytes_ = self.peda.writemem(address, data)
        if bytes_ >= 0:
            info("Written %d bytes to 0x%x" % (bytes_, address))
        else:
            warning("Failed to patch memory, try 'set write on' first for offline patching")

    # dumpmem()
    def dumpmem(self, *arg):
        """
        Dump content of a memory region to raw binary file
        Usage:
            MYNAME file start end
            MYNAME file mapname
        """
        (filename, start, end) = normalize_argv(arg, 3)
        if end is not None and to_int(end):
            if end < start:
                start, end = end, start
            ret = self.peda.execute("dump memory %s 0x%x 0x%x" % (filename, start, end))
            if not ret:
                warning("failed to dump memory")
            else:
                info("Dumped %d bytes to '%s'" % (end - start, filename))
        elif start is not None:  # dump by mapname
            maps = self.peda.get_vmmap(start)
            if maps:
                fd = open(filename, "wb")
                count = 0
                for (start, end, _, _) in maps:
                    mem = self.peda.dumpmem(start, end)
                    if mem is None:  # nullify unreadable memory
                        mem = "\x00" * (end - start)
                    fd.write(mem)
                    count += end - start
                fd.close()
                info("Dumped %d bytes to '%s'" % (count, filename))
            else:
                warning("invalid mapname")
        else:
            self._missing_argument()

    # loadmem()
    def loadmem(self, *arg):
        """
        Load contents of a raw binary file to memory
        Usage:
            MYNAME file address [size]
        """
        mem = ""
        (filename, address, size) = normalize_argv(arg, 3)
        address = to_int(address)
        size = to_int(size)
        if filename is not None:
            try:
                mem = open(filename, "rb").read()
            except:
                pass
            if mem == "":
                error("cannot read data or filename is empty")
                return
            if size is not None and size < len(mem):
                mem = mem[:size]
            bytes = self.peda.writemem(address, mem)
            if bytes > 0:
                info("Written %d bytes to 0x%x" % (bytes, address))
            else:
                warning("failed to load filename to memory")
        else:
            self._missing_argument()

    def writemem(self, *arg):
        """
        Write HEX raw to memory
        Usage:
            MYNAME address RAW
        """
        args = list(arg)
        if len(args) == 1:
            self._missing_argument()

        address = to_int(args[0])
        if address is not None:
            mem = ''.join(args[1:])
            if len(mem) % 2 == 1:
                error("Odd-length hex string")
                return
            mem = codecs.decode(mem, 'hex')
            bytes = self.peda.writemem(address, mem)
            if bytes > 0:
                info("Written %d bytes to 0x%x" % (bytes, address))
            else:
                warning("failed to write raw to memory")
        else:
            self._missing_argument()

    # cmpmem()
    def cmpmem(self, *arg):
        """
        Compare content of a memory region with a file
        Usage:
            MYNAME start end file
        """
        (start, end, filename) = normalize_argv(arg, 3)
        if filename is None:
            self._missing_argument()

        try:
            buf = open(filename, "rb").read()
        except:
            error("cannot read data from filename %s" % filename)
            return

        result = self.peda.cmpmem(start, end, buf)

        if result is None:
            warning("failed to perform comparison")
        elif result == {}:
            msg("mem and filename are identical")
        else:
            msg("--- mem: %s -> %s" % (arg[0], arg[1]), "green", "bold")
            msg("+++ filename: %s" % arg[2], "blue", "bold")
            for (addr, bytes_) in result.items():
                msg("@@ 0x%x @@" % addr, "red")
                line_1 = "- "
                line_2 = "+ "
                for (mem_val, file_val) in bytes_:
                    m_byte = "%02X " % ord(mem_val)
                    f_byte = "%02X " % ord(file_val)
                    if mem_val == file_val:
                        line_1 += m_byte
                        line_2 += f_byte
                    else:
                        line_1 += green(m_byte)
                        line_2 += blue(f_byte)
                msg(line_1)
                msg(line_2)

    # xormem()
    def xormem(self, *arg):
        """
        XOR a memory region with a key
        Usage:
            MYNAME start end key
        """
        (start, end, key) = normalize_argv(arg, 3)
        if key is None:
            self._missing_argument()

        result = self.peda.xormem(start, end, key)
        if result is not None:
            msg("XORed data (first 32 bytes):")
            msg('"' + to_hexstr(result[:32]) + '"')

    # searchmem(), searchmem_by_range()
    def searchmem(self, *arg):
        """
        Search for a pattern in memory; support regex search
        Usage:
            MYNAME pattern start end
            MYNAME pattern mapname
        """
        (pattern, start, end) = normalize_argv(arg, 3)
        (pattern, mapname) = normalize_argv(arg, 2)
        if pattern is None:
            self._missing_argument()

        pattern = arg[0]
        # result = []
        if end is None and to_int(mapname):
            vmrange = self.peda.get_vmrange(mapname)
            if vmrange:
                (start, end, _, _) = vmrange

        if end is None:
            info("Searching for %s in: %s ranges" % (repr(pattern), mapname))
            result = self.peda.searchmem_by_range(mapname, pattern)
        else:
            info("Searching for %s in range: 0x%x - 0x%x" % (repr(pattern), start, end))
            result = self.peda.searchmem(start, end, pattern)

        text = self.peda.format_search_result(result)
        pager(text)

    # search_reference()
    def refsearch(self, *arg):
        """
        Search for all references to a value in memory ranges
        Usage:
            MYNAME value mapname
            MYNAME value (search in all memory ranges)
        """
        (search, mapname) = normalize_argv(arg, 2)
        if search is None:
            self._missing_argument()

        search = arg[0]
        if mapname is None:
            mapname = "all"
        info("Searching for reference to: %s in: %s ranges" % (repr(search), mapname))
        result = self.peda.search_reference(search, mapname)

        text = self.peda.format_search_result(result)
        pager(text)

    # search_address(), search_pointer()
    def lookup(self, *arg):
        """
        Search for all addresses/references to addresses which belong to a memory range
        Usage:
            MYNAME address searchfor belongto
            MYNAME pointer searchfor belongto
        """
        (option, searchfor, belongto) = normalize_argv(arg, 3)
        if option is None:
            self._missing_argument()

        result = []
        if searchfor is None:
            searchfor = "stack"
        if belongto is None:
            belongto = "binary"

        if option == "pointer":
            info("Searching for pointers on: %s pointed to: %s, this may take minutes to complete..." % (
                searchfor, belongto))
            result = self.peda.search_pointer(searchfor, belongto)
        if option == "address":
            info("Searching for addresses on: %s belong to: %s, this may take minutes to complete..." % (
                searchfor, belongto))
            result = self.peda.search_address(searchfor, belongto)

        text = self.peda.format_search_result(result, 0)
        pager(text)

    lookup.options = ["address", "pointer"]

    # examine_mem_reference()
    def telescope(self, *arg):
        """
        Display memory content at an address with smart dereferences
        Usage:
            MYNAME [linecount] (analyze at current $SP)
            MYNAME address [linecount]
        """

        (address, count) = normalize_argv(arg, 2)

        if self._is_running():
            sp = self.peda.getreg("sp")
        else:
            sp = None

        if count is None:
            count = 8
            if address is None:
                address = sp
            elif address < 0x1000:
                count = address
                address = sp

        if not address:
            return

        step = self.peda.intsize()
        if not self.peda.is_address(address):  # cannot determine address
            for i in range(count):
                if not self.peda.execute("x/%sx 0x%x" % ("g" if step == 8 else "w", address + i * step)):
                    break
            return

        result = []
        for i in range(count):
            value = address + i * step
            if self.peda.is_address(value):
                result += [self.peda.examine_mem_reference(value)]
            else:
                result += [None]
        idx = 0
        text = ""
        for chain in result:
            text += "%04d| " % (idx)
            text += format_reference_chain(chain)
            text += "\n"
            idx += step

        pager(text)

    def xinfo(self, *arg):
        """
        Display detail information of address/registers
        Usage:
            MYNAME address
            MYNAME register [reg1 reg2]
        """

        (address, regname) = normalize_argv(arg, 2)
        if address is None:
            self._missing_argument()

        text = ""
        if not self._is_running():
            return

        def get_reg_text(r, v):
            texts = [green("%s" % r.upper().ljust(3)), ": "]
            chain = self.peda.examine_mem_reference(v)
            texts.append(format_reference_chain(chain))
            texts.append("\n")
            return ''.join(texts)

        (arch, bits) = self.peda.getarch()
        if str(address).startswith("r"):
            # Register
            regs = self.peda.getregs(" ".join(arg[1:]))
            texts = []
            if regname is None:
                for r in self.peda.registers[bits]:
                    if r in regs:
                        texts.append(get_reg_text(r, regs[r]))
            else:
                for (r, v) in sorted(regs.items()):
                    texts.append(get_reg_text(r, v))
            text = ''.join(texts)
            if text:
                msg(text.strip())
            return

        elif to_int(address) is None:
            warning("not a register nor an address")
        else:
            # Address
            chain = self.peda.examine_mem_reference(address)
            text += format_reference_chain(chain) + "\n"
            vmrange = self.peda.get_vmrange(address)
            if vmrange:
                (start, end, perm, name) = vmrange
                text += "Virtual memory mapping:\n" \
                        + green("Start : %s\n" % to_address(start)) \
                        + green("End   : %s\n" % to_address(end)) \
                        + yellow("Offset: 0x%x\n" % (address - start)) \
                        + red("Perm  : %s\n" % perm) \
                        + blue("Name  : %s" % name)
        msg(text)

    def strings(self, *arg):
        """
        Display printable strings in memory
        Usage:
            MYNAME start end [minlen]
            MYNAME mapname [minlen]
            MYNAME (display all printable strings in binary - slow)
        """
        (start, end, minlen) = normalize_argv(arg, 3)

        mapname = None
        if start is None:
            mapname = "binary"
        elif to_int(start) is None or (end < start):
            (mapname, minlen) = normalize_argv(arg, 2)

        if minlen is None:
            minlen = 1

        if mapname:
            maps = self.peda.get_vmmap(mapname)
        else:
            maps = [(start, end, None, None)]

        if not maps:
            warning("failed to get memory map for %s" % mapname)
            return

        text = ""
        regex_pattern = "[%s]{%d,}" % (re.escape(string.printable), minlen)
        p = re.compile(regex_pattern.encode('utf-8'))
        for (start, end, _, _) in maps:
            mem = self.peda.dumpmem(start, end)
            if not mem: continue
            found = p.finditer(mem)
            if not found: continue

            for m in found:
                text += "0x%x: %s\n" % (
                    start + m.start(), string_repr(mem[m.start():m.end()].strip(), show_quotes=False))

        pager(text)

    def sgrep(self, *arg):
        """
        Search for full strings contain the given pattern
        Usage:
            MYNAME pattern start end
            MYNAME pattern mapname
            MYNAME pattern
        """
        (pattern,) = normalize_argv(arg, 1)

        if pattern is None:
            self._missing_argument()
        arg = list(arg[1:])
        if not arg:
            arg = ["binary"]

        pattern = "[^\x00]*%s[^\x00]*" % pattern
        self.searchmem(pattern, *arg)

    ###############################
    #   Exploit Helper Commands   #
    ###############################

    # cyclic_pattern()
    def pattern_create(self, *arg):
        """
        Generate a cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME size [file]
        """

        (size, filename) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        pattern = cyclic_pattern(size)
        if filename is not None:
            open(filename, "wb").write(pattern)
            info("Writing pattern of %d chars to filename \"%s\"" % (len(pattern), filename))
        else:
            msg("'" + pattern.decode('utf-8') + "'")

    # cyclic_pattern()
    def pattern_offset(self, *arg):
        """
        Search for offset of a value in cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME value
        """

        (value,) = normalize_argv(arg, 1)
        if value is None:
            self._missing_argument()

        pos = cyclic_pattern_offset(value)
        if pos is None:
            msg("%s not found in pattern buffer" % value)
        else:
            msg("%s found at offset: %d" % (value, pos))

    # cyclic_pattern(), searchmem_*()
    def pattern_search(self, *arg):
        """
        Search a cyclic pattern in registers and memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME
        """

        def nearby_offset(v):
            for offset in range(-128, 128, 4):
                pos = cyclic_pattern_offset(v + offset)
                if pos is not None:
                    return (pos, offset)
            return None

        if not self._is_running():
            return

        reg_result = {}
        regs = self.peda.getregs()

        # search for registers with value in pattern buffer
        for (r, v) in regs.items():
            if len(to_hex(v)) < 8: continue
            res = nearby_offset(v)
            if res:
                reg_result[r] = res

        if reg_result:
            msg("Registers contain pattern buffer:", "red")
            for (r, (p, o)) in reg_result.items():
                msg("%s+%d found at offset: %d" % (r.upper(), o, p))
        else:
            msg("No register contains pattern buffer")

        # search for registers which point to pattern buffer
        reg_result = {}
        for (r, v) in regs.items():
            if not self.peda.is_address(v): continue
            chain = self.peda.examine_mem_reference(v)
            (v, t, vn) = chain[-1]
            if not vn: continue
            o = cyclic_pattern_offset(vn.strip("'").strip('"')[:4])
            if o is not None:
                reg_result[r] = (len(chain), len(vn) - 2, o)

        if reg_result:
            msg("Registers point to pattern buffer:", "yellow")
            for (r, (d, l, o)) in reg_result.items():
                msg("[%s] %s offset %d - size ~%d" % (r.upper(), "-->" * d, o, l))
        else:
            msg("No register points to pattern buffer")

        # search for pattern buffer in memory
        maps = self.peda.get_vmmap()
        search_result = []
        for (start, end, perm, name) in maps:
            if "w" not in perm: continue  # only search in writable memory
            res = cyclic_pattern_search(self.peda.dumpmem(start, end))
            for (a, l, o) in res:
                a += start
                search_result += [(a, l, o)]

        sp = self.peda.getreg("sp")
        if search_result:
            msg("Pattern buffer found at:", "green")
            for (a, l, o) in search_result:
                ranges = self.peda.get_vmrange(a)
                text = "%s : offset %4d - size %4d" % (to_address(a), o, l)
                if ranges[3] == "[stack]":
                    text += " ($sp + %s [%d dwords])" % (to_hex(a - sp), (a - sp) // 4)
                else:
                    text += " (%s)" % ranges[3]
                msg(text)
        else:
            msg("Pattern buffer not found in memory")

        # search for references to pattern buffer in memory
        ref_result = []
        for (a, l, o) in search_result:
            res = self.peda.searchmem_by_range("all", "0x%x" % a)
            ref_result += [(x[0], a) for x in res]
        if len(ref_result) > 0:
            msg("References to pattern buffer found at:", "blue")
            for (a, v) in ref_result:
                ranges = self.peda.get_vmrange(a)
                text = "%s : %s" % (to_address(a), to_address(v))
                if ranges[3] == "[stack]":
                    text += " ($sp + %s [%d dwords])" % (to_hex(a - sp), (a - sp) // 4)
                else:
                    text += " (%s)" % ranges[3]
                msg(text)
        else:
            msg("Reference to pattern buffer not found in memory")

    # cyclic_pattern(), writemem()
    def pattern_patch(self, *arg):
        """
        Write a cyclic pattern to memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME address size
        """

        (address, size) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        pattern = cyclic_pattern(size)
        num_bytes_written = self.peda.writemem(address, pattern)
        if num_bytes_written:
            info("Written %d chars of cyclic pattern to 0x%x" % (size, address))
        else:
            warning("Failed to write to memory")

    # cyclic_pattern()
    def pattern_arg(self, *arg):
        """
        Set argument list with cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME size1 [size2,offset2] ...
        """

        if not arg:
            self._missing_argument()

        arglist = []
        for a in arg:
            (size, offset) = (a + ",").split(",")[:2]
            if offset:
                offset = to_int(offset)
            else:
                offset = 0
            size = to_int(size)
            if size is None or offset is None:
                self._missing_argument()

            # try to generate unique, non-overlapped patterns
            if arglist and offset == 0:
                offset = sum(arglist[-1])
            arglist += [(size, offset)]

        patterns = []
        for (s, o) in arglist:
            patterns += ["\'%s\'" % cyclic_pattern(s, o).decode('utf-8')]
        self.peda.execute("set arg %s" % " ".join(patterns))
        info("Set %d arguments to program" % len(patterns))

    # cyclic_pattern()
    def pattern_env(self, *arg):
        """
        Set environment variable with a cyclic pattern
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME ENVNAME size[,offset]
        """

        (env, size) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        (size, offset) = (arg[1] + ",").split(",")[:2]
        size = to_int(size)
        if offset:
            offset = to_int(offset)
        else:
            offset = 0
        if size is None or offset is None:
            self._missing_argument()

        self.peda.execute("set env %s %s" % (env, cyclic_pattern(size, offset).decode('utf-8')))
        info("Set environment %s = cyclic_pattern(%d, %d)" % (env, size, offset))

    def pattern(self, *arg):
        """
        Generate, search, or write a cyclic pattern to memory
        Set "pattern" option for basic/extended pattern type
        Usage:
            MYNAME create size [file]
            MYNAME offset value
            MYNAME search
            MYNAME patch address size
            MYNAME arg size1 [size2,offset2]
            MYNAME env size[,offset]
        """

        options = ["create", "offset", "search", "patch", "arg", "env"]
        (opt,) = normalize_argv(arg, 1)
        if opt is None or opt not in options:
            self._missing_argument()

        func = getattr(self, "pattern_%s" % opt)
        func(*arg[1:])

    pattern.options = ["create", "offset", "search", "patch", "arg", "env"]

    def substr(self, *arg):
        """
        Search for substrings of a given string/number in memory
        Commonly used for ret2strcpy ROP exploit
        Usage:
            MYNAME "string" start end
            MYNAME "string" [mapname] (default is search in current binary)
        """
        (search, start, end) = normalize_argv(arg, 3)
        if search is None:
            self._missing_argument()

        result = []
        search = arg[0]
        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start

        if mapname:
            info("Searching for sub strings of: %s in: %s ranges" % (repr(search), mapname))
            maps = self.peda.get_vmmap(mapname)
            for (start, end, perm, _) in maps:
                if perm == "---p":  # skip private range
                    continue
                result = self.peda.search_substr(start, end, search)
                if result:  # return the first found result
                    break
        else:
            info("Searching for sub strings of: %s in range: 0x%x - 0x%x" % (repr(search), start, end))
            result = self.peda.search_substr(start, end, search)

        if result:
            msg("# (address, target_offset), # value (address=0xffffffff means not found)")
            offset = 0
            for (k, v) in result:
                msg("(0x%x, %d), # %s" % ((0xffffffff if v == -1 else v), offset, string_repr(k)))
                offset += len(k)
        else:
            info("Not found")

    def snapshot(self, *arg):
        """
        Save/restore process's snapshot to/from file
        Usage:
            MYNAME save file
            MYNAME restore file
        Warning: this is not thread safe, do not use with multithread program
        """
        options = ["save", "restore"]
        (opt, filename) = normalize_argv(arg, 2)
        if opt not in options:
            self._missing_argument()

        if not filename:
            filename = self.peda.get_config_filename("snapshot")

        if opt == "save":
            if self.peda.save_snapshot(filename):
                msg("Saved process's snapshot to filename '%s'" % filename)
            else:
                msg("Failed to save process's snapshot")

        if opt == "restore":
            if self.peda.restore_snapshot(filename):
                msg("Restored process's snapshot from filename '%s'" % filename)
                self.peda.execute("stop")
            else:
                msg("Failed to restore process's snapshot")

        return

    snapshot.options = ["save", "restore"]

    def crashdump(self, *arg):
        """
        Display crashdump info and save to file
        Usage:
            MYNAME [reason_text]
        """
        (reason,) = normalize_argv(arg, 1)
        if not reason:
            reason = "Interactive dump"

        logname = self.peda.get_config_filename("crashlog")
        logfd = open(logname, "a")
        config.Option.set("_teefd", logfd)
        msg("[%s]" % "START OF CRASH DUMP".center(self.width, "-"))
        msg("Timestamp: %s" % time.ctime())
        msg("Reason: %s" % red(reason))

        # exploitability
        pc = self.peda.getpc()
        if not self.peda.is_address(pc):
            exp = red("EXPLOITABLE")
        else:
            exp = "Unknown"
        msg("Exploitability: %s" % exp)

        # registers, code, stack
        self.context_register()
        self.context_code(16)
        self.context_stack()

        # backtrace
        msg("[%s]" % "backtrace (innermost 10 frames)".center(self.width, "-"), "blue")
        msg(self.peda.execute_redirect("backtrace 10"))

        msg("[%s]\n" % "END OF CRASH DUMP".center(self.width, "-"))
        config.Option.set("_teefd", "")
        logfd.close()

    def utils(self, *arg):
        """
        Miscelaneous utilities from utils module
        Usage:
            MYNAME command arg
        """
        (command, carg) = normalize_argv(arg, 2)
        # todo maybe add? mention below
        cmds = ["int2hexstr", "list2hexstr", "str2intlist"]
        if not command or command not in cmds or not carg:
            self._missing_argument()

        func = globals()[command]
        result = ''
        if command == "int2hexstr":
            if to_int(carg) is None:
                msg("Not a number")
                return
            result = func(to_int(carg))
            result = to_hexstr(result)

        elif command == "list2hexstr":
            if to_int(carg) is not None:
                msg("Not a list")
                return
            result = func(eval("%s" % carg))
            result = to_hexstr(result)

        elif command == "str2intlist":
            res = func(carg)
            result = "["
            for v in res:
                result += "%s, " % to_hex(v)
            result = result.rstrip(", ") + "]"

        msg(result)

    utils.options = ["int2hexstr", "list2hexstr", "str2intlist"]

    ####################################
    #           Plugins support        #
    ####################################
    def plugin(self, *arg):
        """
        List or Load plugins.
        Usage:
            MYNAME [name] [reload]
        """
        (name, opt) = normalize_argv(arg, 2)
        if name is None:
            msg('Available plugins:', 'blue')
            files = []
            self.plugin.__func__.options = []
            for f in os.listdir(os.path.dirname(self.pedafile) + "/plugins/"):
                if f.endswith('-plugin.py'):
                    tmp = f[:-10]
                    self.plugin.__func__.options.append(tmp)
                    files.append(green(tmp) + red('*') if tmp in self.plugins else tmp)
            msg('\t'.join(files))
        elif name in self.plugins:
            if not opt or not str(opt).startswith('r'):
                warning('Plugin %s already loaded!' % name)
                warning('Please use "plugin %s reload" to force reload.)' % name)
                return
            info('Plugin %s is reloading.' % name)
            m = reload_plugin('%s-plugin' % name)
            if m is None or not hasattr(m, 'invoke') or not callable(getattr(m, 'invoke')):
                error('Reload plugin failed. Please check the plugin file or restart gdb.')
                return
            func = getattr(m, 'invoke')
            self.plugins[name] = func
            info('Plugin %s reloaded.' % name)
        else:
            if not os.path.exists(os.path.dirname(self.pedafile) + "/plugins/%s-plugin.py" % name):
                error('Plugin %s does not Exist!!' % name)
                return
            m = import_plugin('%s-plugin' % name)
            if not hasattr(m, 'invoke') or not callable(getattr(m, 'invoke')):
                error('Not a valid plugin file!')
                return
            func = getattr(m, 'invoke')
            self.plugins[name] = func
            PluginCommand(self.peda, self, name)
            info('Plugin %s loaded.' % name)
            info('Plugin doc:\n%s' % func.__doc__.strip('\n'))

    plugin.options = [i[:-10] for i in os.listdir(os.path.dirname(__file__) + "/../plugins/") if
                      i.endswith('-plugin.py')]

    def _alias(self, alias, command, shorttext=True):
        return PEDACmdAlias(self, alias, command, shorttext)


###########################################################################
class PluginCommand(gdb.Command):
    """
    Wrapper of gdb.Command for added plugins.
    """

    def __init__(self, peda, pedacmd, name):
        self.peda = peda
        self.pedacmd = pedacmd
        self.name = name
        func = self.pedacmd.plugins.get(self.name)
        self.__doc__ = func.__doc__.strip('\n')
        super(PluginCommand, self).__init__(self.name, gdb.COMMAND_NONE)

    def invoke(self, arg_string, from_tty):
        self.dont_repeat()
        arg = self.peda.string_to_argv(arg_string)
        func = self.pedacmd.plugins.get(self.name)
        if func is None:
            self.pedacmd.plugins[self.name] = None
            self.peda.execute('peda plugin %s reload' % self.name)
            func = self.pedacmd.plugins.get(self.name)
        try:
            reset_cache(sys.modules['__main__'])
            func(self.peda, *arg)
        except Exception as e:
            if config.Option.get("debug") == "on":
                msg("Exception: %s" % e)
                traceback.print_exc()
            gdb.execute('peda pflush')
            self.peda.restore_user_command("all")
            msg(self.__doc__, 'green')

    def complete(self, text, word):
        func = self.pedacmd.plugins.get(self.name)
        options = func.options if hasattr(func, 'options') else []
        opname = [x for x in options if x.startswith(text.strip())]
        if opname:
            return opname
        else:
            return []


###########################################################################
class pedaGDBCommand(gdb.Command):
    """
    Wrapper of gdb.Command for master "peda" command
    """

    def __init__(self, peda, pedacmd, cmdname="peda"):
        self.peda = peda
        self.pedacmd = pedacmd
        self.cmdname = cmdname
        self.__doc__ = pedacmd._get_helptext()
        super(pedaGDBCommand, self).__init__(self.cmdname, gdb.COMMAND_DATA)

    def invoke(self, arg_string, from_tty):
        # do not repeat command
        self.dont_repeat()
        arg = self.peda.string_to_argv(arg_string)
        if len(arg) < 1:
            self.pedacmd.help()
        else:
            cmd = arg[0]
            if cmd in self.pedacmd.commands:
                func = getattr(self.pedacmd, cmd)
                try:
                    # reset memoized cache
                    reset_cache(sys.modules['__main__'])
                    func(*arg[1:])
                except Exception as e:
                    if config.Option.get("debug") == "on":
                        msg("Exception: %s" % e)
                        traceback.print_exc()
                    gdb.execute('peda pflush')
                    self.peda.restore_user_command("all")
                    self.pedacmd.help(cmd)
            else:
                warning('Undefined command: %s. Try "peda help"' % cmd)

    def complete(self, text, word):
        completion = []
        if text != "":
            cmd = text.split()[0]
            if cmd in self.pedacmd.commands:
                func = getattr(self.pedacmd, cmd)
                for opt in func.options:
                    if word in opt:
                        completion += [opt]
            else:
                for cmd in self.pedacmd.commands:
                    if cmd.startswith(text.strip()):
                        completion += [cmd]
        else:
            for cmd in self.pedacmd.commands:
                if word in cmd and cmd not in completion:
                    completion += [cmd]
        return completion


class PEDACmdAlias(gdb.Command):
    """ Alias for peda, so you need to pass peda and pedacmd"""

    def __init__(self, pedacmd, alias, command, shorttext=False):
        """ command should not involve 'peda' """
        self.pedacmd = pedacmd
        cmd = command.split()[0]
        if cmd == 'peda':
            raise Exception('command should not involve "peda"')
        if not shorttext:
            self.__doc__ = pedacmd._get_helptext(cmd)
        else:
            self.__doc__ = green("Alias for 'peda %s'" % command)
        self._command = command
        self._alias = alias
        super(PEDACmdAlias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("peda %s %s" % (self._command, args))

    def complete(self, text, word):
        completion = []
        cmds = self._command.split()
        cmd = cmds[0]
        for opt in getattr(self.pedacmd, cmd).options:  # list of command's options
            if text in opt and opt not in completion:
                completion.append(opt)
        if completion:
            return completion
        if cmd in ["set", "show"] and text.split()[0] in ["option"]:
            opname = [x for x in config.OPTIONS.keys() if x.startswith(word.strip())]
            if opname:
                completion = opname
            else:
                completion = list(config.OPTIONS.keys())
        return completion


class Alias(gdb.Command):
    """
    Generic alias, create short command names
    This doc should be changed dynamically
    """

    def __init__(self, alias, command, shorttext=True):
        self.__doc__ = green("Alias for '%s'" % command)
        self._command = command
        self._alias = alias
        super(Alias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" % (self._command, args))


# common used shell commands aliases
shellcmds = ["man", "ls", "ps", "grep", "cat", "more", "less", "pkill", "clear", "vi", 'vim', "nano"]
for cmd in shellcmds:
    Alias(cmd, "shell %s" % cmd)

# misc gdb settings
PEDA.execute("set confirm off")
PEDA.execute("set verbose off")
PEDA.execute("set output-radix 0x10")
PEDA.execute("set history expansion on")
PEDA.execute("set history save on")  # enable history saving
PEDA.execute("set follow-fork-mode child")
PEDA.execute("set backtrace past-main on")
PEDA.execute("set step-mode on")
PEDA.execute("set print pretty on")
PEDA.execute("handle SIGALRM print nopass")  # ignore SIGALRM
PEDA.execute("handle SIGSEGV stop print nopass")  # catch SIGSEGV
PEDA.execute('set pagination off')  # disable paging
