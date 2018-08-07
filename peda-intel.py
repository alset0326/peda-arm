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

import os
import random
import sys

# point to absolute path of peda.py
PEDAFILE = os.path.abspath(os.path.expanduser(__file__))
while os.path.islink(PEDAFILE):
    PEDAFILE = os.readlink(PEDAFILE)
sys.path.insert(0, os.path.dirname(PEDAFILE))

from peda import *
from peda.intel.skeleton import *
from peda.intel.shellcode import *

try:
    import zlib
except ImportError:
    zlib = None

__version__ = 'alpha-1.0'


class Nasm(AsmBase):
    """
    Wrapper class for assemble/disassemble using nasm/ndisassm
    """
    READELF = "/usr/bin/readelf"
    OBJDUMP = "/usr/bin/objdump"
    NASM = "/usr/bin/nasm"
    NDISASM = "/usr/bin/ndisasm"

    @staticmethod
    def assemble(asmcode, mode=32):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
            - mode: 16/32/64 bits assembly

        Returns:
            - bin code (raw bytes)
        """
        asmcode = asmcode.strip('"').strip("'")
        asmcode = asmcode.replace(";", "\n")
        asmcode = ("BITS %d\n" % mode) + asmcode
        asmcode = decode_string_escape(asmcode)
        asmcode = re.sub("PTR|ptr|ds:|DS:", "", asmcode)
        infd = tmpfile()
        outfd = tmpfile(is_binary_file=True)
        infd.write(asmcode)
        infd.flush()
        execute_external_command("%s -f bin -o %s %s" % (Nasm.NASM, outfd.name, infd.name))
        infd.close()

        if os.path.exists(outfd.name):
            bincode = outfd.read()
            outfd.close()
            return bincode
        # reopen it so tempfile will not complain
        open(outfd.name, 'w').write('B00B')
        return None

    @staticmethod
    def disassemble(buf, mode=32):
        """
        Disassemble binary to ASM instructions using NASM
            - buf: input binary (raw bytes)
            - mode: 16/32/64 bits assembly

        Returns:
            - ASM code (String)
        """
        out = execute_external_command("%s -b %d -" % (Nasm.NDISASM, mode), buf)
        return out

    @staticmethod
    def format_shellcode(buf, mode=32):
        """
        Format raw shellcode to ndisasm output display
            "\x6a\x01"  # 0x00000000:    push byte +0x1
            "\x5b"      # 0x00000002:    pop ebx

        TODO: understand syscall numbers, socket call
        """

        def nasm2shellcode(asmcode):
            if not asmcode:
                return ""

            shellcode = []
            pattern = re.compile("([0-9A-F]{8})\s*([^\s]*)\s*(.*)")

            # matches = pattern.findall(asmcode)
            for line in asmcode.splitlines():
                m = pattern.match(line)
                if m:
                    (addr, bytes, code) = m.groups()
                    sc = '"0x%s"' % bytes
                    shellcode += [(sc, "0x" + addr, code.strip())]

            maxlen = max([len(x[0]) for x in shellcode])
            text = ""
            for (sc, addr, code) in shellcode:
                text += "%s # %s:    %s\n" % (sc.ljust(maxlen + 1), addr, code)

            return text

        out = execute_external_command("%s -b %d -" % (Nasm.NDISASM, mode), buf)
        return nasm2shellcode(out)

    def objdump_disasm_search(self, name, search):
        return execute_external_command(
            "%s -M intel -z --prefix-address -d '%s' | grep '%s'" % (self.OBJDUMP, name, search))


# Define registers

REGISTERS = {
    8: ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
    16: ["ax", "bx", "cx", "dx"],
    32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
    64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
}

EFLAGS = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]
EFLAGS_TEXT = ["carry", "parity", "adjust", "zero", "sign", "trap", "interrupt", "direction", "overflow"]
EFLAGS_CF = 1 << 0
EFLAGS_PF = 1 << 2
EFLAGS_AF = 1 << 4
EFLAGS_ZF = 1 << 6
EFLAGS_SF = 1 << 7
EFLAGS_TF = 1 << 8
EFLAGS_IF = 1 << 9
EFLAGS_DF = 1 << 10
EFLAGS_OF = 1 << 11
EFLAGS_INDEX = [EFLAGS_CF, EFLAGS_PF, EFLAGS_AF, EFLAGS_ZF, EFLAGS_SF, EFLAGS_TF, EFLAGS_IF, EFLAGS_DF, EFLAGS_OF, ]

MSG_LEGEND = "Legend: %s, %s, %s, value" % (red("code"), blue("data"), green("rodata"))


###########################################################################
class IntelPEDACmd(PEDACmd):
    def pltbreak(self, *arg):
        """
        Set breakpoint at PLT functions match name regex
        Usage:
            MYNAME [name]
        """
        (name,) = normalize_argv(arg, 1)
        if not name:
            name = ""
        headers = self.peda.elfheader()
        end = headers[".bss"]
        symbols = self.peda.elfsymbol(name)
        if len(symbols) == 0:
            warning("File not specified or PLT symbols not found")
            return
        else:
            # Traverse symbols in order to have more predictable output
            for symname in sorted(symbols):
                if "plt" not in symname: continue
                if name in symname:  # fixme(longld) bounds checking?
                    line = self.peda.set_breakpoint_redirect(symname)
                    msg("%s (%s)" % (line.strip("\n"), symname))

    def deactive(self, *arg):
        """
        Bypass a function by ignoring its execution (eg sleep/alarm)
        Usage:
            MYNAME function
            MYNAME function del (re-active)
        """
        (function, action) = normalize_argv(arg, 2)
        if function is None:
            self._missing_argument()

        if to_int(function):
            function = "0x%x" % function

        bnum = "$deactive_%s_bnum" % function
        if action and "del" in action:
            self.peda.execute("delete %s" % bnum)
            self.peda.execute("set %s = \"void\"" % bnum)
            msg("'%s' re-activated" % function)
            return

        if "void" not in self.peda.execute_redirect("p %s" % bnum):
            out = self.peda.execute_redirect("info breakpoints %s" % bnum)
            if out:
                msg("Already deactivated '%s'" % function)
                msg(out)
                return
            else:
                self.peda.execute("set %s = \"void\"" % bnum)

        (arch, bits) = self.peda.getarch()
        if not function.startswith("0x"):  # named function
            symbol = self.peda.elfsymbol(function)
            if not symbol:
                warning("cannot retrieve info of function '%s'" % function)
                return
            self.peda.set_breakpoint("*0x%x" % symbol[function + "@plt"])

        else:  # addressed function
            self.peda.set_breakpoint("*%s" % function)

        self.peda.execute("set %s = $bpnum" % bnum)
        tmpfd = tmpfile()
        if "i386" in arch:
            tmpfd.write("\n".join([
                "commands $bpnum",
                "silent",
                "set $eax = 0",
                "return",
                "continue",
                "end"]))
        if "64" in arch:
            tmpfd.write("\n".join([
                "commands $bpnum",
                "silent",
                "set $rax = 0",
                "return",
                "continue",
                "end"]))
        tmpfd.flush()
        self.peda.execute("source %s" % tmpfd.name)
        tmpfd.close()
        out = self.peda.execute_redirect("info breakpoints %s" % bnum)
        if out:
            msg("'%s' deactivated" % function)
            msg(out)

    def unptrace(self, *arg):
        """
        Disable anti-ptrace detection
        Usage:
            MYNAME
            MYNAME del
        """
        (action,) = normalize_argv(arg, 1)

        self.deactive("ptrace", action)

        if not action and "void" in self.peda.execute_redirect("p $deactive_ptrace_bnum"):
            # cannot deactive vi plt entry, try syscall method
            info("Try to patch 'ptrace' via syscall")
            self.peda.execute("catch syscall ptrace")
            self.peda.execute("set $deactive_ptrace_bnum = $bpnum")
            tmpfd = tmpfile()
            (arch, bits) = self.peda.getarch()
            if "i386" in arch:
                tmpfd.write("\n".join([
                    "commands $bpnum",
                    "silent",
                    "if (*(int*)($esp+4) == 0 || $ebx == 0)",
                    "    set $eax = 0",
                    "end",
                    "continue",
                    "end"]))
            if "64" in arch:
                tmpfd.write("\n".join([
                    "commands $bpnum",
                    "silent",
                    "if ($rdi == 0)",
                    "    set $rax = 0",
                    "end",
                    "continue",
                    "end"]))
            tmpfd.flush()
            self.peda.execute("source %s" % tmpfd.name)
            tmpfd.close()
            out = self.peda.execute_redirect("info breakpoints $deactive_ptrace_bnum")
            if out:
                msg("'ptrace' deactivated")
                msg(out)

    def _get_function_args_32(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - i386
        """
        if not argc:
            argc = 0
            p = re.compile(".*mov.*\[esp(.*)\],")
            matches = p.findall(code)
            if matches:
                l = len(matches)
                for v in matches:
                    if v.startswith("+"):
                        offset = to_int(v[1:])
                        if offset is not None and (offset // 4) > l:
                            continue
                    argc += 1
            else:  # try with push style
                argc = code.count("push")

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = []
        sp = self.peda.getreg("sp")
        mem = self.peda.dumpmem(sp, sp + 4 * argc)
        for i in range(argc):
            args += [struct.unpack("<L", mem[i * 4:(i + 1) * 4])[0]]

        return args

    def _get_function_args_64(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - x86_64
        """

        # just retrieve max 6 args
        arg_order = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

        if not argc:
            p = re.compile(":\s*([^ ]*)\s*(.*),")
            matches = p.findall(code)
            regs = [r for (_, r) in matches]
            p = re.compile("di|si|dx|cx|r8|r9")
            m = p.findall(" ".join(regs))
            m = list(set(m))  # uniqify
            argc = 0
            if "si" in m and "di" not in m:  # dirty fix
                argc += 1
            argc += m.count("di")
            if argc > 0:
                argc += m.count("si")
            if argc > 1:
                argc += m.count("dx")
            if argc > 2:
                argc += m.count("cx")
            if argc > 3:
                argc += m.count("r8")
            if argc > 4:
                argc += m.count("r9")

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = []
        regs = self.peda.getregs()
        for i in range(argc):
            args += [regs[arg_order[i]]]

        return args

    def _get_function_args(self, argc=None):
        """
        Get the guessed arguments passed to a function when stopped at a call instruction

        Args:
            - argc: force to get specific number of arguments (Int)

        Returns:
            - list of arguments (List)
        """

        args = []
        regs = self.peda.getregs()
        if regs is None:
            return []

        (arch, bits) = self.peda.getarch()

        code = ""
        if argc is None:
            pc = self.peda.getreg("pc")
            prev_insts = self.peda.prev_inst(pc, 12)
            if not prev_insts:
                return []
            for (addr, inst) in prev_insts[::-1]:
                if "call" in inst.strip().split()[0]:
                    break
                code = "0x%x:%s\n" % (addr, inst) + code

        if "i386" in arch:
            args = self._get_function_args_32(code, argc)
        if "64" in arch:
            args = self._get_function_args_64(code, argc)

        return args

    # get_function_args()
    def dumpargs(self, *arg):
        """
        Display arguments passed to a function when stopped at a call instruction
        Usage:
            MYNAME [count]
                count: force to display "count args" instead of guessing
        """

        (count,) = normalize_argv(arg, 1)
        if not self._is_running():
            return

        args = self._get_function_args(count)
        if args:
            msg("Guessed arguments:")
            for (i, a) in enumerate(args):
                chain = self.peda.examine_mem_reference(a)
                msg("arg[%d]: %s" % (i, format_reference_chain(chain)))
        else:
            msg("No argument")

    def start(self, *arg):
        """
        Start debugged program and stop at most convenient entry
        Usage:
            MYNAME
        """
        entries = ["main"]
        main_addr = self.peda.main_entry()
        if main_addr:
            entries += ["*0x%x" % main_addr]
        entries += ["__libc_start_main@plt"]
        entries += ["_start"]
        entries += ["_init"]

        started = 0
        for e in entries:
            out = self.peda.execute_redirect("tbreak %s" % e)
            if out and "breakpoint" in out:
                self.peda.execute("run %s" % ' '.join(arg))
                started = 1
                break

        if not started:  # try ELF entry point or just "run" as the last resort
            elf_entry = self.peda.elfentry()
            if elf_entry:
                out = self.peda.execute_redirect("tbreak *%s" % elf_entry)

            self.peda.execute("run")

    # wrapper for stepuntil("call")
    def nextcall(self, *arg):
        """
        Step until next 'call' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(arg, 2)

        if keyword:
            self.stepuntil("call.*%s" % keyword, mapname)
        else:
            self.stepuntil("call", mapname)

    # wrapper for stepuntil("j")
    def nextjmp(self, *arg):
        """
        Step until next 'j*' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(arg, 2)

        if keyword:
            self.stepuntil("j.*%s" % keyword, mapname)
        else:
            self.stepuntil("j", mapname)

    # stepuntil()
    def tracecall(self, *arg):
        """
        Trace function calls made by the program
        Usage:
            MYNAME ["func1,func2"] [mapname1,mapname2]
            MYNAME ["-func1,func2"] [mapname1,mapname2] (inverse)
                default is to trace internal calls made by the program
        """
        (funcs, mapname) = normalize_argv(arg, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = "binary"

        fnames = [""]
        if funcs:
            if to_int(funcs):
                funcs = "0x%x" % funcs
            fnames = funcs.replace(",", " ").split()
        for (idx, fn) in enumerate(fnames):
            if to_int(fn):
                fnames[idx] = "0x%x" % to_int(fn)

        inverse = 0
        for (idx, fn) in enumerate(fnames):
            if fn.startswith("-"):  # inverse trace
                fnames[idx] = fn[1:]
                inverse = 1

        binname = self.peda.getfile()
        logname = self.peda.get_config_filename("tracelog")

        if mapname is None:
            mapname = binname

        self.peda.save_user_command("hook-stop")  # disable hook-stop to speedup
        info("Tracing calls %s '%s', Ctrl-C to stop..." % ("match" if not inverse else "not match", ",".join(fnames)))
        prev_depth = self.peda.backtrace_depth(peda.getreg("sp"))

        logfd = open(logname, "w")
        while True:
            result = self.peda.stepuntil("call", mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith("=>"):
                break

            if not inverse:
                matched = False
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(":\t")[-1]):
                        matched = True
                        break
            else:
                matched = True
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(":\t")[-1]):
                        matched = False
                        break

            if matched:
                code = format_disasm_code(code)
                msg("%s%s%s" % (" " * (prev_depth - 1), " dep:%02d " % (prev_depth - 1), colorize(code.strip())),
                    teefd=logfd)
                args = self.peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = self.peda.examine_mem_reference(a)
                        text = "%s        |-- arg[%d]: %s" % (" " * (prev_depth - 1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

        msg(code, "red")
        self.peda.restore_user_command("hook-stop")
        if "STOP" not in self.peda.get_status():
            self.peda.execute("stop")
        logfd.close()
        info("Saved trace information in file %s, view with 'less -r file'" % logname)

    # stepuntil()
    def traceinst(self, *arg):
        """
        Trace specific instructions executed by the program
        Usage:
            MYNAME ["inst1,inst2"] [mapname1,mapname2]
            MYNAME count (trace execution of next count instrcutions)
                default is to trace instructions inside the program
        """
        (insts, mapname) = normalize_argv(arg, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = "binary"

        instlist = [".*"]
        count = -1
        if insts:
            if to_int(insts):
                count = insts
            else:
                instlist = insts.replace(",", " ").split()

        binname = self.peda.getfile()
        logname = self.peda.get_config_filename("tracelog")

        if mapname is None:
            mapname = binname

        self.peda.save_user_command("hook-stop")  # disable hook-stop to speedup
        info("Tracing instructions match '%s', Ctrl-C to stop..." % (",".join(instlist)))
        prev_depth = self.peda.backtrace_depth(peda.getreg("sp"))
        logfd = open(logname, "w")

        p = re.compile(".*?:\s*[^ ]*\s*([^,]*),(.*)")
        while count:
            result = self.peda.stepuntil(",".join(instlist), mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith("=>"):
                break

            # special case for JUMP inst
            prev_code = ""
            if re.search("j[^m]", code.split(":\t")[-1].split()[0]):
                prev_insts = self.peda.prev_inst(peda.getpc())
                if prev_insts:
                    prev_code = "0x%x:%s" % prev_insts[0]
                    msg("%s%s%s" % (" " * (prev_depth - 1), " dep:%02d    " % (prev_depth - 1), prev_code), teefd=logfd)

            text = "%s%s%s" % (" " * (prev_depth - 1), " dep:%02d " % (prev_depth - 1), code.strip())
            msg(text, teefd=logfd)

            if re.search("call", code.split(":\t")[-1].split()[0]):
                args = self.peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = self.peda.examine_mem_reference(a)
                        text = "%s        |-- arg[%d]: %s" % (" " * (prev_depth - 1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

            # get registers info if any
            (arch, bits) = self.peda.getarch()
            code = code.split("#")[0].strip("=>")
            if prev_code:
                m = p.search(prev_code)
            else:
                m = p.search(code)

            if m:
                for op in m.groups():
                    if op.startswith("0x"): continue
                    v = to_int(peda.parse_and_eval(op))
                    chain = self.peda.examine_mem_reference(v)
                    text = "%s        |-- %03s: %s" % (" " * (prev_depth - 1), op, format_reference_chain(chain))
                    msg(text, teefd=logfd)

            count -= 1

        msg(code, "red")
        self.peda.restore_user_command("hook-stop")
        logfd.close()
        info("Saved trace information in file %s, view with 'less -r file'" % logname)

    def _testjump(self, inst=None):
        """
        Test if jump instruction is taken or not

        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self._get_eflags()
        if not flags:
            return None

        if not inst:
            pc = self.peda.getpc()
            inst = self.peda.execute_redirect("x/i 0x%x" % pc)
            if not inst:
                return None

        opcode = inst.split(":\t")[-1].split()[0]
        next_addr = self.peda.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        if opcode == "jmp":
            return next_addr
        elif opcode == "je" and flags["ZF"]:
            return next_addr
        elif opcode == "jne" and not flags["ZF"]:
            return next_addr
        elif opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
            return next_addr
        elif opcode == "jge" and (flags["SF"] == flags["OF"]):
            return next_addr
        elif opcode == "ja" and not flags["CF"] and not flags["ZF"]:
            return next_addr
        elif opcode == "jae" and not flags["CF"]:
            return next_addr
        elif opcode == "jl" and (flags["SF"] != flags["OF"]):
            return next_addr
        elif opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
            return next_addr
        elif opcode == "jb" and flags["CF"]:
            return next_addr
        elif opcode == "jbe" and (flags["CF"] or flags["ZF"]):
            return next_addr
        elif opcode == "jo" and flags["OF"]:
            return next_addr
        elif opcode == "jno" and not flags["OF"]:
            return next_addr
        elif opcode == "jz" and flags["ZF"]:
            return next_addr
        elif opcode == "jnz" and flags["OF"]:
            return next_addr

        return None

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
            text = ""
            opcode = inst.split(":\t")[-1].split()[0]
            # stopped at function call
            if "call" in opcode:
                text += self.peda.disassemble_around(pc, count)
                msg(format_disasm_code(text, pc))
                self.dumpargs()
            # stopped at jump
            elif "j" in opcode:
                jumpto = self._testjump(inst)
                if jumpto:  # JUMP is taken
                    code = self.peda.disassemble_around(pc, count)
                    code = code.splitlines()
                    pc_idx = 999
                    for (idx, line) in enumerate(code):
                        if ("0x%x" % pc) in line.split(":")[0]:
                            pc_idx = idx
                        if idx <= pc_idx:
                            text += line + "\n"
                        else:
                            text += " | %s\n" % line.strip()
                    text = format_disasm_code(text, pc) + "\n"
                    text += " |->"
                    code = self.peda.get_disasm(jumpto, count // 2)
                    if not code:
                        code = "   Cannot evaluate jump destination\n"

                    code = code.splitlines()
                    text += red(code[0]) + "\n"
                    for line in code[1:]:
                        text += "       %s\n" % line.strip()
                    text += red("JUMP is taken".rjust(79))
                else:  # JUMP is NOT taken
                    text += format_disasm_code(peda.disassemble_around(pc, count), pc)
                    text += "\n" + green("JUMP is NOT taken".rjust(79))

                msg(text.rstrip())
            # stopped at other instructions
            else:
                text += self.peda.disassemble_around(pc, count)
                msg(format_disasm_code(text, pc))
        else:  # invalid $PC
            msg("Invalid $PC address: 0x%x" % pc, "red")

    def _get_eflags(self):
        """
        Get flags value from EFLAGS register

        Returns:
            - dictionary of named flags
        """
        eflags = self.peda.getreg("eflags")
        if not eflags:
            return None
        flags = {}
        for i in range(len(EFLAGS)):
            flags[EFLAGS[i]] = bool(eflags & EFLAGS_INDEX[i])

        return flags

    def _set_eflags(self, flagname, value):
        """
        Set/clear/toggle value of a flag register

        Returns:
            - True if success (Bool)
        """

        # Eflags bit masks, source vdb
        eflags = self.peda.get_eflags()
        if not eflags:
            return False

        if flagname.upper() in EFLAGS:
            index = EFLAGS.index(flagname.upper())
        elif flagname.lower() in EFLAGS_TEXT:
            index = EFLAGS_TEXT.index(flagname.lower())
        else:
            return False

        if value is None or eflags[EFLAGS[index]] != value:  # switch value
            reg_eflags = self.peda.getreg("eflags")
            reg_eflags ^= EFLAGS_INDEX[index]
            result = self.peda.execute("set $eflags = 0x%x" % reg_eflags)
            return result

        return True

    def eflags(self, *arg):
        """
        Display/set/clear/toggle value of eflags register
        Usage:
            MYNAME
            MYNAME [set|clear] flagname
            MYNAME [set|clear|toggle] flagname
        """
        (option, flagname) = normalize_argv(arg, 2)
        if not self._is_running():
            return

        if option and not flagname:
            self._missing_argument()

        if option is None:  # display eflags
            flags = self._get_eflags()
            text = ""
            for (i, f) in enumerate(EFLAGS):
                if flags[f]:
                    text += "%s " % red(EFLAGS_TEXT[i].upper(), "bold")
                else:
                    text += "%s " % green(EFLAGS_TEXT[i].lower())

            eflags = self.peda.getreg("eflags")
            msg("%s: 0x%x (%s)" % (green("EFLAGS"), eflags, text.strip()))

        if option == "set":
            self._set_eflags(flagname.lower(), True)
        elif option == "clear":
            self._set_eflags(flagname, False)
        elif option == 'toggle':
            self._set_eflags(flagname, None)

    eflags.options = ["set", "clear", "toggle"]

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

        super(IntelPEDACmd, self).xinfo(*arg)
        if str(address).startswith("r"):
            if regname is None or "eflags" in regname:
                self.eflags()

    xinfo.options = ["register"]

    ###############################
    #   Exploit Helper Commands   #
    ###############################
    # elfheader()
    def elfheader(self, *arg):
        """
        Get headers information from debugged ELF file
        Usage:
            MYNAME [header_name]
        """

        (name,) = normalize_argv(arg, 1)
        result = self.peda.elfheader(name)
        if len(result) == 0:
            warning("%s not found, did you specify the FILE to debug?" % (name if name else "headers"))
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg("%s: 0x%x - 0x%x (%s)" % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = 0x%x" % (k, start))

    @memoized
    def _readelf_header(self, filename, name=None):
        """
        Get headers information of an ELF file using 'readelf'

        Args:
            - filename: ELF file (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers (name(String), value(Int)) (Dict)
        """
        elfinfo = {}
        vmap = self.peda.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0
        out = execute_external_command("%s -W -S %s" % (Nasm.READELF, filename))
        if not out:
            return {}
        p = re.compile("^ *\[ *\d*\] +(\S+) +\S+ +(\S+) +\S+ +(\S*)(.*)$", re.M)
        matches = p.findall(out)
        if not matches:
            return None

        for (hname, start, size, attr) in matches:
            start, end = to_int("0x" + start), to_int("0x" + start) + to_int("0x" + size)
            # if PIE binary or DSO, update with runtime address
            if start < elfbase:
                start += elfbase
            if end < elfbase:
                end += elfbase

            if "X" in attr:
                htype = "code"
            elif "W" in attr:
                htype = "data"
            else:
                htype = "rodata"
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

    # readelf_header(), elfheader_solib()
    def readelf(self, *arg):
        """
        Get headers information from an ELF file
        Usage:
            MYNAME mapname [header_name]
            MYNAME filename [header_name]
        """

        (filename, hname) = normalize_argv(arg, 2)
        # result = {}
        # maps = peda.get_vmmap()
        if filename is None:  # fallback to elfheader()
            result = self.peda.elfheader()
        else:
            result = self.peda.elfheader_solib(filename, hname)

        if not result:
            result = self._readelf_header(filename, hname)
        if len(result) == 0:
            warning("%s or %s not found" % (filename, hname))
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg("%s: 0x%x - 0x%x (%s)" % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = 0x%x" % (k, start))

    # elfsymbol()
    def elfsymbol(self, *arg):
        """
        Get non-debugging symbol information from an ELF file
        Usage:
            MYNAME symbol_name
        """
        (name,) = normalize_argv(arg, 1)
        if not self.peda.getfile():
            warning("please specify a file to debug")
            return

        result = self.peda.elfsymbol(name)
        if len(result) == 0:
            msg("'%s': no match found" % (name if name else "plt symbols"))
        else:
            if ("%s@got" % name) not in result:
                msg("Found %d symbols" % len(result))
            else:
                msg("Detail symbol info")
            for (k, v) in sorted(result.items(), key=lambda x: x[1]):
                msg("%s = %s" % (k, "0x%x" % v if v else repr(v)))

    @memoized
    def _checksec(self, filename=None):
        """
        Check for various security options of binary (ref: http://www.trapkit.de/tools/checksec.sh)

        Args:
            - file: path name of file to check (String)

        Returns:
            - dictionary of (setting(String), status(Int)) (Dict)
        """
        result = {}
        result["RELRO"] = 0
        result["CANARY"] = 0
        result["NX"] = 1
        result["PIE"] = 0
        result["FORTIFY"] = 0

        if filename is None:
            filename = self.peda.getfile()

        if not filename:
            return None

        out = execute_external_command("%s -W -a \"%s\" 2>&1" % (Nasm.READELF, filename))
        if "Error:" in out:
            return None

        for line in out.splitlines():
            if "GNU_RELRO" in line:
                result["RELRO"] |= 2
            if "BIND_NOW" in line:
                result["RELRO"] |= 1
            if "__stack_chk_fail" in line:
                result["CANARY"] = 1
            if "GNU_STACK" in line and "RWE" in line:
                result["NX"] = 0
            if "Type:" in line and "DYN (" in line:
                result["PIE"] = 4  # Dynamic Shared Object
            if "(DEBUG)" in line and result["PIE"] == 4:
                result["PIE"] = 1
            if "_chk@" in line:
                result["FORTIFY"] = 1

        if result["RELRO"] == 1:
            result["RELRO"] = 0  # ? | BIND_NOW + NO GNU_RELRO = NO PROTECTION
        # result["RELRO"] == 2 # Partial | NO BIND_NOW + GNU_RELRO
        # result["RELRO"] == 3 # Full | BIND_NOW + GNU_RELRO
        return result

    # checksec()
    def checksec(self, *arg):
        """
        Check for various security options of binary
        For full features, use http://www.trapkit.de/tools/checksec.sh
        Usage:
            MYNAME [file]
        """
        (filename,) = normalize_argv(arg, 1)
        colorcodes = {
            0: red("disabled"),
            1: green("ENABLED"),
            2: yellow("Partial"),
            3: green("FULL"),
            4: yellow("Dynamic Shared Object"),
        }

        result = self._checksec(filename)
        if result:
            for (k, v) in sorted(result.items()):
                msg("%s: %s" % (k.ljust(10), colorcodes[v]))

    def nxtest(self, *arg):
        """
        Perform real NX test to see if it is enabled/supported by OS
        Usage:
            MYNAME [address]
        """
        (address,) = normalize_argv(arg, 1)

        exec_wrapper = self.peda.execute_redirect("show exec-wrapper").split('"')[1]
        if exec_wrapper != "":
            self.peda.execute("unset exec-wrapper")

        if not self.peda.getpid():  # start program if not running
            self.peda.execute("start")

        # set current PC => address, continue
        pc = self.peda.getpc()
        sp = self.peda.getreg("sp")
        if not address:
            address = sp
        self.peda.execute("set $pc = 0x%x" % address)
        # set value at address => 0xcc
        self.peda.execute("set *0x%x = 0x%x" % (address, 0xcccccccc))
        self.peda.execute("set *0x%x = 0x%x" % (address + 4, 0xcccccccc))
        out = self.peda.execute_redirect("continue")
        text = "NX test at %s: " % (to_address(address) if address != sp else "stack")

        if out:
            if "SIGSEGV" in out:
                text += red("Non-Executable")
            elif "SIGTRAP" in out:
                text += green("Executable")
        else:
            text += "Failed to test"

        msg(text)
        # restore exec-wrapper
        if exec_wrapper != "":
            self.peda.execute("set exec-wrapper %s" % exec_wrapper)

    def _verify_rop_gadget(self, start, end, depth=5):
        """
        Verify ROP gadget code from start to end with max number of instructions

        Args:
            - start: start address (Int)
            - end: end addres (Int)
            - depth: number of instructions (Int)

        Returns:
            - list of valid gadgets (address(Int), asmcode(String))
        """

        result = []
        valid = 0
        out = self.peda.execute_redirect("disassemble 0x%x, 0x%x" % (start, end + 1))
        if not out:
            return []

        code = out.splitlines()[1:-1]
        for line in code:
            if "bad" in line:
                return []
            (addr, code) = line.strip().split(":", 1)
            addr = to_int(addr.split()[0])
            result += [(addr, " ".join(code.strip().split()))]
            if "ret" in code:
                return result
            if len(result) > depth:
                break

        return []

    @memoized
    def _search_asm(self, start, end, asmcode, rop=0):
        """
        Search for ASM instructions in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - asmcode: assembly instruction (String)
                + multiple instructions are separated by ";"
                + wildcard ? supported, will be replaced by registers or multi-bytes

        Returns:
            - list of (address(Int), hexbyte(String))
        """
        wildcard = asmcode.count('?')
        magic_bytes = ["0x00", "0xff", "0xdead", "0xdeadbeef", "0xdeadbeefdeadbeef"]

        ops = [x for x in asmcode.split(';') if x]

        def buildcode(code=b"", pos=0, depth=0):
            if depth == wildcard and pos == len(ops):
                yield code
                return

            c = ops[pos].count('?')
            if c > 2:
                return
            elif c == 0:
                asm = self._assemble(ops[pos])
                if asm:
                    for code in buildcode(code + asm, pos + 1, depth):
                        yield code
            else:
                save = ops[pos]
                for regs in REGISTERS.values():
                    for reg in regs:
                        ops[pos] = save.replace("?", reg, 1)
                        for asmcode_reg in buildcode(code, pos, depth + 1):
                            yield asmcode_reg
                for byte in magic_bytes:
                    ops[pos] = save.replace("?", byte, 1)
                    for asmcode_mem in buildcode(code, pos, depth + 1):
                        yield asmcode_mem
                ops[pos] = save

        searches = []

        def decode_hex_escape(str_):
            """Decode string as hex and escape for regex"""
            return re.escape(codecs.decode(str_, 'hex'))

        for machine_code in buildcode():
            search = re.escape(machine_code)
            search = search.replace(decode_hex_escape(b"dead"), b"..") \
                .replace(decode_hex_escape(b"beef"), b"..") \
                .replace(decode_hex_escape(b"00"), b".") \
                .replace(decode_hex_escape(b"ff"), b".")

            if rop and 'ret' not in asmcode:
                search += b".{0,24}\\xc3"
            searches.append(search)

        search = b"(?=(" + b"|".join(searches) + b"))"
        candidates = self.searchmem(start, end, search)

        if rop:
            result = {}
            for (a, v) in candidates:
                gadget = self._verify_rop_gadget(a, a + len(v) // 2 - 1)
                # gadget format: [(address, asmcode), (address, asmcode), ...]
                if gadget != []:
                    blen = gadget[-1][0] - gadget[0][0] + 1
                    bytes = v[:2 * blen]
                    asmcode_rs = "; ".join([c for _, c in gadget])
                    if re.search(re.escape(asmcode).replace("\ ", ".*").replace("\?", ".*"), asmcode_rs) \
                            and a not in result:
                        result[a] = (bytes, asmcode_rs)
            result = list(result.items())
        else:
            result = []
            for (a, v) in candidates:
                asmcode = self.execute_redirect("disassemble 0x%x, 0x%x" % (a, a + (len(v) // 2)))
                if asmcode:
                    asmcode = "\n".join(asmcode.splitlines()[1:-1])
                    matches = re.findall(".*:([^\n]*)", asmcode)
                    result += [(a, (v, ";".join(matches).strip()))]

        return result

    # search_asm()
    def asmsearch(self, *arg):
        """
        Search for ASM instructions in memory
        Usage:
            MYNAME "asmcode" start end
            MYNAME "asmcode" mapname
        """
        (asmcode, start, end) = normalize_argv(arg, 3)
        if asmcode is None:
            self._missing_argument()

        if not self._is_running():
            return

        asmcode = arg[0]
        result = []
        if end is None:
            mapname = start
            if mapname is None:
                mapname = "binary"
            maps = self.peda.get_vmmap(mapname)
            info("Searching for ASM code: %s in: %s ranges" % (repr(asmcode), mapname))
            for (start, end, _, _) in maps:
                if not self.peda.is_executable(start, maps): continue  # skip non-executable page
                result += self.peda.search_asm(start, end, asmcode)
        else:
            info("Searching for ASM code: %s in range: 0x%x - 0x%x" % (repr(asmcode), start, end))
            result = self.peda.search_asm(start, end, asmcode)

        text = "Not found"
        if result:
            text = ""
            for (addr, (byte, code)) in result:
                text += "%s : (%s)\t%s\n" % (to_address(addr), byte.decode('utf-8'), code)
        pager(text)

    # search_asm()
    def ropsearch(self, *arg):
        """
        Search for ROP gadgets in memory
            Note: only for simple gadgets, for full ROP search try: http://ropshell.com
        Usage:
            MYNAME "gadget" start end
            MYNAME "gadget" pagename
        """

        (asmcode, start, end) = normalize_argv(arg, 3)
        if asmcode is None:
            self._missing_argument()

        if not self._is_running():
            return

        asmcode = arg[0]
        result = []
        if end is None:
            if start is None:
                mapname = "binary"
            else:
                mapname = start
            maps = self.peda.get_vmmap(mapname)
            info("Searching for ROP gadget: %s in: %s ranges" % (repr(asmcode), mapname))
            for (start, end, _, _) in maps:
                if not self.peda.is_executable(start, maps): continue  # skip non-executable page
                result += self.peda.search_asm(start, end, asmcode, rop=1)
        else:
            info("Searching for ROP gadget: %s in range: 0x%x - 0x%x" % (repr(asmcode), start, end))
            result = self.peda.search_asm(start, end, asmcode, rop=1)

        result = sorted(result, key=lambda x: len(x[1][0]))
        text = "Not found"
        if result:
            text = ""
            for (addr, (byte, code)) in result:
                text += "%s : (%s)\t%s\n" % (to_address(addr), byte, code)
        pager(text)

    def _dumprop(self, start, end, keyword=None, depth=5):
        """
        Dump unique ROP gadgets in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - keyword: to match start of gadgets (String)

        Returns:
            - dictionary of (address(Int), asmcode(String))
        """

        EXTRA_WORDS = ["BYTE ", " WORD", "DWORD ", "FWORD ", "QWORD ", "PTR ", "FAR "]
        result = {}
        mem = self.peda.dumpmem(start, end)
        if mem is None:
            return {}

        if keyword:
            search = keyword
        else:
            search = ""

        if len(mem) > 20000:  # limit backward depth if searching in large mem
            depth = 3
        found = re.finditer("\xc3", mem)
        found = list(found)
        for m in found:
            idx = start + m.start()
            for i in range(1, 24):
                gadget = self._verify_rop_gadget(idx - i, idx, depth)
                if gadget != []:
                    k = "; ".join([v for (a, v) in gadget])
                    if k.startswith(search):
                        for w in EXTRA_WORDS:
                            k = k.replace(w, "")
                        if k not in result:
                            result[k] = gadget[0][0]
        return result

    # dumprop()
    def dumprop(self, *arg):
        """
        Dump all ROP gadgets in specific memory range
            Note: only for simple gadgets, for full ROP search try: http://ropshell.com
            Warning: this can be very slow, do not run for big memory range
        Usage:
            MYNAME start end [keyword] [depth]
            MYNAME mapname [keyword]
                default gadget instruction depth is: 5
        """

        (start, end, keyword, depth) = normalize_argv(arg, 4)
        filename = self.peda.getfile()
        if filename is None:
            warning("please specify a filename to debug")
            return

        filename = os.path.basename(filename)
        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start
        elif to_int(end) is None:
            mapname = start
            keyword = end

        if depth is None:
            depth = 5

        result = {}
        warning("this can be very slow, do not run for large memory range")
        if mapname:
            maps = self.peda.get_vmmap(mapname)
            for (start, end, _, _) in maps:
                if not self.peda.is_executable(start, maps): continue  # skip non-executable page
                result.update(peda.dumprop(start, end, keyword))
        else:
            result.update(peda.dumprop(start, end, keyword))

        text = "Not found"
        if len(result) > 0:
            text = ""
            outfile = "%s-rop.txt" % filename
            fd = open(outfile, "w")
            info("Writing ROP gadgets to file: %s ..." % outfile)
            for (code, addr) in sorted(result.items(), key=lambda x: len(x[0])):
                text += "0x%x: %s\n" % (addr, code)
                fd.write("0x%x: %s\n" % (addr, code))
            fd.close()

        pager(text)

    def _common_rop_gadget(self, mapname=None):
        """
        Get common rop gadgets in binary: ret, popret, pop2ret, pop3ret, add [mem] reg, add reg [mem]

        Returns:
            - dictionary of (gadget(String), address(Int))
        """

        def _valid_register_opcode(bytes_):
            if not bytes_:
                return False

            for c in bytes_iterator(bytes_):
                if ord(c) not in list(range(0x58, 0x60)):
                    return False
            return True

        result = {}
        if mapname is None:
            mapname = "binary"
        maps = self.peda.get_vmmap(mapname)
        if maps is None:
            return result

        for (start, end, _, _) in maps:
            if not self.peda.is_executable(start, maps): continue

            mem = self.peda.dumpmem(start, end)
            found = self.peda.searchmem(start, end, b"....\xc3", mem)
            for (a, v) in found:
                v = codecs.decode(v, 'hex')
                if "ret" not in result:
                    result["ret"] = a + 4
                if "leaveret" not in result:
                    if v[-2] == "\xc9":
                        result["leaveret"] = a + 3
                if "popret" not in result:
                    if _valid_register_opcode(v[-2:-1]):
                        result["popret"] = a + 3
                if "pop2ret" not in result:
                    if _valid_register_opcode(v[-3:-1]):
                        result["pop2ret"] = a + 2
                if "pop3ret" not in result:
                    if _valid_register_opcode(v[-4:-1]):
                        result["pop3ret"] = a + 1
                if "pop4ret" not in result:
                    if _valid_register_opcode(v[-5:-1]):
                        result["pop4ret"] = a

            # search for add esp, byte 0xNN
            found = self.peda.searchmem(start, end, b"\x83\xc4([^\xc3]){0,24}\xc3", mem)
            # search for add esp, 0xNNNN
            found += self.peda.searchmem(start, end, b"\x81\xc4([^\xc3]){0,24}\xc3", mem)
            for (a, v) in found:
                if v.startswith(b"81"):
                    offset = to_int("0x" + codecs.encode(codecs.decode(v, 'hex')[2:5][::-1], 'hex').decode('utf-8'))
                elif v.startswith(b"83"):
                    offset = to_int("0x" + v[4:6].decode('utf-8'))
                gg = self._verify_rop_gadget(a, a + len(v) // 2 - 1)
                for (_, c) in gg:
                    if "pop" in c:
                        offset += 4
                gadget = "addesp_%d" % offset
                if gadget not in result:
                    result[gadget] = a

        return result

    # common_rop_gadget()
    def ropgadget(self, *arg):
        """
        Get common ROP gadgets of binary or library
        Usage:
            MYNAME [mapname]
        """

        (mapname,) = normalize_argv(arg, 1)
        result = self._common_rop_gadget(mapname)
        if not result:
            msg("Not found")
        else:
            text = ""
            for (k, v) in sorted(result.items(),
                                 key=lambda x: len(x[0]) if not x[0].startswith("add") else int(x[0].split("_")[1])):
                text += "%s = 0x%x\n" % (k, v)
            pager(text)

    def _search_jmpcall(self, start, end, regname=None):
        """
        Search memory for jmp/call reg instructions

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - reg: register name (String)

        Returns:
            - list of (address(Int), instruction(String))
        """

        result = []
        REG = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7: "edi"}
        P2REG = {0: "[eax]", 1: "[ecx]", 2: "[edx]", 3: "[ebx]", 6: "[esi]", 7: "[edi]"}
        OPCODE = {0xe: "jmp", 0xd: "call"}
        P2OPCODE = {0x1: "call", 0x2: "jmp"}
        JMPREG = [b"\xff" + bytes_chr(i) for i in range(0xe0, 0xe8)]
        JMPREG += [b"\xff" + bytes_chr(i) for i in range(0x20, 0x28)]
        CALLREG = [b"\xff" + bytes_chr(i) for i in range(0xd0, 0xd8)]
        CALLREG += [b"\xff" + bytes_chr(i) for i in range(0x10, 0x18)]
        JMPCALL = JMPREG + CALLREG

        if regname is None:
            regname = ""
        regname = regname.lower()
        pattern = re.compile(b'|'.join(JMPCALL).replace(b' ', b'\ '))
        mem = self.peda.dumpmem(start, end)
        found = pattern.finditer(mem)
        (arch, bits) = self.peda.getarch()
        for m in list(found):
            inst = ""
            addr = start + m.start()
            opcode = codecs.encode(m.group()[1:2], 'hex')
            type = int(opcode[0:1], 16)
            reg = int(opcode[1:2], 16)
            if type in OPCODE:
                inst = OPCODE[type] + " " + REG[reg]

            if type in P2OPCODE and reg in P2REG:
                inst = P2OPCODE[type] + " " + P2REG[reg]

            if inst != "" and regname[-2:] in inst.split()[-1]:
                if bits == 64:
                    inst = inst.replace("e", "r")
                result += [(addr, inst)]

        return result

    # search_jmpcall()
    def jmpcall(self, *arg):
        """
        Search for JMP/CALL instructions in memory
        Usage:
            MYNAME (search all JMP/CALL in current binary)
            MYNAME reg [mapname]
            MYNAME reg start end
        """

        (reg, start, end) = normalize_argv(arg, 3)
        result = []
        if not self._is_running():
            return

        mapname = None
        if start is None:
            mapname = "binary"
        elif end is None:
            mapname = start

        if mapname:
            maps = self.peda.get_vmmap(mapname)
            for (start, end, _, _) in maps:
                if not self.peda.is_executable(start, maps): continue
                result += self._search_jmpcall(start, end, reg)
        else:
            result = self._search_jmpcall(start, end, reg)

        if not result:
            msg("Not found")
        else:
            text = ""
            for (a, v) in result:
                text += "0x%x : %s\n" % (a, v)
            pager(text)

    @memoized
    def _assemble(self, asmcode, bits=None):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)

        Returns:
            - bin code (raw bytes)
        """
        if bits is None:
            (arch, bits) = self.peda.getarch()
        return Nasm.assemble(asmcode, bits)

    def assemble(self, *arg):
        """
        On the fly assemble and execute instructions using NASM.  Auto exec when changing instruction at pc.
        Usage:
            MYNAME [mode] [address]
                mode: -b16 / -b32 / -b64
        """
        (mode, address) = normalize_argv(arg, 2)

        exec_mode = write_mode = False
        if to_int(mode) is not None:
            address, mode = mode, None

        (arch, bits) = self.peda.getarch()
        if mode is None:
            mode = bits
        else:
            mode = to_int(mode[2:])
            if mode not in [16, 32, 64]:
                self._missing_argument()

        if self._is_running() and address == self.peda.getpc():
            write_mode = exec_mode = True

        if address is None or mode != bits:
            write_mode = exec_mode = False
        elif self.peda.is_address(address):
            write_mode = True

        if write_mode:
            msg('Instruction will be written to 0x%x. '
                'Command "set write on" can be used to patch the binary file.' % address)
        else:
            msg("Instructions will be written to stdout")

        msg("Type instructions (NASM syntax), one or more per line separated by \";\"")
        msg("End with a line saying just \"end\"")

        if not write_mode:
            address = 0xdeadbeef

        inst_list = []
        inst_code = b""
        # fetch instruction loop
        while True:
            try:
                inst = input("iasm|0x%x> " % address)
            except EOFError:
                msg('')
                break
            if inst == "end":
                break
            if inst == "":
                continue
            bincode = self._assemble(inst, mode)
            if bincode is None:
                continue
            size = len(bincode)
            if size == 0:
                continue
            inst_list.append((size, bincode, inst))
            if write_mode:
                self.peda.writemem(address, bincode)
            # execute assembled code
            if exec_mode:
                self.peda.execute("stepi %d" % (inst.count(";") + 1))

            address += size
            inst_code += bincode
            msg('hexify: "%s"' % to_hexstr(bincode))

        text = Nasm.format_shellcode(b"".join([x[1] for x in inst_list]), mode)
        if text:
            msg("Assembled%s instructions:" % ("/Executed" if exec_mode else ""))
            msg(text)
            msg('hexify: "%s"' % to_hexstr(inst_code))

    ####################################
    #   Payload/Shellcode Generation   #
    ####################################
    def skeleton(self, *arg):
        """
        Generate python exploit code template
        Usage:
            MYNAME type [file]
                type = argv: local exploit via argument
                type = env: local exploit via crafted environment (including NULL byte)
                type = stdin: local exploit via stdin
                type = remote: remote exploit via TCP socket
        """
        options = ["argv", "stdin", "env", "remote"]
        (opt, outfile) = normalize_argv(arg, 2)
        if opt not in options:
            self._missing_argument()

        pattern = cyclic_pattern(20000).decode('utf-8')
        if opt == "argv":
            code = ExploitSkeleton().skeleton_local_argv
        if opt == "env":
            code = ExploitSkeleton().skeleton_local_env
        if opt == "stdin":
            code = ExploitSkeleton().skeleton_local_stdin
        if opt == "remote":
            code = ExploitSkeleton().skeleton_remote_tcp

        if outfile:
            msg("Writing skeleton code to file \"%s\"" % outfile)
            open(outfile, "w").write(code.strip("\n"))
            os.chmod(outfile, 0o755)
            open("pattern.txt", "w").write(pattern)
        else:
            msg(code)

    skeleton.options = ["argv", "stdin", "env", "remote"]

    def shellcode(self, *arg):
        """
        Generate or download common shellcodes.
        Usage:
            MYNAME generate [arch/]platform type [port] [host]
            MYNAME search keyword (use % for any character wildcard)
            MYNAME display shellcodeId (shellcodeId as appears in search results)
            MYNAME zsc [generate customize shellcode]

            For generate option:
                default port for bindport shellcode: 16706 (0x4142)
                default host/port for connect back shellcode: 127.127.127.127/16706
                supported arch: x86
        """

        def list_shellcode():
            """
            List available shellcodes
            """
            text = "Available shellcodes:\n"
            for arch in SHELLCODES:
                for platform in SHELLCODES[arch]:
                    for sctype in SHELLCODES[arch][platform]:
                        text += "    %s/%s %s\n" % (arch, platform, sctype)
            msg(text)

        """ Multiple variable name for different modes """
        (mode, platform, sctype, port, host) = normalize_argv(arg, 5)
        (mode, keyword) = normalize_argv(arg, 2)
        (mode, shellcodeId) = normalize_argv(arg, 2)

        if mode == "generate":
            arch = "x86"
            if platform and "/" in platform:
                (arch, platform) = platform.split("/")

            if platform not in SHELLCODES[arch] or not sctype:
                list_shellcode()
                return
            # dbg_print_vars(arch, platform, sctype, port, host)
            try:
                sc = Shellcode(arch, platform).shellcode(sctype, port, host)
            except Exception as e:
                self._missing_argument()

            if not sc:
                msg("Unknown shellcode")
                return

            hexstr = to_hexstr(sc)
            linelen = 16  # display 16-bytes per line
            i = 0
            text = "# %s/%s/%s: %d bytes\n" % (arch, platform, sctype, len(sc))
            if sctype in ["bindport", "connect"]:
                text += "# port=%s, host=%s\n" % (port if port else '16706', host if host else '127.127.127.127')
            text += "shellcode = (\n"
            while hexstr:
                text += '    "%s"\n' % (hexstr[:linelen * 4])
                hexstr = hexstr[linelen * 4:]
                i += 1
            text += ")"
            msg(text)

        # search shellcodes on shell-storm.org
        elif mode == "search":
            if keyword is None:
                self._missing_argument()

            res_dl = Shellcode().search(keyword)
            if not res_dl:
                msg("Shellcode not found or cannot retrieve the result")
                return

            msg("Found %d shellcodes" % len(res_dl))
            msg("%s\t%s" % (blue("ScId"), blue("Title")))
            text = ""
            for data_d in res_dl:
                text += "[%s]\t%s - %s\n" % (yellow(data_d['ScId']), data_d['ScArch'], data_d['ScTitle'])
            pager(text)

        # download shellcodes from shell-storm.org
        elif mode == "display":
            if to_int(shellcodeId) is None:
                self._missing_argument()

            res = Shellcode().display(shellcodeId)
            if not res:
                msg("Shellcode id not found or cannot retrieve the result")
                return

            msg(res)
        # OWASP ZSC API Z3r0D4y.Com
        elif mode == "zsc":
            'os lists'
            oslist = ['linux_x86', 'linux_x64', 'linux_arm', 'linux_mips', 'freebsd_x86',
                      'freebsd_x64', 'windows_x86', 'windows_x64', 'osx', 'solaris_x64', 'solaris_x86']
            'functions'
            joblist = ['exec(\'/path/file\')', 'chmod(\'/path/file\',\'permission number\')',
                       'write(\'/path/file\',\'text to write\')',
                       'file_create(\'/path/file\',\'text to write\')', 'dir_create(\'/path/folder\')',
                       'download(\'url\',\'filename\')',
                       'download_execute(\'url\',\'filename\',\'command to execute\')',
                       'system(\'command to execute\')']
            'encode types'
            encodelist = ['none', 'xor_random', 'xor_yourvalue', 'add_random', 'add_yourvalue', 'sub_random',
                          'sub_yourvalue', 'inc', 'inc_timeyouwant', 'dec', 'dec_timeyouwant', 'mix_all']
            try:
                while True:
                    for os in oslist:
                        msg('%s %s' % (yellow('[+]'), green(os)))
                    os = input('%s' % blue('os:'))
                    if os in oslist:  # check if os exist
                        break
                    else:
                        warning("Wrong input! Try Again.")
                while True:
                    for job in joblist:
                        msg('%s %s' % (yellow('[+]'), green(job)))
                    job = input('%s' % blue('job:'))
                    if job != '':
                        break
                    else:
                        warning("Please enter a function.")
                while True:
                    for encode in encodelist:
                        msg('%s %s' % (yellow('[+]'), green(encode)))
                    encode = input('%s' % blue('encode:'))
                    if encode != '':
                        break
                    else:
                        warning("Please enter a encode type.")
            except (KeyboardInterrupt, SystemExit):
                warning("Aborted by user")
            result = Shellcode().zsc(os, job, encode)
            if result is not None:
                msg(result)
            else:
                pass
            return
        else:
            self._missing_argument()

    shellcode.options = ["generate", "search", "display", "zsc"]

    def gennop(self, *arg):
        """
        Generate abitrary length NOP sled using given characters
        Usage:
            MYNAME size [chars]
        """
        (size, chars) = normalize_argv(arg, 2)
        if size is None:
            self._missing_argument()

        nops = Shellcode.gennop(size, chars)
        msg(repr(nops))

    def _payload_copybytes(self, target=None, data=None, template=0):
        """
        Suggest function for ret2plt exploit and generate payload for it

        Args:
            - target: address to copy data to (Int)
            - data: (String)
        Returns:
            - python code template (String)
        """
        result = ""
        funcs = ["strcpy", "sprintf", "strncpy", "snprintf", "memcpy"]

        symbols = self.peda.elfsymbols()
        transfer = ""
        for f in funcs:
            if f + "@plt" in symbols:
                transfer = f
                break
        if transfer == "":
            warning("No copy function available")
            return None

        headers = self.peda.elfheader()
        start = min([v[0] for (k, v) in headers.items() if v[0] > 0])
        end = max([v[1] for (k, v) in headers.items() if v[2] != "data"])
        symbols = self.peda.elfsymbol(transfer)
        if not symbols:
            warning("Unable to find symbols")
            return None

        plt_func = transfer + "_plt"
        plt_addr = symbols[transfer + "@plt"]
        gadgets = self._common_rop_gadget()
        function_template = "\n".join([
            "popret = 0x%x" % gadgets["popret"],
            "pop2ret = 0x%x" % gadgets["pop2ret"],
            "pop3ret = 0x%x" % gadgets["pop3ret"],
            "def %s_payload(target, bytes):" % transfer,
            "    %s = 0x%x" % (plt_func, plt_addr),
            "    payload = []",
            "    offset = 0",
            "    for (str, addr) in bytes:",
            "",
        ])
        if "ncp" in transfer or "mem" in transfer:  # memcpy() style
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, addr, len(str)]" % plt_func,
                "        offset += len(str)",
            ])
        elif "snp" in transfer:  # snprintf()
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, len(str)+1, addr]" % plt_func,
                "        offset += len(str)",
            ])
        else:
            function_template += "\n".join([
                "        payload += [%s, pop2ret, target+offset, addr]" % plt_func,
                "        offset += len(str)",
            ])
        function_template += "\n".join(["",
                                        "    return payload",
                                        "",
                                        "payload = []"
                                        ])

        if target is None:
            if template != 0:
                return function_template
            else:
                return ""

        # text = "\n_payload = []\n"
        text = "\n"
        mem = self.peda.dumpmem(start, end)
        bytes = self.peda.search_substr(start, end, data, mem)

        if to_int(target) is not None:
            target = to_hex(target)
        text += "# %s <= %s\n" % (target, repr(data))
        if not bytes:
            text += "***Failed***\n"
        else:
            text += "bytes = [\n"
            for (s, a) in bytes:
                if a != -1:
                    text += "    (%s, %s),\n" % (repr(s), to_hex(a))
                else:
                    text += "    (%s, ***Failed***),\n" % repr(s)
            text += "\n".join([
                "]",
                "payload += %s_payload(%s, bytes)" % (transfer, target),
                "",
            ])

        return text

    def payload(self, *arg):
        """
        Generate various type of ROP payload using ret2plt
        Usage:
            MYNAME copybytes (generate function template for ret2strcpy style payload)
            MYNAME copybytes dest1 data1 dest2 data2 ...
        """
        (option,) = normalize_argv(arg, 1)
        if option is None:
            self._missing_argument()

        if option == "copybytes":
            result = self._payload_copybytes(template=1)  # function template
            arg = arg[1:]
            while len(arg) > 0:
                (target, data) = normalize_argv(arg, 2)
                if data is None:
                    break
                if to_int(data) is None:
                    if data[0] == "[" and data[-1] == "]":
                        data = eval(data)
                        data = list2hexstr(data, self.peda.intsize())
                else:
                    data = "0x%x" % data
                result += self.peda.payload_copybytes(target, data)
                arg = arg[2:]

        if not result:
            msg("Failed to construct payload")
        else:
            text = ""
            indent = to_int(config.Option.get("indent"))
            for line in result.splitlines():
                text += " " * indent + line + "\n"
            msg(text)
            filename = self.peda.get_config_filename("payload")
            open(filename, "w").write(text)

    payload.options = ["copybytes"]


###########################################################################
## INITIALIZATION ##
# global instances of PEDA() and PEDACmd()
asm = peda = pedacmd = None

if __name__ == '__main__':
    info('Checking complie toolchains')
    asm = Nasm()
    info('Init PEDA main section.')
    peda = PEDA(REGISTERS, asm)
    pedacmd = IntelPEDACmd(peda, PEDAFILE, asm)
    pedacmd.help.__func__.options = pedacmd.commands  # XXX HACK

    # register "peda" command in gdb
    pedaGDBCommand(peda, pedacmd)
    Alias("pead", "peda")  # just for auto correction

    # create aliases for subcommands
    for cmd in pedacmd.commands:
        func = getattr(pedacmd, cmd)
        func.__func__.__doc__ = func.__doc__.replace("MYNAME", cmd)
        if cmd not in ["help", "show", "set"]:
            pedacmd._alias(cmd, cmd, False)

    # custom hooks
    peda.define_user_command("hook-stop", "peda context\nsession autosave")

    # custom command aliases, add any alias you want
    pedacmd._alias("phelp", "help")
    pedacmd._alias("pset", "set")
    pedacmd._alias("pshow", "show")
    pedacmd._alias("pbreak", "pltbreak")
    pedacmd._alias("pattc", "pattern_create")
    pedacmd._alias("patto", "pattern_offset")
    pedacmd._alias("patta", "pattern_arg")
    pedacmd._alias("patte", "pattern_env")
    pedacmd._alias("patts", "pattern_search")
    pedacmd._alias("find", "searchmem")  # override gdb find command
    pedacmd._alias("ftrace", "tracecall")
    pedacmd._alias("itrace", "traceinst")
    pedacmd._alias("jtrace", "traceinst j")
    pedacmd._alias("stack", "telescope $sp")
    pedacmd._alias("viewmem", "telescope")
    pedacmd._alias("reg", "xinfo register")

    # misc gdb settings
    peda.execute("set prompt \001%s\002" % red("\002gdb-peda > \001"))  # custom prompt
    peda.execute("set disassembly-flavor intel")
    info('Registering commands.')
    msg('')

    if zlib:
        with open(os.path.dirname(PEDAFILE) + '/peda/intel/logos', 'rb') as f:
            logos = pickle_loads(zlib.decompress(f.read()))
        msg(logos[random.randint(0, len(logos) - 1)], 'blue', 'bold')
        msg(('Modified by alset %s' % __version__).rjust(random.randint(10, len(logos) + 10)), 'red')
        msg('')
    else:
        msg(('PEDA modified by alset %s' % __version__).rjust(random.randint(10, 50)), 'red')
        msg('')
