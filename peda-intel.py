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
    PEDAFILE = os.path.abspath(os.path.join(os.path.dirname(PEDAFILE), os.path.expanduser(os.readlink(PEDAFILE))))
sys.path.insert(0, os.path.dirname(PEDAFILE))

from peda import *

try:
    import zlib
except ImportError:
    zlib = None

__version__ = 'alpha-1.0'


class Nasm:
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
            pattern = re.compile(r"([0-9A-F]{8})\s*([^\s]*)\s*(.*)")

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


# Define registers

# REGISTERS = {
#     8: ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
#     16: ["ax", "bx", "cx", "dx"],
#     32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
#     64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
#          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
# }

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
            self.peda.execute_redirect("b *0x%x" % symbol[function + "@plt"])

        else:  # addressed function
            self.peda.execute_redirect("b *%s" % function)

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
            p = re.compile(r".*mov.*\[esp(.*)\],")
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
            p = re.compile(r":\s*([^ ]*)\s*(.*),")
            matches = p.findall(code)
            regs = [r for (_, r) in matches]
            p = re.compile(r"di|si|dx|cx|r8|r9")
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
            pc = self.peda.getpc()
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
        entries = ["main", "__libc_start_main@plt", "_start", "_init"]

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
                self.peda.execute_redirect("tbreak *%s" % elf_entry)

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
                code = format_disasm_code_intel(code)
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

        p = re.compile(r".*?:\s*[^ ]*\s*([^,]*),(.*)")
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
            if re.search(r"j[^m]", code.split(":\t")[-1].split()[0]):
                prev_insts = self.peda.prev_inst(peda.getpc())
                if prev_insts:
                    prev_code = "0x%x:%s" % prev_insts[0]
                    msg("%s%s%s" % (" " * (prev_depth - 1), " dep:%02d    " % (prev_depth - 1), prev_code), teefd=logfd)

            text = "%s%s%s" % (" " * (prev_depth - 1), " dep:%02d " % (prev_depth - 1), code.strip())
            msg(text, teefd=logfd)

            if re.search(r"call", code.split(":\t")[-1].split()[0]):
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

        if (
                opcode == "jmp"
        ) or (
                opcode == "je" and flags["ZF"]
        ) or (
                opcode == "jne" and not flags["ZF"]
        ) or (
                opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"])
        ) or (
                opcode == "jge" and (flags["SF"] == flags["OF"])
        ) or (
                opcode == "ja" and not flags["CF"] and not flags["ZF"]
        ) or (
                opcode == "jae" and not flags["CF"]
        ) or (
                opcode == "jl" and (flags["SF"] != flags["OF"])
        ) or (
                opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"]))
        ) or (
                opcode == "jb" and flags["CF"]
        ) or (
                opcode == "jbe" and (flags["CF"] or flags["ZF"])
        ) or (
                opcode == "jo" and flags["OF"]
        ) or (
                opcode == "jno" and not flags["OF"]
        ) or (
                opcode == "jz" and flags["ZF"]
        ) or (
                opcode == "jnz" and flags["OF"]
        ):
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
                msg(format_disasm_code_intel(text, pc))
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
                    text = format_disasm_code_intel(text, pc) + "\n"
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
                    text += format_disasm_code_intel(peda.disassemble_around(pc, count), pc)
                    text += "\n" + green("JUMP is NOT taken".rjust(79))

                msg(text.rstrip())
            # stopped at other instructions
            else:
                text += self.peda.disassemble_around(pc, count)
                msg(format_disasm_code_intel(text, pc))
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
        p = re.compile(r"^ *\[ *\d*] +(\S+) +\S+ +(\S+) +\S+ +(\S*)(.*)$", re.M)
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


####################
## INITIALIZATION ##
####################

# global instances of PEDA() and PEDACmd()
asm = peda = pedacmd = None

if __name__ == '__main__':
    info('Checking compile toolchains')
    asm = Nasm()
    info('Init PEDA main section.')
    peda = PEDA()
    # skip selector registers
    peda_registers_func = peda.registers
    peda.registers = lambda: [i for i in peda_registers_func() if
                              not i.name.endswith('s') and not i.name.startswith('k')]
    pedacmd = IntelPEDACmd(peda, PEDAFILE)
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
    peda.define_user_command("hook-stop", "peda context")

    # custom command aliases, add any alias you want
    pedacmd._alias("phelp", "help")
    pedacmd._alias("pset", "set")
    pedacmd._alias("pshow", "show")
    pedacmd._alias("find", "searchmem")  # override gdb find command
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
