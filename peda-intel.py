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

# Define registers

# REGISTERS = {
#     8: ['al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh'],
#     16: ['ax', 'bx', 'cx', 'dx'],
#     32: ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip'],
#     64: ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'rip',
#          'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
# }

EFLAGS = ['CF', 'PF', 'AF', 'ZF', 'SF', 'TF', 'IF', 'DF', 'OF']
EFLAGS_TEXT = ['carry', 'parity', 'adjust', 'zero', 'sign', 'trap', 'interrupt', 'direction', 'overflow']
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

MSG_LEGEND = 'Legend: %s, %s, %s, value' % (red('code'), blue('data'), green('rodata'))


###########################################################################
class IntelPEDACmd(PEDACmd):
    def deactive(self, *args):
        """
        Bypass a function by ignoring its execution (eg sleep/alarm)
        Usage:
            MYNAME function
            MYNAME function del (re-active)
        """
        (function, action) = normalize_argv(args, 2)
        if function is None:
            self._missing_argument()

        if to_int(function):
            function = '0x%x' % function

        bnum = '$deactive_%s_bnum' % function
        if action and 'del' in action:
            self.peda.execute('delete %s' % bnum)
            self.peda.execute('set %s = "void"' % bnum)
            msg('"%s" re-activated' % function)
            return

        if 'void' not in self.peda.execute_redirect('p %s' % bnum):
            out = self.peda.execute_redirect('info breakpoints %s' % bnum)
            if out:
                msg('Already deactivated "%s"' % function)
                msg(out)
                return
            else:
                self.peda.execute('set %s = "void"' % bnum)

        (arch, bits) = self.peda.getarch()
        if not function.startswith("0x"):  # named function
            symbol = self.peda.elfsymbol(function)
            if not symbol:
                warning('cannot retrieve info of function "%s"' % function)
                return
            self.peda.execute_redirect('b *0x%x' % symbol[function + '@plt'])

        else:  # addressed function
            self.peda.execute_redirect('b *%s' % function)

        self.peda.execute('set %s = $bpnum' % bnum)
        tmpfd = tmpfile()
        if 'i386' in arch:
            tmpfd.write('\n'.join([
                'commands $bpnum',
                'silent',
                'set $eax = 0',
                'return',
                'continue',
                'end']))
        if '64' in arch:
            tmpfd.write('\n'.join([
                'commands $bpnum',
                'silent',
                'set $rax = 0',
                'return',
                'continue',
                'end']))
        tmpfd.flush()
        self.peda.execute('source %s' % tmpfd.name)
        tmpfd.close()
        out = self.peda.execute_redirect('info breakpoints %s' % bnum)
        if out:
            msg('"%s" deactivated' % function)
            msg(out)

    def unptrace(self, *args):
        """
        Disable anti-ptrace detection
        Usage:
            MYNAME
            MYNAME del
        """
        (action,) = normalize_argv(args, 1)

        self.deactive('ptrace', action)

        if not action and 'void' in self.peda.execute_redirect('p $deactive_ptrace_bnum'):
            # cannot deactive vi plt entry, try syscall method
            info('Try to patch "ptrace" via syscall')
            self.peda.execute('catch syscall ptrace')
            self.peda.execute('set $deactive_ptrace_bnum = $bpnum')
            tmpfd = tmpfile()
            (arch, bits) = self.peda.getarch()
            if 'i386' in arch:
                tmpfd.write('\n'.join([
                    'commands $bpnum',
                    'silent',
                    'if (*(int*)($esp+4) == 0 || $ebx == 0)',
                    '    set $eax = 0',
                    'end',
                    'continue',
                    'end']))
            if '64' in arch:
                tmpfd.write('\n'.join([
                    'commands $bpnum',
                    'silent',
                    'if ($rdi == 0)',
                    '    set $rax = 0',
                    'end',
                    'continue',
                    'end']))
            tmpfd.flush()
            self.peda.execute('source %s' % tmpfd.name)
            tmpfd.close()
            out = self.peda.execute_redirect('info breakpoints $deactive_ptrace_bnum')
            if out:
                msg('"ptrace" deactivated')
                msg(out)

    def _get_function_args_32(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - i386
        """
        if not argc:
            argc = 0
            matches = RE.INTEL_DISASM_WITH_ESP.findall(code)
            if matches:
                l = len(matches)
                for v in matches:
                    if v.startswith('+'):
                        offset = to_int(v[1:])
                        if offset is not None and (offset // 4) > l:
                            continue
                    argc += 1
            else:  # try with push style
                argc = code.count('push')

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = list(self.peda.dumpstack(argc))
        return args

    def _get_function_args_64(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - x86_64
        """

        # just retrieve max 6 args
        arg_order = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

        if not argc:
            matches = RE.ARM_DISASM_WITH_REGS.findall(code)
            regs = set([r.rjust(2)[-2:] for (_, r) in matches])
            argc = 0
            if 'si' in regs and 'di' not in regs:  # dirty fix
                argc += 1
            argc += 1 if 'di' in regs else 0
            if argc > 0:
                argc += 1 if 'si' in regs else 0
            if argc > 1:
                argc += 1 if 'dx' in regs else 0
            if argc > 2:
                argc += 1 if 'cx' in regs else 0
            if argc > 3:
                argc += 1 if 'r8' in regs else 0
            if argc > 4:
                argc += 1 if 'r9' in regs else 0

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = []
        regs = self.peda.getregs()
        for i in range(argc):
            args.append(regs[arg_order[i]])

        return args

    def _get_function_args(self, argc=None):
        """
        Get the guessed arguments passed to a function when stopped at a call instruction

        Args:
            - argc: force to get specific number of arguments (Int)

        Returns:
            - list of arguments (List)
        """

        regs = self.peda.getregs()
        if regs is None:
            return []

        (arch, bits) = self.peda.getarch()

        code = []
        if argc is None:
            pc = self.peda.getpc()
            prev_insts = self.peda.prev_inst(pc, 12)
            if not prev_insts:
                return []
            for (addr, inst) in prev_insts[::-1]:
                if 'call' in inst.strip().split()[0]:
                    break
                code.append('0x%x:%s' % (addr, inst))
            code.reverse()
        code = os.linesep.join(code)

        if 'i386' in arch:
            args = self._get_function_args_32(code, argc)
        elif '64' in arch:
            args = self._get_function_args_64(code, argc)
        else:
            args = []

        return args

    # get_function_args()
    def dumpargs(self, *args):
        """
        Display arguments passed to a function when stopped at a call instruction
        Usage:
            MYNAME [count]
                count: force to display 'count args' instead of guessing
        """

        (count,) = normalize_argv(args, 1)
        if not self._is_running():
            return

        args = self._get_function_args(count)
        if args:
            msg('Guessed arguments:')
            for (i, a) in enumerate(args):
                chain = self.peda.examine_mem_reference(a)
                msg('arg[%d]: %s' % (i, format_reference_chain(chain)))
        else:
            msg('No argument')

    def start(self, *args):
        """
        Start debugged program and stop at most convenient entry
        Usage:
            MYNAME
        """
        entries = ['main', '__libc_start_main@plt', '_start', '_init']

        started = 0
        for e in entries:
            out = self.peda.execute_redirect('tbreak %s' % e)
            if out and 'breakpoint' in out:
                self.peda.execute('run %s' % ' '.join(args))
                started = 1
                break

        if not started:  # try ELF entry point or just 'run' as the last resort
            elf_entry = self.peda.elfentry()
            if elf_entry:
                self.peda.execute_redirect('tbreak *%s' % elf_entry)

            self.peda.execute('run')

    # wrapper for stepuntil('call')
    def nextcall(self, *args):
        """
        Step until next 'call' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(args, 2)

        if keyword:
            self.stepuntil('call.*%s' % keyword, mapname)
        else:
            self.stepuntil('call', mapname)

    # wrapper for stepuntil('j')
    def nextjmp(self, *args):
        """
        Step until next 'j*' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(args, 2)

        if keyword:
            self.stepuntil('j.*%s' % keyword, mapname)
        else:
            self.stepuntil('j', mapname)

    # stepuntil()
    def tracecall(self, *args):
        """
        Trace function calls made by the program
        Usage:
            MYNAME ['func1,func2'] [mapname1,mapname2]
            MYNAME ['-func1,func2'] [mapname1,mapname2] (inverse)
                default is to trace internal calls made by the program
        """
        (funcs, mapname) = normalize_argv(args, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = 'binary'

        fnames = [""]
        if funcs:
            if to_int(funcs):
                funcs = '0x%x' % funcs
            fnames = funcs.replace(',', ' ').split()
        for (idx, fn) in enumerate(fnames):
            if to_int(fn):
                fnames[idx] = '0x%x' % to_int(fn)

        inverse = 0
        for (idx, fn) in enumerate(fnames):
            if fn.startswith('-'):  # inverse trace
                fnames[idx] = fn[1:]
                inverse = 1

        binname = self.peda.getfile()
        logname = self.peda.get_config_filename('tracelog')

        if mapname is None:
            mapname = binname

        self.peda.deactivate_user_command('hook-stop')  # disable hook-stop to speedup
        info('Tracing calls %s "%s", Ctrl-C to stop...' % ('match' if not inverse else 'not match', ','.join(fnames)))
        prev_depth = self.peda.backtrace_depth(peda.getreg('sp'))

        logfd = open(logname, 'w')
        code = ''
        while True:
            result = self.peda.stepuntil('call', mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith('=>'):
                break

            if not inverse:
                matched = False
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(':\t')[-1]):
                        matched = True
                        break
            else:
                matched = True
                for fn in fnames:
                    fn = fn.strip()
                    if re.search(fn, code.split(':\t')[-1]):
                        matched = False
                        break

            if matched:
                code = format_disasm_code_intel(code)
                msg('%s%s%s' % (' ' * (prev_depth - 1), ' dep:%02d ' % (prev_depth - 1), colorize(code.strip())),
                    teefd=logfd)
                args = self.peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = self.peda.examine_mem_reference(a)
                        text = '%s        |-- arg[%d]: %s' % (' ' * (prev_depth - 1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

        msg(code, 'red')
        self.peda.restore_user_command('hook-stop')
        if 'STOP' not in self.peda.get_status():
            self.peda.execute('stop')
        logfd.close()
        info('Saved trace information in file %s, view with "less -r file"' % logname)

    # stepuntil()
    def traceinst(self, *args):
        """
        Trace specific instructions executed by the program
        Usage:
            MYNAME ['inst1,inst2'] [mapname1,mapname2]
            MYNAME count (trace execution of next count instrcutions)
                default is to trace instructions inside the program
        """
        (insts, mapname) = normalize_argv(args, 2)

        if not self._is_running():
            return

        if not mapname:
            mapname = 'binary'

        instlist = ['.*']
        count = -1
        if insts:
            if to_int(insts):
                count = insts
            else:
                instlist = insts.replace(',', ' ').split()

        binname = self.peda.getfile()
        logname = self.peda.get_config_filename('tracelog')

        if mapname is None:
            mapname = binname

        self.peda.deactivate_user_command('hook-stop')  # disable hook-stop to speedup
        info('Tracing instructions match "%s", Ctrl-C to stop...' % (','.join(instlist)))
        prev_depth = self.peda.backtrace_depth(peda.getreg('sp'))
        logfd = open(logname, 'w')

        p = re.compile(r'.*?:\s*[^ ]*\s*([^,]*),(.*)')
        while count:
            result = self.peda.stepuntil(','.join(instlist), mapname, prev_depth)
            if result is None:
                break
            (call_depth, code) = result
            prev_depth += call_depth
            if not code.startswith('=>'):
                break

            # special case for JUMP inst
            prev_code = ""
            if re.search(r'j[^m]', code.split(':\t')[-1].split()[0]):
                prev_insts = self.peda.prev_inst(peda.getpc())
                if prev_insts:
                    prev_code = '0x%x:%s' % prev_insts[0]
                    msg('%s%s%s' % (' ' * (prev_depth - 1), ' dep:%02d    ' % (prev_depth - 1), prev_code), teefd=logfd)

            text = '%s%s%s' % (' ' * (prev_depth - 1), ' dep:%02d ' % (prev_depth - 1), code.strip())
            msg(text, teefd=logfd)

            if re.search(r'call', code.split(':\t')[-1].split()[0]):
                args = self.peda.get_function_args()
                if args:
                    for (i, a) in enumerate(args):
                        chain = self.peda.examine_mem_reference(a)
                        text = '%s        |-- arg[%d]: %s' % (' ' * (prev_depth - 1), i, format_reference_chain(chain))
                        msg(text, teefd=logfd)

            # get registers info if any
            (arch, bits) = self.peda.getarch()
            code = code.split('#')[0].strip('=>')
            if prev_code:
                m = p.search(prev_code)
            else:
                m = p.search(code)

            if m:
                for op in m.groups():
                    if op.startswith('0x'): continue
                    v = to_int(peda.parse_and_eval(op))
                    chain = self.peda.examine_mem_reference(v)
                    text = '%s        |-- %03s: %s' % (' ' * (prev_depth - 1), op, format_reference_chain(chain))
                    msg(text, teefd=logfd)

            count -= 1

        msg(code, 'red')
        self.peda.restore_user_command('hook-stop')
        logfd.close()
        info('Saved trace information in file %s, view with "less -r file"' % logname)

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
            inst = self.peda.execute_redirect('x/i 0x%x' % pc)
            if not inst:
                return None

        opcode = inst.split(':\t')[-1].split()[0]
        next_addr = self.peda.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        if (
                opcode == 'jmp'
        ) or (
                opcode == 'je' and flags['ZF']
        ) or (
                opcode == 'jne' and not flags['ZF']
        ) or (
                opcode == 'jg' and not flags['ZF'] and (flags['SF'] == flags['OF'])
        ) or (
                opcode == 'jge' and (flags['SF'] == flags['OF'])
        ) or (
                opcode == 'ja' and not flags['CF'] and not flags['ZF']
        ) or (
                opcode == 'jae' and not flags['CF']
        ) or (
                opcode == 'jl' and (flags['SF'] != flags['OF'])
        ) or (
                opcode == 'jle' and (flags['ZF'] or (flags['SF'] != flags['OF']))
        ) or (
                opcode == 'jb' and flags['CF']
        ) or (
                opcode == 'jbe' and (flags['CF'] or flags['ZF'])
        ) or (
                opcode == 'jo' and flags['OF']
        ) or (
                opcode == 'jno' and not flags['OF']
        ) or (
                opcode == 'jz' and flags['ZF']
        ) or (
                opcode == 'jnz' and flags['OF']
        ):
            return next_addr

        return None

    @msg.bufferize
    def context_code(self, *args):
        """
        Display nearby disassembly at $PC of current execution context
        Usage:
            MYNAME [linecount]
        """
        (count,) = normalize_argv(args, 1)

        if count is None:
            count = 8

        if not self._is_running():
            return

        pc = self.peda.getpc()
        if self.peda.is_address(pc):
            inst = self.peda.get_disasm(pc)
        else:
            inst = None

        text = blue('[%s]' % 'CODE'.center(self.width, '-'))
        msg(text)

        if not inst:
            # invalid $PC
            msg('Invalid $PC address: 0x%x' % pc, 'red')
            return

        # valid $PC
        opcode = inst.split(':\t')[-1].split()[0]
        # stopped at function call
        if 'call' in opcode:
            text = self.peda.disassemble_around(pc, count)
            msg(format_disasm_code_intel(text, pc))
            self.dumpargs()
        # stopped at jump
        elif 'j' in opcode:
            jumpto = self._testjump(inst)
            if jumpto:  # JUMP is taken
                code = self.peda.disassemble_around(pc, count)
                code = code.splitlines()
                pc_idx = 999
                text = []
                for (idx, line) in enumerate(code):
                    if ('0x%x' % pc) in line.split(':')[0]:
                        pc_idx = idx
                    if idx <= pc_idx:
                        text.append(line)
                    else:
                        text.append(' | ' + line.strip())
                text = [format_disasm_code_intel(os.linesep.join(text), pc)]
                code = self.peda.get_disasm(jumpto, count // 2)
                if not code:
                    code = '   Cannot evaluate jump destination\n'

                code = code.splitlines()
                text.append(' |->' + red(code[0]))
                for line in code[1:]:
                    text.append('       ' + line.strip())
                text.append(red('JUMP is taken'.rjust(self.width)))
            else:  # JUMP is NOT taken
                text = format_disasm_code_intel(peda.disassemble_around(pc, count), pc) + os.linesep + green(
                    'JUMP is NOT taken'.rjust(self.width))

            msg(text)
        # stopped at other instructions
        else:
            text = self.peda.disassemble_around(pc, count)
            msg(format_disasm_code_intel(text, pc))

    def _get_eflags(self):
        """
        Get flags value from EFLAGS register

        Returns:
            - dictionary of named flags
        """
        eflags = self.peda.getreg('eflags')
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
            reg_eflags = self.peda.getreg('eflags')
            reg_eflags ^= EFLAGS_INDEX[index]
            result = self.peda.execute('set $eflags = 0x%x' % reg_eflags)
            return result

        return True

    def eflags(self, *args):
        """
        Display/set/clear/toggle value of eflags register
        Usage:
            MYNAME
            MYNAME [set|clear] flagname
            MYNAME [set|clear|toggle] flagname
        """
        (option, flagname) = normalize_argv(args, 2)
        if not self._is_running():
            return

        if option and not flagname:
            self._missing_argument()

        if option is None:  # display eflags
            flags = self._get_eflags()
            text = []
            for (i, f) in enumerate(EFLAGS):
                if flags[f]:
                    text.append(red(EFLAGS_TEXT[i].upper(), 'bold'))
                else:
                    text.append(green(EFLAGS_TEXT[i].lower()))

            eflags = self.peda.getreg('eflags')
            msg('%s: 0x%x (%s)' % (green('EFLAGS'), eflags, ' '.join(text)))

        if option == 'set':
            self._set_eflags(flagname.lower(), True)
        elif option == 'clear':
            self._set_eflags(flagname, False)
        elif option == 'toggle':
            self._set_eflags(flagname, None)

    eflags.options = ['set', 'clear', 'toggle']

    def xinfo(self, *args):
        """
        Display detail information of address/registers
        Usage:
            MYNAME address
            MYNAME register [reg1 reg2]
        """

        (address, regname) = normalize_argv(args, 2)
        if address is None:
            self._missing_argument()

        super(IntelPEDACmd, self).xinfo(*args)
        if str(address).startswith('r'):
            if regname is None or 'eflags' in regname:
                self.eflags()

    xinfo.options = ['register']

    ###############################
    #   Exploit Helper Commands   #
    ###############################
    # elfheader()
    def elfheader(self, *args):
        """
        Get headers information from debugged ELF file
        Usage:
            MYNAME [header_name]
        """

        (name,) = normalize_argv(args, 1)
        result = self.peda.elfheader(name)
        if len(result) == 0:
            warning('%s not found, did you specify the FILE to debug?' % (name if name else 'headers'))
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg('%s: 0x%x - 0x%x (%s)' % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg('%s = 0x%x' % (k, start))

    # readelf_header(), elfheader_solib()
    def readelf(self, *args):
        """
        Get headers information from an ELF file
        Usage:
            MYNAME mapname [header_name]
            MYNAME filename [header_name]
        """

        (filename, hname) = normalize_argv(args, 2)
        # result = {}
        # maps = peda.get_vmmap()
        if filename is None:  # fallback to elfheader()
            result = self.peda.elfheader()
        else:
            result = self.peda.elfheader_solib(filename, hname)

        if not result:
            warning('%s or %s not found' % (filename, hname))
            return
        elif len(result) == 1:
            (k, (start, end, type)) = list(result.items())[0]
            msg('%s: 0x%x - 0x%x (%s)' % (k, start, end, type))
        else:
            for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
                msg('%s = 0x%x' % (k, start))


####################
## INITIALIZATION ##
####################

# global instances of PEDA() and PEDACmd()
asm = peda = pedacmd = None

if __name__ == '__main__':
    info('Init PEDA main section.')
    peda = PEDA()
    # skip selector registers
    peda_registers_func = peda.registers
    peda.registers = lambda: [i for i in peda_registers_func() if
                              not i.name.endswith('s') and not i.name.startswith('k')]
    pedacmd = IntelPEDACmd(peda, PEDAFILE)
    pedacmd.help.__func__.options = pedacmd.commands  # XXX HACK

    # register 'peda' command in gdb
    PedaGDBCommand(peda, pedacmd)
    Alias('pead', 'peda')  # just for auto correction

    # create aliases for subcommands
    for cmd in pedacmd.commands:
        func = getattr(pedacmd, cmd)
        func.__func__.__doc__ = func.__doc__.replace('MYNAME', cmd)
        if cmd not in ['help', 'show', 'set']:
            pedacmd._alias(cmd, cmd, False)

    # custom hooks
    peda.define_user_command('hook-stop', 'peda context')

    # custom command aliases, add any alias you want
    pedacmd._alias('phelp', 'help')
    pedacmd._alias('pset', 'set')
    pedacmd._alias('pshow', 'show')
    pedacmd._alias('find', 'searchmem')  # override gdb find command
    pedacmd._alias('stack', 'telescope $sp')
    pedacmd._alias('viewmem', 'telescope')
    pedacmd._alias('reg', 'xinfo register')

    # misc gdb settings
    peda.execute('set prompt \001%s\002' % red('\002gdb-peda > \001'))  # custom prompt
    peda.execute('set disassembly-flavor intel')
    info('Registering commands.')

    info('Checking plugins.')
    pedacmd.plugin()

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
