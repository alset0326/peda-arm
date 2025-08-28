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

# Define syscall dict {number:[function_name,name,params_num,[params...]]}
SYSTEM_CALLS = None

# Define registers
# REGISTERS = {
#     32: ['r' + str(i) for i in range(13)] + 'sp lr pc'.split(),
#     64: ['x' + str(i) for i in range(31)] + 'sp pc'.split()
# }

CPSRS = {
    32: 'N Z C V I F T'.split(),
    64: 'N Z C V SS IL D A I F'.split()
}

CPSR_TEXTS = {
    32: 'negative zero carry overflow no-irq no-fiq thumb'.split(),
    64: 'negative zero carry overflow software-step illegal-execution debug asynchronous-abort no-irq no-fiq'.split()
}

CPSR_N = 1 << 31
CPSR_Z = 1 << 30
CPSR_C = 1 << 29
CPSR_V = 1 << 28
CPSR_SS = 1 << 21
CPSR_IL = 1 << 20
CPSR_D = 1 << 9
CPSR_A = 1 << 8
CPSR_I = 1 << 7
CPSR_F = 1 << 6
CPSR_T = 1 << 5
CPSR_MASKS = {
    32: [CPSR_N, CPSR_Z, CPSR_C, CPSR_V, CPSR_I, CPSR_F, CPSR_T],
    64: [CPSR_N, CPSR_Z, CPSR_C, CPSR_V, CPSR_SS, CPSR_IL, CPSR_D, CPSR_A, CPSR_I, CPSR_F]
}

CPSR_M_MASKS = {
    32: 0b11111,
    64: 0b1111
}
CPSR_M_MODES = {
    32: {0b10000: 'user', 0b10001: 'fiq', 0b10010: 'irq', 0b10011: 'supervisor', 0b10111: 'abort', 0b11011: 'undefined',
         0b11111: 'system'},
    64: {0b0000: 'EL0t', 0b0100: 'El1t', 0b0101: 'EL1h', 0b1000: 'EL2t', 0b1001: 'EL2h', 0b1100: 'EL3t', 0b1101: 'EL3h'}
}


# CPSR = ['T', 'F', 'I', 'V', 'C', 'Z', 'N']
# CPSR_TEXT = ['thumb', 'no-fiq', 'no-irq', 'overflow', 'carry', 'zero', 'negative']
#
# CPSR_INDEX = [CPSR_T, CPSR_F, CPSR_I, CPSR_V, CPSR_C, CPSR_Z, CPSR_N]
# CPSR_M = 0b11111
# CPSR_M_TEXT = ['user', 'fiq', 'irq', 'supervisor', 'abort', 'undefined', 'system']
# CPSR_M_INDEX = [0b10000, 0b10001, 0b10010, 0b10011, 0b10111, 0b11011, 0b11111]
# CPSR_MODES = dict(zip(CPSR_M_INDEX, CPSR_M_TEXT))


class ArmPEDACmd(PEDACmd):
    def _get_function_args_32(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - arm

        Args:
            code: the whole disasm code to search
            argc: args number want to check
        """
        reg_order = ['r0', 'r1', 'r2', 'r3']

        if argc is None:
            # deal with regs
            matches = RE.ARM_DISASM_WITH_REGS.findall(code)
            m = [r for (_, r) in matches]

            args = []
            regs = self.peda.getregs()
            for arg in reg_order:
                if arg in m:
                    args.append(regs[arg])
                else:
                    break

            if len(args) < 4:
                return args
            else:
                # search from disasm
                argc = 0
                #  '0x8d08: str     r3, [sp, #20]'
                matches = RE.ARM_DISASM_WITH_STR.findall(code)
                if matches:
                    l = len(matches)
                    for v in matches:
                        offset = to_int(v)
                        if offset is not None and (offset // 4) > l:
                            continue
                        argc += 1
                else:  # try with push style todo
                    argc = code.count('push')

                argc = min(argc, 6)
                if argc == 0:
                    return args

                args.extend(self.peda.dumpstack(argc))

                return args

        elif to_int(argc) is None:
            return None
        else:
            argc = to_int(argc)
            args = []

            # deal with regs
            regs = self.peda.getregs()
            for reg in reg_order:
                if argc == 0:
                    break
                args.append(regs[reg])
                argc -= 1

            if argc == 0:
                return args

            args.extend(self.peda.dumpstack(argc))
            return args

    def _get_function_args_64(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - x86_64
        """
        reg_order = ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7')

        argc = to_int(argc)
        if argc is None:
            argc = 4
        args = []

        # deal with regs
        regs = self.peda.getregs()
        for reg in reg_order:
            if argc == 0:
                break
            args.append(regs[reg])
            argc -= 1
        else:
            # deal with mem
            args.extend(self.peda.dumpstack(argc))

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

        bits = self.peda.getbits()

        code = []
        if argc is None:
            pc = self.peda.getpc()
            prev_insts = self.peda.prev_inst(pc, 12)
            if not prev_insts:
                return []
            for (addr, inst) in prev_insts[::-1]:
                if inst.strip().startswith('b'):
                    break
                code.append('0x%x:%s' % (addr, inst))
            code.reverse()
        code = os.linesep.join(code)

        if bits == 32:
            args = self._get_function_args_32(code, argc)
        elif bits == 64:
            args = self._get_function_args_64(code, argc)

        return args

    # get_function_args()
    @msg.bufferize
    def dumpargs(self, *arg):
        """
        Display arguments passed to a function when stopped at a call instruction
        Usage:
            MYNAME [count]
                count: force to display 'count args' instead of guessing
        """

        (count,) = normalize_argv(arg, 1)
        if not self._is_running():
            return

        args = self._get_function_args(count)
        if args:
            msg('Guessed arguments:')
            for (i, a) in enumerate(args):
                chain = peda.examine_mem_reference(a)
                msg('arg[%d]: %s' % (i, format_reference_chain(chain)))
        else:
            msg('No argument')

        return

    # return [function_name,name,params_num,[params...],[params_value...]]
    def _get_syscall_args(self, num=None):
        if self.peda.getbits() != 32:
            msg('only support 32 bits')
            return None
        regs = self.peda.getregs()
        if regs is None:
            return None
        r7 = to_int(num)
        if r7 is None:
            r7 = regs['r7']
        if r7 not in SYSTEM_CALLS:
            return None
        function_name, name, params_num, params = SYSTEM_CALLS[r7]
        args = []

        # deal with regs
        for reg in 'r0 r1 r2 r3 r4 r5 r6'.split():
            if params_num == 0:
                break
            args.append(regs[reg])
            params_num -= 1

        if params_num != 0:
            # deal with mem
            args.extend(self.peda.dumpstack(params_num))

        return function_name, name, len(params), params, args

    def syscall(self, *arg):
        """
        Display information at a system call instruction
        Usage:
            MYNAME [num]
                nun: force to display 'system call num' instead of figure out register r7
        """
        if SYSTEM_CALLS is None:
            return

        (num,) = normalize_argv(arg, 1)
        if not self._is_running():
            return

        args = self._get_syscall_args(num)
        if args:
            function_name, name, params_num, params, args = args
            text = [blue('System call:', 'bold'),
                    '        %s' % function_name,
                    blue('Description:', 'bold'),
                    '        %s' % name,
                    blue('Arguments:', 'bold')]
            if params_num == 0:
                text.append('        Argument None')
            else:
                for i in range(params_num):
                    chain = peda.examine_mem_reference(args[i])
                    text.append('        arg[%d]:(%s) %s' % (i, params[i], format_reference_chain(chain)))
            text = '\n'.join(text)
            msg(text)
        else:
            msg('    System call not found!')

        return

    def syscall_detail(self, *arg):
        """
        Display details at a system call instruction
        Usage:
            MYNAME num | syscall_name
                num: force to display 'system call num' instead of figure out register r7
        """
        if SYSTEM_CALLS is None:
            return
        (num,) = normalize_argv(arg, 1)
        if num is None:
            self._missing_argument()
        if to_int(num) is not None:
            func_name = SYSTEM_CALLS[to_int(num)][0]
        else:
            func_name = num
        peda.execute('shell man 2 %s' % func_name)

    # wrapper for stepuntil('j')
    def nextjmp(self, *arg):
        """
        Step until next 'j*' instruction in specific memory range
        Usage:
            MYNAME [keyword] [mapname1,mapname2]
        """
        (keyword, mapname) = normalize_argv(arg, 2)
        if keyword:
            self.stepuntil('b.*%s' % keyword, mapname)
        else:
            self.stepuntil('b', mapname)

    def _testjump(self, inst=None):
        """
        Test if jump instruction is taken or not

        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self._get_cpsr()
        if not flags:
            return None

        if not inst:
            pc = self.peda.getpc()
            inst = self.peda.execute_redirect('x/i 0x%x' % pc)
            if not inst:
                return None

        # inst='=> 0x8b84 <_start+40>:\tblxeq.n\t0xa3bc <__libc_start_main>'
        match = RE.ARM_DISASM_WITH_JMP.match(inst)

        if not match:
            return None

        next_addr = self.peda.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        cond = match.group(2)
        if (
                cond == ''
        ) or (
                cond == 'al'
        ) or (
                cond == 'eq' and flags['Z']
        ) or (
                cond == 'ne' and not flags['Z']
        ) or (
                (cond == 'cs' or cond == 'hs') and flags['C']
        ) or (
                (cond == 'cc' or cond == 'lo') and not flags['C']
        ) or (
                cond == 'mi' and flags['N']
        ) or (
                cond == 'pl' and not flags['N']
        ) or (
                cond == 'vs' and flags['V']
        ) or (
                cond == 'vc' and not flags['V']
        ) or (
                cond == 'hi' and flags['C'] and not flags['Z']
        ) or (
                cond == 'ls' and (not flags['C'] or flags['Z'])
        ) or (
                cond == 'ge' and (flags['Z'] or flags['N'] == flags['V'])
        ) or (
                cond == 'lt' and not flags['Z'] and flags['N'] != flags['V']
        ) or (
                cond == 'gt' and not flags['Z'] and flags['N'] == flags['V']
        ) or (
                cond == 'le' and (flags['Z'] or flags['N'] != flags['V'])
        ):
            return next_addr
        else:
            return None

    def _testjump_cb(self, inst=None):
        """
        Test if jump instruction for `cb` is taken or not

        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self._get_cpsr()
        if not flags:
            return None

        if not inst:
            pc = self.peda.getpc()
            inst = self.peda.execute_redirect('x/i 0x%x' % pc)
            if not inst:
                return None

        # inst='=> 0xaf130bd4:\tcbz\tr0, 0xaf130be4'
        match = RE.ARM_DISASM_WITH_CB.match(inst)
        if not match:
            return None
        cond, r, next_addr = match.groups()
        r = self.peda.parse_and_eval(r)
        r = to_int(r)
        if r is None:
            return None
        next_addr = self.peda.parse_and_eval(next_addr)
        next_addr = to_int(next_addr)
        if next_addr is None:
            next_addr = 0

        if (
                cond == 'z' and r == 0
        ) or (
                cond == 'nz' and r != 0
        ):
            return next_addr
        else:
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

        peda = self.peda
        pc = peda.getpc()
        if peda.is_address(pc):
            inst = peda.get_disasm(pc)
        else:
            inst = None

        text = blue('[%s]' % 'CODE'.center(self.width, '-'))
        msg(text)
        if not inst:  # valid $PC
            msg('Invalid $PC address: 0x%x' % pc, 'red')
            return

        opcode = inst.split(':\t')[-1].split()[0]
        if opcode.startswith('b'):  # check if is b?? opcode
            jumpto = self._testjump(inst)
            if jumpto:  # JUMP is taken
                code = peda.disasm_add_regs_comments(peda.disassemble_around(pc, count))
                pc_idx = 999
                text = []
                for (idx, line) in enumerate(code.splitlines()):
                    if ('0x%x' % pc) in line.split(':')[0]:
                        pc_idx = idx
                    if idx <= pc_idx:
                        text.append(line)
                    else:
                        text.append(' | ' + line.strip())
                text = [format_disasm_code_arm(os.linesep.join(text), pc)]
                if 'x' in opcode:
                    current_mode = peda.execute_redirect('show arm force-mode')
                    match = re.search(r'"(\S *)"', current_mode)
                    if match:
                        current_mode = match.group(1)
                    else:
                        current_mode = 'auto'
                    peda.execute_redirect('set arm force-mode %s' % ('thumb' if jumpto & 0x1 else 'arm'))
                    code = peda.get_disasm(jumpto, count // 2)
                    peda.execute_redirect('set arm force-mode %s' % current_mode)
                else:
                    code = peda.get_disasm(jumpto, count // 2)
                if not code:
                    code = '   Cannot evaluate jump destination\n'
                code = code.splitlines()
                text.append(' |->' + red(code[0]))
                for line in code[1:]:
                    text.append('       ' + line.strip())
                text.append(red('JUMP is taken'.rjust(self.width)))
                msg(os.linesep.join(text))
                self.dumpargs()
            else:  # JUMP is NOT taken
                text = format_disasm_code_arm(
                    peda.disasm_add_regs_comments(peda.disassemble_around(pc, count)), pc
                ) + os.linesep + green('JUMP is NOT taken'.rjust(self.width))
                msg(text.rstrip())
        elif opcode.startswith('cb'):
            jumpto = self._testjump_cb(inst)
            if jumpto:  # JUMP is taken
                code = peda.disasm_add_regs_comments(peda.disassemble_around(pc, count))
                pc_idx = 999
                text = []
                for (idx, line) in enumerate(code.splitlines()):
                    if ('0x%x' % pc) in line.split(':')[0]:
                        pc_idx = idx
                    if idx <= pc_idx:
                        text.append(line)
                    else:
                        text.append(' | ' + line.strip())
                text = [format_disasm_code_arm(os.linesep.join(text), pc)]
                code = peda.get_disasm(jumpto, count // 2)
                if not code:
                    code = '   Cannot evaluate jump destination\n'
                code = code.splitlines()
                text.append(' |->' + red(code[0]))
                for line in code[1:]:
                    text.append('       ' + line.strip())
                text.append(red('JUMP is taken'.rjust(self.width)))
                msg(os.linesep.join(text))
            else:  # JUMP is NOT taken
                text = format_disasm_code_arm(
                    peda.disasm_add_regs_comments(peda.disassemble_around(pc, count)), pc
                ) + os.linesep + green('JUMP is NOT taken'.rjust(self.width))
                msg(text)
        # stopped at other instructions
        else:
            text = peda.disasm_add_regs_comments(peda.disassemble_around(pc, count))
            msg(format_disasm_code_arm(text, pc))
            if 'svc' in opcode:
                msg('')
                self.syscall()

    def _get_cpsr(self):
        """
        Get flags value from CPSR register

        Returns:
            - dictionary of named flags
        """

        # need indeed
        cpsr = self.peda.getreg('cpsr')
        # if not cpsr:
        #    return None

        bits = self.peda.getbits()
        CPSR = CPSRS[bits]
        CPSR_MASK = CPSR_MASKS[bits]
        flags = {}
        for i in range(len(CPSR)):
            flags[CPSR[i]] = bool(cpsr & CPSR_MASK[i])
        return flags

    def _get_mode(self):
        cpsr = self.peda.getreg('cpsr')
        if not cpsr:
            return None
        bits = self.peda.getbits()
        mode = cpsr & CPSR_M_MASKS[bits]
        CPSR_MODES = CPSR_M_MODES[bits]
        if mode in CPSR_MODES:
            return CPSR_MODES[mode].upper()
        else:
            return None

    def _set_cpsr(self, flagname, value):
        """
        Set/clear/toggle value of a flag register

        Returns:
            - True if success (Bool)
        """

        #  like above
        cpsr = self._get_cpsr()
        if not cpsr:
            return False

        bits = self.peda.getbits()
        CPSR = CPSRS[bits]
        CPSR_TEXT = CPSR_TEXTS[bits]
        CPSR_MASK = CPSR_MASKS[bits]

        if flagname.upper() in CPSR:
            index = CPSR.index(flagname.upper())
        elif flagname.lower() in CPSR_TEXT:
            index = CPSR_TEXT.index(flagname.lower())
        else:
            return False

        if value is None or cpsr[CPSR[index]] != value:  # switch value
            reg_cpsr = self.peda.getreg('cpsr')
            reg_cpsr ^= CPSR_MASK[index]
            result = self.peda.execute('set $cpsr = 0x%x' % reg_cpsr)
            return result

        return True

    def cpsr(self, *arg):
        """
        Display/set/clear value of cpsr register
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

        if option is None:  # display cpsr
            bits = self.peda.getbits()
            CPSR = CPSRS[bits]
            CPSR_TEXT = CPSR_TEXTS[bits]

            text = []
            flags = self._get_cpsr()
            for (i, f) in enumerate(CPSR):
                if flags[f]:
                    text.append(red(CPSR_TEXT[i].upper(), 'bold'))
                else:
                    text.append(green(CPSR_TEXT[i].lower()))
            text.append(blue('[%s-MODE]' % self._get_mode()))
            text = ' '.join(text)

            cpsr = peda.getreg('cpsr')
            msg('%s: 0x%x (%s)' % (green('CPSR'), cpsr, text))

        elif option == 'set':
            self._set_cpsr(flagname.lower(), True)

        elif option == 'clear':
            self._set_cpsr(flagname, False)

        elif option == 'toggle':
            self._set_cpsr(flagname, None)

    cpsr.options = ['set', 'clear']

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

        super(ArmPEDACmd, self).xinfo(*arg)
        if str(address).startswith('r'):
            if regname is None or 'cpsr' in regname:
                self.cpsr()

    xinfo.options = ['register']


###########################################################################
# INITIALIZATION #
# global instances of PEDA() and PEDACmd() and Asm(). Maybe not global?
asm = peda = pedacmd = None

if __name__ == '__main__':
    info('Init PEDA main section.')
    peda = PEDA()
    pedacmd = ArmPEDACmd(peda, PEDAFILE)
    pedacmd.help.__func__.options = pedacmd.commands  # XXX HACK

    # register 'peda' command in gdb
    info('Registering commands.')
    pedaGDBCommand(peda, pedacmd)
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

    Alias('arm', 'set arm force-mode arm')
    Alias('thumb', 'set arm force-mode thumb')
    Alias('auto', 'set arm force-mode auto')

    PEDA.execute('set prompt \001%s\002' % red('\002peda-arm > \001'))  # custom prompt

    # Check syscalls
    if zlib:
        info('Loading system calls.')
        with open(os.path.dirname(PEDAFILE) + '/peda/arm/system_calls', 'rb') as f:
            # {number:[function_name,name,params_num,[params...]]}
            SYSTEM_CALLS = pickle_loads(zlib.decompress(f.read()))
    else:
        warning('zlib module not supported. Syscall lookup is disabled.')

    info('Checking plugins.')
    pedacmd.plugin()

    # Check logos
    msg('')

    if zlib:
        with open(os.path.dirname(PEDAFILE) + '/peda/arm/logos', 'rb') as f:
            logos = pickle_loads(zlib.decompress(f.read()))
        msg(logos[random.randint(0, len(logos) - 1)], 'blue', 'bold')
        msg(__version__.rjust(random.randint(10, len(logos) + 10)), 'red')
    else:
        msg(('PEDA-ARM ' + __version__).rjust(random.randint(10, 50)), 'red')
    msg(os.linesep)
