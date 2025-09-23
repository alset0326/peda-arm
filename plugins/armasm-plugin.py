from peda.six.moves import input

from peda import *


class Asm:
    """
    Wrapper class for assemble/disassemble using as
    """

    def __init__(self):
        # Check cross compile toolchains
        PREFIXES = 'arm-none-eabi- arm-eabi- arm-androideabi- arm-none-linux-gnueabi- arm-linux-androideabi- ' \
                   'arm-linux-android- arm-linux-eabi- arm-linux-gnueabi- arm-linux-gnueabihf-'
        prefix = None
        for i in PREFIXES.split():
            if self.exist_toolchain(i):
                prefix = i
                break
        self.set_prefix(prefix)

    @staticmethod
    def exist_toolchain(prefix):
        command = '%sobjdump' % prefix
        return which(command) is not None

    def set_prefix(self, prefix):
        self.PREFIX = prefix
        if prefix is None:
            warning('Cross compile toolchain not found! '
                    'You can install it from https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads')
            return
        self.READELF = '%sreadelf' % prefix
        self.OBJDUMP = '%sobjdump' % prefix
        self.OBJCOPY = '%sobjcopy' % prefix
        self.AS = '%sas' % prefix

    def assemble(self, asmcode, arch='arm'):
        """
        Assemble ASM instructions using AS
            - asmcode: input ASM instructions, multiple instructions are separated by ';' (String)
            - arch: arm / aarch64 / thumb / thumb64 assembly

        Returns:
            - bin code (raw bytes)
        """
        if self.PREFIX is None:
            warning('Cross compile toolchain not found! ')
            return
        # todo: thumb64
        gas = self.AS
        assemblers = {
            'arm': '%s -marmv7-a' % gas,
            'aarch64': '%s -march=armv8-a' % gas,
            'thumb': '%s -mthumb' % gas
        }
        arch = arch.lower()
        if '6' in arch:
            arch = 'aarch64'
        elif arch.startswith('t'):
            arch = 'thumb'
        else:
            arch = 'arm'
        assembler = assemblers[arch]

        asmcode = asmcode.strip('"').strip("'")
        asmcode = asmcode.replace(';', '\n')
        asmcode = decode_string_escape(asmcode)

        infd = tmpfile()
        elffd = tmpfile(is_binary_file=True)
        print(asmcode, file=infd)  # add a newline
        infd.flush()
        execute_external_command('%s -o %s %s' % (assembler, elffd.name, infd.name))
        infd.close()

        if not os.path.exists(elffd.name):
            # reopen it so tempfile will not complain
            open(elffd.name, 'w').write('B00B')
            return None

        outfd = tmpfile(is_binary_file=True)
        objcopy = '%s -j .text -Obinary %s %s' % (self.OBJCOPY, elffd.name, outfd.name)
        execute_external_command(objcopy)
        elffd.close()
        if not os.path.exists(outfd.name):
            # reopen it so tempfile will not complain
            open(outfd.name, 'w').write('B00B')
            return None
        bincode = outfd.read()
        outfd.close()
        return bincode

    def disassemble(self, buf, arch='arm'):
        """
        Disassemble binary to ASM instructions using OBJCOPY OBJDUMP
            - buf: input binary (raw bytes)
            - arch: arm / aarch64 / thumb / thumb64 assembly

        Returns:
            - ASM code (String)
        """
        if self.PREFIX is None:
            warning('Cross compile toolchain not found! ')
            return
        # todo aarch64 and thumb64
        if not buf:
            return None

        rawfd = tmpfile(is_binary_file=True)
        elffd = tmpfile(is_binary_file=True)

        objdump = [self.OBJDUMP, '-d', '--adjust-vma', '0', '-b', 'elf32-littlearm']
        objcopy = [self.OBJCOPY,
                   '-I', 'binary',
                   '-O', 'elf32-littlearm',
                   '-B', 'arm',
                   '--set-section-flags', '.data=code',
                   '--rename-section', '.data=.text',
                   ]

        if 'thumb' in arch:
            objcopy += ['--prefix-symbol=\\$t.']
        else:
            objcopy += ['-w', '-N', '\\*']

        rawfd.write(buf)
        rawfd.flush()

        execute_external_command(' '.join(objcopy + [rawfd.name, elffd.name]))
        out = execute_external_command(' '.join(objdump + [elffd.name]))
        out = out.split('<.text>:\n')

        if len(out) != 2:
            return None

        result = out[1].strip('\n').rstrip().expandtabs()
        return result

    def format_shellcode(self, buf, arch='arm'):
        """
        Format raw shellcode to disasm output display
            "\x6a\x01"  # 0x00000000:    push byte +0x1
            "\x5b"      # 0x00000002:    pop ebx

        """
        if self.PREFIX is None:
            warning('Cross compile toolchain not found! ')
            return

        asmcode = self.disassemble(buf, arch)

        if not asmcode:
            return ''

        shellcode = []
        # '   0:   e49df004        pop     {pc}            ; (ldr pc, [sp], #4)'
        pattern = re.compile(r'\s*([0-9a-f]+):\s*([0-9a-f]+)(.+)')

        # matches = pattern.findall(asmcode)
        for line in asmcode.splitlines():
            m = pattern.match(line)
            if m:
                (addr, bytes, code) = m.groups()
                sc = '"0x%s"' % bytes
                shellcode += [(sc, '0x' + addr, code.strip())]


info('Checking cross compile toolchains')
asm = Asm()


def _is_thumb(peda):
    """
    Get T flags value from CPSR register

    Returns: 0/1
    """
    bits = peda.getbits()
    if bits != 32:
        return False
    cpsr = peda.getreg('cpsr')
    CPSR_T = 1 << 5
    return bool(cpsr & CPSR_T)


def assemble(peda, mode, address):
    """
    On the fly assemble and execute instructions using AS. Auto exec when changing instruction at pc.
    Usage:
        MYNAME [mode] [address]
            mode: arm / aarch64 / thumb / thumb64
    """

    exec_mode = write_mode = False
    if to_int(mode) is not None:
        address, mode = mode, None

    if mode is None:
        bits = peda.getbits()
        if not peda.getreg('cpsr'):
            error('Not attached. Need to specify a MODE!')
            mode = 'error'
        elif _is_thumb(peda):
            mode = 'thumb' if bits == 32 else 'thumb64'
        else:
            mode = 'arm' if bits == 32 else 'aarch64'
    if mode not in ('arm', 'aarch64', 'thumb', 'thumb64'):
        raise NotImplementedError('Invalid mode')

    if peda.getpid() != 0 and address == peda.getpc():
        write_mode = exec_mode = True

    if address is None:
        write_mode = exec_mode = False
    elif peda.is_address(address):
        write_mode = True

    if write_mode:
        msg('Instruction will be written to 0x%x. '
            'Command "set write on" can be used to patch the binary file.' % address)
    else:
        msg('Instructions will be written to stdout')

    msg('Type instructions (%s syntax), one or more per line separated by ";".' % red(mode.upper()))
    msg('End with a line saying just "end".')

    if not write_mode:
        address = 0xdeadbeef

    inst_list = []
    inst_code = b''
    # fetch instruction loop
    while True:
        try:
            inst = input('%s|0x%x> ' % (mode, address))
        except EOFError:
            msg('')
            break
        if inst == 'end':
            break
        if inst == '':
            continue
        bincode = asm.assemble(inst, mode)
        if bincode is None:
            continue
        size = len(bincode)
        if size == 0:
            continue
        inst_list.append((size, bincode, inst))
        if write_mode:
            peda.writemem(address, bincode)
        # execute assembled code
        if exec_mode:
            peda.execute('stepi %d' % (inst.count(';') + 1))

        address += size
        inst_code += bincode
        msg('hexify: "%s"' % to_hexstr(bincode))

    msg('total hexify: "%s"' % to_hexstr(inst_code))

    text = asm.format_shellcode(b''.join([x[1] for x in inst_list]), mode)
    if text:
        msg('Assembled%s instructions:' % ('/Executed' if exec_mode else ''))
        msg(text)

    return


def invoke(peda, *args):
    """
    Sample invoke
    Usage:
        armasm [mode] [address]
            mode: arm / aarch64 / thumb / thumb64
    """
    if asm.PREFIX is None:
        warning('Cross compile toolchain not found! ')
        prefix = input('Input correct toolchain prefix >>')
        if not asm.exist_toolchain(prefix):
            error('Invalid toolchain prefix')
            return
        asm.set_prefix(prefix)

    (mode, address) = peda.normalize_argv(args, 2)
    assemble(peda, mode, address)


invoke.options = ['arm', 'thumb']
