from peda import *


class Nasm:
    """
    Wrapper class for assemble/disassemble using nasm/ndisassm
    """
    READELF = '/usr/bin/readelf'
    OBJDUMP = '/usr/bin/objdump'
    NASM = '/usr/bin/nasm'
    NDISASM = '/usr/bin/ndisasm'

    @staticmethod
    def assemble(asmcode, mode=32):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ';' (String)
            - mode: 16/32/64 bits assembly

        Returns:
            - bin code (raw bytes)
        """
        asmcode = asmcode.strip('"').strip("'")
        asmcode = asmcode.replace(';', '\n')
        asmcode = ('BITS %d\n' % mode) + asmcode
        asmcode = decode_string_escape(asmcode)
        asmcode = re.sub('PTR|ptr|ds:|DS:', "", asmcode)
        infd = tmpfile()
        outfd = tmpfile(is_binary_file=True)
        infd.write(asmcode)
        infd.flush()
        execute_external_command('%s -f bin -o %s %s' % (Nasm.NASM, outfd.name, infd.name))
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
        out = execute_external_command('%s -b %d -' % (Nasm.NDISASM, mode), buf)
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
            pattern = re.compile(r'([0-9A-F]{8})\s*([^\s]*)\s*(.*)')

            # matches = pattern.findall(asmcode)
            for line in asmcode.splitlines():
                m = pattern.match(line)
                if m:
                    (addr, bytes, code) = m.groups()
                    sc = '"0x%s"' % bytes
                    shellcode += [(sc, '0x' + addr, code.strip())]

            maxlen = max([len(x[0]) for x in shellcode])
            text = ""
            for (sc, addr, code) in shellcode:
                text += '%s # %s:    %s\n' % (sc.ljust(maxlen + 1), addr, code)

            return text

        out = execute_external_command('%s -b %d -' % (Nasm.NDISASM, mode), buf)
        return nasm2shellcode(out)


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
    out = execute_external_command('%s -W -S %s' % (Nasm.READELF, filename))
    if not out:
        return {}
    p = re.compile(r'^ *\[ *\d*] +(\S+) +\S+ +(\S+) +\S+ +(\S*)(.*)$', re.M)
    matches = p.findall(out)
    if not matches:
        return None

    for (hname, start, size, attr) in matches:
        start, end = to_int('0x' + start), to_int('0x' + start) + to_int('0x' + size)
        # if PIE binary or DSO, update with runtime address
        if start < elfbase:
            start += elfbase
        if end < elfbase:
            end += elfbase

        if 'X' in attr:
            htype = 'code'
        elif 'W' in attr:
            htype = 'data'
        else:
            htype = 'rodata'
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
# todo: merge with plugin?
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
        warning('%s or %s not found' % (filename, hname))
    elif len(result) == 1:
        (k, (start, end, type)) = list(result.items())[0]
        msg('%s: 0x%x - 0x%x (%s)' % (k, start, end, type))
    else:
        for (k, (start, end, type)) in sorted(result.items(), key=lambda x: x[1]):
            msg('%s = 0x%x' % (k, start))


def assemble(peda, mode, address):
    """
    On the fly assemble and execute instructions using NASM.  Auto exec when changing instruction at pc.
    Usage:
        MYNAME [mode] [address]
            mode: -b16 / -b32 / -b64
    """

    exec_mode = write_mode = False
    if to_int(mode) is not None:
        address, mode = mode, None

    (arch, bits) = peda.getarch()
    if mode is None:
        mode = bits
    else:
        mode = to_int(mode[2:])
        if mode not in [16, 32, 64]:
            raise NotImplementedError('invalid mode: %s' % mode)

    if peda.getpid() != 0 and address == peda.getpc():
        write_mode = exec_mode = True

    if address is None or mode != bits:
        write_mode = exec_mode = False
    elif peda.is_address(address):
        write_mode = True

    if write_mode:
        msg('Instruction will be written to 0x%x. '
            'Command "set write on" can be used to patch the binary file.' % address)
    else:
        msg('Instructions will be written to stdout')

    msg('Type instructions (NASM syntax), one or more per line separated by ";"')
    msg('End with a line saying just "end"')

    if not write_mode:
        address = 0xdeadbeef

    inst_list = []
    inst_code = b""
    # fetch instruction loop
    while True:
        try:
            inst = input('iasm|0x%x> ' % address)
        except EOFError:
            msg('')
            break
        if inst == 'end':
            break
        if inst == "":
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

    text = Nasm.format_shellcode(b"".join([x[1] for x in inst_list]), mode)
    if text:
        msg('Assembled%s instructions:' % ('/Executed' if exec_mode else ""))
        msg(text)
        msg('hexify: "%s"' % to_hexstr(inst_code))


def invoke(peda, *arg):
    """
    Sample invoke
    Usage:
        intelasm [mode] [address]
            mode: -b16 / -b32 / -b64
    """
    (mode, address) = normalize_argv(arg, 2)
    assemble(peda, mode, address)


invoke.options = ['-b16', '-b32', '-b64']
