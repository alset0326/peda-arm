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

from lib.utils import *
from lib import config

if config.prefix == '':
    warning('Cross compile toolchain not found! You can install it from https://github.com/jsnyder/arm-eabi-toolchain')


class Asm(object):
    """
    Wrapper class for assemble/disassemble using nasm/ndisassm
    """

    def __init__(self):
        pass

    @staticmethod
    def assemble(asmcode, arch='arm'):
        """
        Assemble ASM instructions using AS
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)
            - arch: arm / aarch64 / thumb / thumb64 assembly

        Returns:
            - bin code (raw bytes)
        """
        # todo aarch64 and thumb64
        gas = config.AS
        assemblers = {
            'arm': gas,
            'aarch64': '%s --64' % gas,
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
        asmcode = asmcode.replace(";", "\n")
        asmcode = decode_string_escape(asmcode)

        infd = tmpfile()
        elffd = tmpfile(is_binary_file=True)
        infd.write(asmcode)
        infd.flush()
        execute_external_command("%s -o %s %s" % (assembler, elffd.name, infd.name))
        infd.close()

        if not os.path.exists(elffd.name):
            # reopen it so tempfile will not complain
            open(elffd.name, 'w').write('B00B')
            return None

        outfd = tmpfile(is_binary_file=True)
        objcopy = '%s -j .text -Obinary %s %s' % (config.OBJCOPY, elffd.name, outfd.name)
        execute_external_command(objcopy)
        elffd.close()
        if not os.path.exists(outfd.name):
            # reopen it so tempfile will not complain
            open(outfd.name, 'w').write('B00B')
            return None
        bincode = outfd.read()
        outfd.close()
        return bincode

    @staticmethod
    def disassemble(buf, arch='arm'):
        """
        Disassemble binary to ASM instructions using OBJCOPY OBJDUMP
            - buf: input binary (raw bytes)
            - arch: arm / aarch64 / thumb / thumb64 assembly

        Returns:
            - ASM code (String)
        """
        # todo aarch64 and thumb64
        if not buf:
            return None

        rawfd = tmpfile(is_binary_file=True)
        elffd = tmpfile(is_binary_file=True)

        objdump = [config.OBJDUMP, '-d', '--adjust-vma', '0', '-b', 'elf32-littlearm']
        objcopy = [config.OBJCOPY,
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

    @staticmethod
    def format_shellcode(buf, arch='arm'):
        """
        Format raw shellcode to disasm output display
            "\x6a\x01"  # 0x00000000:    push byte +0x1
            "\x5b"      # 0x00000002:    pop ebx

        TODO: understand syscall numbers, socket call
        """

        asmcode = Asm.disassemble(buf, arch)

        if not asmcode:
            return ""

        shellcode = []
        # '   0:   e49df004        pop     {pc}            ; (ldr pc, [sp], #4)'
        pattern = re.compile("\s*([0-9a-f]+):\s*([0-9a-f]+)(.+)")

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
