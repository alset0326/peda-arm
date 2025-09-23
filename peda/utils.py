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

import codecs
import functools
import inspect
import os
import pprint
import re
import stat
import string
import struct
import subprocess
import sys
import tempfile

from . import config
from . import six
from .six import StringIO
from .six.moves import cPickle as pickle
from .six.moves import input
from .six.moves import range
from .six.moves import reload_module as reload

# we use a cache to save all memoized object
_CACHES = []


# http://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
# http://stackoverflow.com/questions/8856164/class-decorator-decorating-method-in-python
class memoized(object):
    """
    Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    """

    def __init__(self, func):
        self.func = func
        self.instance = None  # bind with instance class of decorated method
        self.cache = {}
        self.__doc__ = inspect.getdoc(self.func)
        _CACHES.append(self)

    def __call__(self, *args, **kwargs):
        key = (self.instance, args) + tuple(kwargs.items())
        try:
            return self.cache[key]
        except KeyError:
            if self.instance is None:
                value = self.func(*args, **kwargs)
            else:
                value = self.func(self.instance, *args, **kwargs)
            self.cache[key] = value
            return value
        except TypeError:
            # unhashable -- for instance, passing a list as an argument.
            # Better to not cache than to blow up entirely.
            if self.instance is None:
                return self.func(*args, **kwargs)
            else:
                return self.func(self.instance, *args, **kwargs)

    def __repr__(self):
        """Return the function's docstring."""
        return self.__doc__

    def __get__(self, obj, objtype):
        """Support instance methods."""
        self.instance = obj
        return self

    def reset(self):
        """Reset the cache"""
        # Make list to prevent modifying dictionary while iterating
        self.cache.clear()


def reset_cache():
    for m in _CACHES:
        m.reset()


def tmpfile(pref='peda-', is_binary_file=False):
    """Create and return a temporary file with custom prefix"""

    mode = 'w+b' if is_binary_file else 'w+'
    return tempfile.NamedTemporaryFile(mode=mode, prefix=pref)


# ansicolor definitions
COLORS = {'black': '30', 'red': '31', 'green': '32', 'yellow': '33',
          'blue': '34', 'purple': '35', 'cyan': '36', 'white': '37'}
CATTRS = {'regular': '0', 'bold': '1', 'underline': '4', 'strike': '9',
          'light': '1', 'dark': '2', 'invert': '7'}
CPRE = '\033['
CSUF = '\033[0m'


def colorize(text, color=None, attrib=None):
    """
    Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
    """

    if config.Option.get('ansicolor') != 'on':
        return text

    ccode = []
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(',+|')
            if attr in CATTRS:
                ccode.append(';')
                ccode.append(CATTRS[attr])
    if color in COLORS:
        ccode.append(';')
        ccode.append(COLORS[color])
    return ''.join([CPRE, ''.join(ccode), 'm', text, CSUF])


def len_with_tab(text, cur=0, start=0, end=-1, tab_size=8):
    """
    Get real length of text with tab as spaces
    Args:
        - cur (int): current length when counting
    Returns:
        - with param cur added
    """
    end = end if end > 0 else len(text)
    while start < end:
        i = text.find('\t', start, end)
        if i == -1:
            cur += end - start
            break
        cur += i - start
        cur += tab_size - (cur % tab_size)
        start = i + 1
    return cur


def len_colorized(text, handle_tab=True):
    """
    Get real length of colorized text
    """
    #
    START, END = '\033[', 'm'
    length = 0
    cur = 0
    while True:
        i = text.find(START, cur)
        if i == -1:
            if not handle_tab:
                length += len(text) - cur
            else:
                length = len_with_tab(text, length, cur)
            break
        # todo: handle tab here?
        length += i - cur
        cur = text.find(END, i + 2) + 1
        if cur == -1:
            raise ValueError("invalid ansi color")
    return length


def green(text, attrib=None):
    """Wrapper for colorize(text, 'green')"""
    return colorize(text, 'green', attrib)


def red(text, attrib=None):
    """Wrapper for colorize(text, 'red')"""
    return colorize(text, 'red', attrib)


def yellow(text, attrib=None):
    """Wrapper for colorize(text, 'yellow')"""
    return colorize(text, 'yellow', attrib)


def blue(text, attrib=None):
    """Wrapper for colorize(text, 'blue')"""
    return colorize(text, 'blue', attrib)


class message(object):
    """
    Generic pretty printer with redirection.
    It also suports buffering using bufferize() and flush().
    """

    def __init__(self):
        self.out = sys.stdout
        self.buffering = 0

    def bufferize(self, f=None):
        """Activate message's bufferization, can also be used as a decorater."""

        if f is not None:
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                self.bufferize()
                f(*args, **kwargs)
                self.flush()

            return wrapper

        # If we are still using stdio we need to change it.
        if self.buffering == 0:
            self.out = StringIO()
        self.buffering += 1
        return None

    def flush(self):
        if self.buffering == 0:
            # Tried to flush a message that is not bufferising.
            self.out.flush()
            return
        self.buffering -= 1

        # We only need to flush if this is the lowest recursion level.
        if self.buffering == 0:
            self.out.flush()
            sys.stdout.write(self.out.getvalue())
            self.out = sys.stdout

    def __call__(self, text, color=None, attrib=None, teefd=None):
        if not teefd:
            teefd = config.Option.get('_teefd')

        if isinstance(text, six.string_types) and '\x00' not in text:
            print(colorize(text, color, attrib), file=self.out)
            if teefd:
                print(colorize(text, color, attrib), file=teefd)
        else:
            pprint.pprint(text, self.out)
            if teefd:
                pprint.pprint(text, teefd)


msg = message()


def warning(text):
    """Colorize warning message with prefix"""
    msg('[!] Warning: ' + str(text), 'yellow')


def error(text):
    """Colorize error message with prefix"""
    msg('[!] Error: ' + str(text), 'red')


def debug(text, prefix='Debug'):
    """Colorize debug message with prefix"""
    msg('%s: %s' % (prefix, str(text)), 'cyan')


def info(text):
    """Colorize info message with prefix"""
    msg(green('[*] ') + str(text))


def trim(docstring):
    """
    Handle docstring indentation, ref: PEP257
    """
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    max_indent = sys.maxsize
    indent = max_indent
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < max_indent:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return os.linesep.join(trimmed)


def pager(text, pagesize=None):
    """
    Paging output, mimic external command less/more
    """
    if not pagesize:
        pagesize = config.Option.get('pagesize')

    if pagesize <= 0:
        msg(text)
        return

    i = 1
    text = text.splitlines()
    l = len(text)

    for line in text:
        msg(line)
        if i % pagesize == 0:
            ans = input('--More--(%d/%d)' % (i, l))
            if ans.lower().strip() == 'q':
                break
        i += 1

    return


def execute_external_command(command, cmd_input=None):
    """
    Execute external command and capture its output

    Args:
        - command (String)

    Returns:
        - output of command (String)
    """
    P = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (result, err) = P.communicate(cmd_input)
    if err and config.Option.get('debug') == 'on':
        warning(err)

    return decode_string_escape(result)


def is_printable(text, printables=''):
    """
    Check if a string is printable
    """
    if six.PY3 and isinstance(text, six.string_types):
        text = six.b(text)
    return len(set(text) - set(six.b(string.printable) + six.b(printables))) == 0


def is_math_exp(str):
    """
    Check if a string is a math exprssion
    """
    charset = set('0123456789abcdefx+-*/%^')
    opers = set('+-*/%^')
    exp = set(str.lower())
    return len(exp & opers) > 0 and len(exp - charset) == 0


# def normalize_argv(args, size=0):
#     """
#     Normalize argv to list with predefined length
#     """
#     args = list(args)
#     for (idx, val) in enumerate(args):
#         if to_int(val) is not None:
#             args[idx] = to_int(val)
#         if size and idx == size:
#             return args[:idx]
#
#     if size == 0:
#         return args
#     args.extend([None for _ in range(len(args), size)])
#     return args


def to_hexstr(b):
    """
    Convert a binary string to hex escape format
    """
    return ''.join([r'\x%02x' % ord(i) for i in bytes_iterator(b)])


def to_hex(num):
    """
    Convert a number to hex format
    """
    if num < 0:
        return '-0x%x' % (-num)
    else:
        return '0x%x' % num


def to_address(num):
    """
    Convert a number to address format in hex
    """
    if num < 0:
        return to_hex(num)
    if num > 0xffffffff:  # 64 bit
        return '0x%016x' % num
    else:
        return '0x%08x' % num


def to_int(val, base=0):
    """
    Convert a string to int number
    """
    if val is None:
        return None
    if isinstance(val, six.integer_types):
        return val
    try:
        return int(str(val), base)
    except:
        return None


def str2hex(str):
    """
    Convert a string to hex encoded format
    """
    result = codecs.encode(str, 'hex')
    return result


def hex2str(hexnum, intsize=4):
    """
    Convert one number in hex format to string
    """
    if not isinstance(hexnum, six.string_types):
        nbits = intsize * 8
        hexnum = '0x%x' % ((hexnum + (1 << nbits)) % (1 << nbits))
    s = hexnum[2:]
    if len(s) % 2 != 0:
        s = '0' + s
    result = codecs.decode(s, 'hex')[::-1]
    return result


STRUCT_FORMAT_SIGNED = ('', 'b', 'h', '', 'l', '', '', '', 'q')
STRUCT_FORMAT_UNSIGNED = ('', 'B', 'H', '', 'L', '', '', '', 'Q')


def int2str(num, intsize=4):
    """
    Convert one number to raw string
    """
    if num < 0:
        mark = STRUCT_FORMAT_SIGNED[intsize]
    else:
        mark = STRUCT_FORMAT_UNSIGNED[intsize]
    return struct.pack('<' + mark, num)


def intlist2str(intlist, intsize=4):
    """
    Convert a list of number/string to hexified string
    """
    result = []
    for value in intlist:
        if isinstance(value, six.binary_type):
            result.append(value)
        else:
            result.append(int2str(value, intsize))
    return six.binary_type().join(result)


def str2intlist(data, intsize=4):
    """
    Convert a string to list of int
    """
    data = six.ensure_binary(data, 'ISO-8859-1')
    adjust_mask = intsize - 1
    data = data.ljust((len(data) + adjust_mask) & (~adjust_mask), six.ensure_binary('\x00', 'ISO-8859-1'))
    return struct.unpack('<' + STRUCT_FORMAT_UNSIGNED[intsize] * (len(data) // intsize), data)


def str2int(data, intsize=4):
    """
    Convert a string to a int
    """
    return str2intlist(data, intsize)[0]


@memoized
def check_badchars(data, chars=None):
    """
    Check an address or a value if it contains badchars
    """
    if to_int(data) is None:
        to_search = data
    else:
        data = to_hex(to_int(data))[2:]
        if len(data) % 2 != 0:
            data = '0' + data
        to_search = codecs.decode(data, 'hex')

    if not chars:
        chars = config.Option.get('badchars')

    if chars:
        for c in chars:
            if c in to_search:
                return True
    return False


@memoized
def format_address(addr, type):
    """Colorize an address"""
    colorcodes = {
        'data': 'blue',
        'code': 'red',
        'rodata': 'green',
        'value': None
    }
    return colorize(addr, colorcodes[type])


@memoized
def format_reference_chain(chain):
    """
    Colorize a chain of references
    """
    if not chain:
        return 'Cannot access memory address'
    else:
        v = t = vn = None
        l = []
        first = True
        for (v, t, vn) in chain:
            if t != 'value':
                l.append('%s%s ' % ('--> ' if not first else '', format_address(v, t)))
            else:
                l.append('%s%s ' % ('--> ' if not first else '', v))
            first = False

        if vn:
            l.append('(%s)' % vn)
        else:
            if v != '0x0':
                s = hex2str(v)
                if is_printable(s, '\x00'):
                    l.append('(%s)' % string_repr(s.split(b'\x00')[0]))
        return ''.join(l)


# vulnerable C functions, source: rats/flawfinder
VULN_FUNCTIONS = [
    'exec', 'system', 'gets', 'popen', 'getenv', 'strcpy', 'strncpy', 'strcat', 'strncat',
    'memcpy', 'bcopy', 'printf', 'sprintf', 'snprintf', 'scanf', 'getchar', 'getc', 'read',
    'recv', 'tmp', 'temp'
]


@memoized
def format_disasm_code_with_opcode_color(code, current=None, opcode_color=None):
    """
    Format output of disassemble command with colors to highlight:
        - dangerous functions (rats/flawfinder)
        - branching: jmp, call, ret
        - testing: cmp, test

    Args:
        - code: input asm code (String)
        - current: address for current addr style format (Int)
        - opcode_color: color for opcode (dict{opcode: color})

    Returns:
        - colorized text code (String)
    """
    if not code:
        return ''

    colorcodes = opcode_color if opcode_color else {}

    if to_int(current) is not None:
        target = to_int(current)
    else:
        target = 0

    results = []
    for line in code.splitlines():
        if ':' not in line:  # not an assembly line
            results.append(line)
            continue

        color = style = None
        m = RE.DISASM_LINE_WITH_ADDR_OPCODE.search(line)
        if not m:  # failed to parse
            results.append(line)
            continue

        addr, opcode = m.group(1), m.group(2)
        prefix, suffix = line.split(':\t', 1)

        # first check VULN_FUNCTIONS
        for f in VULN_FUNCTIONS:
            if f in suffix:
                style = 'bold, underline'
                color = 'red'
                break
        else:
            # then check manual color
            for c in colorcodes:
                if opcode.startswith(c):
                    color = colorcodes[c]
                    break
        # handle no color
        if color is None:
            addr = to_int(addr)
            if addr is None:
                addr = -1
            if addr < target:
                style = 'dark'
            elif addr == target:
                style = 'bold'
                color = 'green'
        if '//' in suffix:
            suffix_p, suffix_s = suffix.split('//', 1)
            code = colorize(suffix_p, color, style)
            comment = colorize('//' + suffix_s, color, 'dark')
        else:
            code = colorize(suffix, color, style)
            comment = ''
        line = '%s:\t%s%s' % (prefix, code, comment)
        results.append(line)

    return os.linesep.join(results)


@memoized
def format_disasm_code(code, current=None):
    return format_disasm_code_with_opcode_color(code, current=current, opcode_color=None)


@memoized
def format_disasm_code_arm(code, current=None):
    colorcodes = {
        'cmp': 'red',
        'b': 'yellow',  # jump
    }
    return format_disasm_code_with_opcode_color(code, current=current, opcode_color=colorcodes)


@memoized
def format_disasm_code_intel(code, current=None):
    colorcodes = {
        'cmp': 'red',
        'test': 'red',
        'call': 'green',
        'j': 'yellow',  # jump
        'ret': 'blue',
    }
    return format_disasm_code_with_opcode_color(code, current=current, opcode_color=colorcodes)


def _decode_string_escape_py2(str_):
    """
    Python2 string escape

    Do not use directly, instead use decode_string.
    """
    return str_.decode('string_escape')


def _decode_string_escape_py3(str_):
    """
    Python3 string escape

    Do not use directly, instead use decode_string.
    """

    # Based on: http://stackoverflow.com/a/4020824
    return codecs.decode(str_, 'unicode_escape')


def decode_string_escape(str_):
    """Generic Python string escape"""
    raise NotImplementedError('Should be overridden')


def bytes_iterator(bytes_):
    """
    Returns iterator over a bytestring. In Python 2, this is just a str. In
    Python 3, this is a bytes.

    Wrap this around a bytestring when you need to iterate to be compatible
    with Python 2 and Python 3.
    """
    raise NotImplementedError('Should be overridden')


def _bytes_iterator_py2(bytes_):
    """
    Returns iterator over a bytestring in Python 2.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield b


def _bytes_iterator_py3(bytes_):
    """
    Returns iterator over a bytestring in Python 3.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield bytes([b])


def bytes_chr(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i. In Python 2,
    this is just a str. In Python 3, this is a bytes.

    Use this instead of chr to be compatible with Python 2 and Python 3.
    """
    raise NotImplementedError('Should be overridden')


def _bytes_chr_py2(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i in Python 2.

    Do not call directly, use bytes_chr instead.
    """
    return chr(i)


def _bytes_chr_py3(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i in Python 3.

    Do not call directly, use bytes_chr instead.
    """
    return bytes([i])


def to_binary_string(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Use this instead of six.b when the text may already be a binary type
    """
    raise NotImplementedError('Should be overridden')


def _to_binary_string_py2(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Do not use directly, use to_binary_string instead.
    """
    return str(text)


def _to_binary_string_py3(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Do not use directly, use to_binary_string instead.
    """
    if isinstance(text, six.binary_type):
        return text
    elif isinstance(text, six.string_types):
        return six.b(text)
    else:
        raise Exception('only takes string types')


# Select functions based on Python version
if six.PY2:
    decode_string_escape = _decode_string_escape_py2
    bytes_iterator = _bytes_iterator_py2
    bytes_chr = _bytes_chr_py2
    to_binary_string = _to_binary_string_py2
elif six.PY3:
    decode_string_escape = _decode_string_escape_py3
    bytes_iterator = _bytes_iterator_py3
    bytes_chr = _bytes_chr_py3
    to_binary_string = _to_binary_string_py3
else:
    raise Exception('Could not identify Python major version')


def dbg_print_vars(*args):
    """Prints name and repr of each arg on a separate line"""
    import inspect
    parent_locals = inspect.currentframe().f_back.f_locals
    maps = []
    for arg in args:
        for name, value in parent_locals.items():
            if id(arg) == id(value):
                maps.append((name, repr(value)))
                break
    print(os.linesep.join(name + '=' + value for name, value in maps))


def string_repr(text, show_quotes=True):
    """
    Prints the repr of a string. Eliminates the leading 'b' in the repr in
    Python 3.

    Optionally can show or include quotes.
    """
    if six.PY3 and isinstance(text, six.binary_type):
        # Skip leading 'b' at the beginning of repr
        output = repr(text)[1:]
    else:
        output = repr(text)

    if show_quotes:
        return output
    else:
        return output[1:-1]


def reload_module(name):
    if reload:
        if name in sys.modules:
            module = sys.modules.get(name)
            return reload(module)
    return None


def pickle_loads(s):
    if six.PY3:
        return pickle.loads(s, encoding='iso-8859-1')
    else:
        return pickle.loads(s)


def import_plugin(name):
    return __import__('plugins.' + name, fromlist=['plugins'])


def reload_plugin(name):
    return reload_module('plugins.' + name)


def is_executable_file(path):
    """Checks that path is an executable regular file, or a symlink towards one.
    This is roughly ``os.path isfile(path) and os.access(path, os.X_OK)``.
    """
    # follow symlinks,
    fpath = os.path.realpath(path)

    if not os.path.isfile(fpath):
        # non-files (directories, fifo, etc.)
        return False

    mode = os.stat(fpath).st_mode

    if (sys.platform.startswith('sunos')
            and os.getuid() == 0):
        # When root on Solaris, os.X_OK is True for *all* files, irregardless
        # of their executability -- instead, any permission bit of any user,
        # group, or other is fine enough.
        #
        # (This may be true for other 'Unix98' OS's such as HP-UX and AIX)
        return bool(mode & (stat.S_IXUSR |
                            stat.S_IXGRP |
                            stat.S_IXOTH))

    return os.access(fpath, os.X_OK)


def which(filename, env=None):
    """This takes a given filename; tries to find it in the environment path;
    then checks if it is executable. This returns the full path to the filename
    if found and executable. Otherwise this returns None."""

    # Special case where filename contains an explicit path.
    if os.path.dirname(filename) != '' and is_executable_file(filename):
        return filename
    if env is None:
        env = os.environ
    p = env.get('PATH')
    if not p:
        p = os.defpath
    pathlist = p.split(os.pathsep)
    for path in pathlist:
        ff = os.path.join(path, filename)
        if is_executable_file(ff):
            return ff
    return None


class RE:
    # disasm line to addr and opcode
    # => 0xfffff7dd8500 <__libc_start_main_impl>:     stp     x29, x30, [sp, #-96]!
    DISASM_LINE_WITH_ADDR_OPCODE = re.compile(r'[^0x]*(0x\S*)[^:]*:\s*(\S*)')

    # disasm line to target addr with/without 0x
    # 0xfffff7dd84f8 <__libc_start_call_main+168>: bl      0xfffff7def2f0 <__GI_exit>
    DISASM_LINE_WITH_TARGET_ADDR = re.compile(r'[^:]*:\s*\S*\s*(0x)?(\S*)')

    # disasm line to comment addr. todo: should we check '//' ?
    # 0xfffff7dd84f4 <__libc_start_call_main+164>: mov     w0, #0x0                        // #0
    DISASM_LINE_WITH_COMMENTS = re.compile(r'[^#]+#\s*(0x\S*)')

    # disasm line to content which trim addr
    DISASM_LINE_WITH_CONTENT = re.compile(r'.*0x[^ ]+\s*(.*)')

    # memory access with []
    # DWORD PTR [esi+eax*1]
    MEMORY_ACCESS = re.compile(r'([^\[\]]*)\[([^\[\]]*)]')

    # memory pointer calculator
    # DWORD PTR ds:0xdeadbeef
    MEMORY_POINTER = re.compile(r'([^:]*).s:(0x\S+)')

    # maps in freebsd
    # 0x8048000 0x8049000 1 0 0xc36afdd0 r-x 1 0 0x1000 COW NC vnode /path/to/file NCH -1
    VMMAP_FREEBSD = re.compile(r'0x([0-9a-f]*) 0x([0-9a-f]*)(?: [^ ]*){3} ([rwx-]*)(?: [^ ]*){6} ([^ ]*)')

    # maps in linux
    # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
    VMMAP_LINUX = re.compile(r'^([0-9a-f]+)-([0-9a-f]+) ([-rwxps]+)(?: \S+){3} *(.*)$', re.MULTILINE)

    # find entry addr
    ENTRY_POINT = re.compile(r'Entry point: (\S+)')

    # output of maintenance info sections
    #  [0]      0xaaaaaaaa0238->0xaaaaaaaa0253 at 0x00000238: .interp ALLOC LOAD READONLY DATA HAS_CONTENTS
    MAINTENANCE_INFO_SECTIONS = re.compile(r'^ *\S+ +(0x[^-]+)->(0x[^ ]+) at (\S+): +(\S+) +(.*)$', re.M)

    # get reg name and value from info reg
    # w17            0xf7dd8500          0xf7dd8500
    # cpsr           0x60001000          [ EL=0 BTYPE=0 SSBS C Z ]
    INFO_REGISTERS = re.compile(r'^(\w+)\s+(\w+)\s+.*$', re.M)

    # used to split string with no word
    NOWORD_SPLIT = re.compile(r'\W')

    # output of info files
    #         0x0000fffff7dd7990 - 0x0000fffff7dd7b88 is .rela.plt in /lib/aarch64-linux-gnu/libc.so.6
    INFO_FILES = re.compile(r'^\s*(0x\S+) - (0x\S+) is (\.\S+) in (\S+)$', re.M)

    # used to check which reg in disasm code
    ARM_DISASM_WITH_REGS = re.compile(r':\s*(\S+)\s*(\w+),')

    # used to check str opcode in disasm code
    #  '0x8d08: str     r3, [sp, #20]'
    ARM_DISASM_WITH_STR = re.compile(r':\s*str\s*[^,\s]+,\s*\[sp[^#]*#(\S*)]')

    # used to check jmp opcode b??
    # inst='=> 0x8b84 <_start+40>:\tblxeq.n\t0xa3bc <__libc_start_main>'
    ARM_DISASM_WITH_JMP = re.compile(r'.*:\s+(b[l|x]{0,2})\.?(\S{0}|\S{2})(\.w|\.n)?\s+')

    # used to check cb opcode
    # inst='=> 0xaf130bd4:\tcbz\tr0, 0xaf130be4'
    ARM_DISASM_WITH_CB = re.compile(r'.*:\s+cb(n?z)?\s+(\S+),\s*(\S+)')

    # used to check 'mov [esp, ??]' opcode in disasm code
    INTEL_DISASM_WITH_ESP = re.compile(r'.*mov.*\[esp(.*)],')
