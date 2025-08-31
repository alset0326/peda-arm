# copy from peda, we split it out to a separate plugin
import re

from peda import config, to_int, hex2str, to_binary_string, normalize_argv, info, msg, to_hex, to_address, warning, \
    error

__all__ = ['invoke']


def _missing_argument(func):
    error('missing argument')
    msg(func.__doc__)


def cyclic_pattern_charset(charset_type=None):
    """
    Generate charset for cyclic pattern

    Args:
        - charset_type: charset type
            0: basic (0-9A-Za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - list of charset
    """

    charset = []
    charset += ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"]  # string.uppercase
    charset += ["abcdefghijklmnopqrstuvwxyz"]  # string.lowercase
    charset += ["0123456789"]  # string.digits

    if not charset_type:
        charset_type = config.Option.get("pattern")

    if charset_type == 1:  # extended type
        charset[1] = "%$-;" + re.sub("[sn]", "", charset[1])
        charset[2] = "sn()" + charset[2]

    if charset_type == 2:  # maximum type
        charset += ['!"#$%&\()*+,-./:;<=>?@[]^_{|}~']  # string.punctuation

    mixed_charset = mixed = ''
    k = 0
    while True:
        for i in range(0, len(charset)): mixed += charset[i][k:k + 1]
        if not mixed: break
        mixed_charset += mixed
        mixed = ''
        k += 1

    return mixed_charset


def de_bruijn(charset, n, maxlen):
    """
    Generate the De Bruijn Sequence up to `maxlen` characters for the charset `charset`
    and subsequences of length `n`.
    Algorithm modified from wikipedia http://en.wikipedia.org/wiki/De_Bruijn_sequence
    """
    k = len(charset)
    a = [0] * k * n
    sequence = []

    def db(t, p):
        if len(sequence) == maxlen:
            return

        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(charset[a[j]])
                    if len(sequence) == maxlen:
                        return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return ''.join(sequence)


def cyclic_pattern(size=None, start=None, charset_type=None):
    """
    Generate a cyclic pattern

    Args:
        - size: size of generated pattern (Int)
        - start: the start offset of the generated pattern (Int)
        - charset_type: charset type
            0: basic (0-9A-Za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - pattern text (byte string) (str in Python 2; bytes in Python 3)
    """
    charset = config.Option.get("p_charset")
    if not charset:
        charset = cyclic_pattern_charset(charset)
    else:
        charset = ''.join(set(charset))

    if start is None:
        start = 0
    if size is None:
        size = 0x10000

    size += start

    pattern = de_bruijn(charset, 3, size)

    return pattern[start:size].encode('utf-8')


def cyclic_pattern_offset(value):
    """
    Search a value if it is a part of cyclic pattern

    Args:
        - value: value to search for (String/Int)

    Returns:
        - offset in pattern if found
    """
    pattern = cyclic_pattern()
    if to_int(value) is None:
        search = value.encode('utf-8')
    else:
        search = hex2str(to_int(value))

    pos = pattern.find(search)
    return pos if pos != -1 else None


def cyclic_pattern_search(buf):
    """
    Search all cyclic pattern pieces in a buffer

    Args:
        - buf: buffer to search for (String)

    Returns:
        - list of tuple (buffer_offset, pattern_len, pattern_offset)
    """
    result = []
    pattern = cyclic_pattern()

    p = re.compile(b"[" + re.escape(to_binary_string(cyclic_pattern_charset())) + b"]{4,}")
    found = p.finditer(buf)
    found = list(found)
    for m in found:
        s = buf[m.start():m.end()]
        i = pattern.find(s)
        k = 0
        while i == -1 and len(s) > 4:
            s = s[1:]
            k += 1
            i = pattern.find(s)
        if i != -1:
            result += [(m.start() + k, len(s), i)]

    return result


# cyclic_pattern()
def pattern_create(*args):
    """
    Generate a cyclic pattern
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic create size [file]
    """

    (size, filename) = normalize_argv(args, 2)
    if size is None:
        _missing_argument(pattern_create)
        return

    pattern = cyclic_pattern(size)
    if filename is not None:
        open(filename, "wb").write(pattern)
        info("Writing pattern of %d chars to filename \"%s\"" % (len(pattern), filename))
    else:
        msg("'" + pattern.decode('utf-8') + "'")


# cyclic_pattern()
def pattern_offset(*args):
    """
    Search for offset of a value in cyclic pattern
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic offset value
    """

    (value,) = normalize_argv(args, 1)
    if value is None:
        _missing_argument(pattern_offset)
        return

    pos = cyclic_pattern_offset(value)
    if pos is None:
        msg("%s not found in pattern buffer" % value)
    else:
        msg("%s found at offset: %d" % (value, pos))


# cyclic_pattern(), searchmem_*()
def pattern_search(*args):
    """
    Search a cyclic pattern in registers and memory
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic search
    """

    def nearby_offset(v):
        for offset in range(-128, 128, 4):
            pos = cyclic_pattern_offset(v + offset)
            if pos is not None:
                return (pos, offset)
        return None

    if peda.getpid() == 0:
        return

    reg_result = {}
    regs = peda.getregs()

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
        if not peda.is_address(v): continue
        chain = peda.examine_mem_reference(v)
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
    maps = peda.get_vmmap()
    search_result = []
    for (start, end, perm, name) in maps:
        if "w" not in perm: continue  # only search in writable memory
        res = cyclic_pattern_search(peda.dumpmem(start, end))
        for (a, l, o) in res:
            a += start
            search_result += [(a, l, o)]

    sp = peda.getreg("sp")
    if search_result:
        msg("Pattern buffer found at:", "green")
        for (a, l, o) in search_result:
            ranges = peda.get_vmrange(a)
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
        res = peda.searchmem_by_range("all", "0x%x" % a)
        ref_result += [(x[0], a) for x in res]
    if len(ref_result) > 0:
        msg("References to pattern buffer found at:", "blue")
        for (a, v) in ref_result:
            ranges = peda.get_vmrange(a)
            text = "%s : %s" % (to_address(a), to_address(v))
            if ranges[3] == "[stack]":
                text += " ($sp + %s [%d dwords])" % (to_hex(a - sp), (a - sp) // 4)
            else:
                text += " (%s)" % ranges[3]
            msg(text)
    else:
        msg("Reference to pattern buffer not found in memory")


# cyclic_pattern(), writemem()
def pattern_patch(*args):
    """
    Write a cyclic pattern to memory
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic patch address size
    """

    (address, size) = normalize_argv(args, 2)
    if size is None:
        _missing_argument(pattern_patch)
        return

    pattern = cyclic_pattern(size)
    num_bytes_written = peda.writemem(address, pattern)
    if num_bytes_written:
        info("Written %d chars of cyclic pattern to 0x%x" % (size, address))
    else:
        warning("Failed to write to memory")


# cyclic_pattern()
def pattern_arg(*args):
    """
    Set argument list with cyclic pattern
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic arg size1 [size2,offset2] ...
    """

    if not args:
        _missing_argument(pattern_arg)
        return

    arglist = []
    for a in args:
        (size, offset) = (a + ",").split(",")[:2]
        if offset:
            offset = to_int(offset)
        else:
            offset = 0
        size = to_int(size)
        if size is None or offset is None:
            _missing_argument(pattern_arg)
            return

        # try to generate unique, non-overlapped patterns
        if arglist and offset == 0:
            offset = sum(arglist[-1])
        arglist += [(size, offset)]

    patterns = []
    for (s, o) in arglist:
        patterns += ["\'%s\'" % cyclic_pattern(s, o).decode('utf-8')]
    peda.execute("set arg %s" % " ".join(patterns))
    info("Set %d arguments to program" % len(patterns))


# cyclic_pattern()
def pattern_env(*args):
    """
    Set environment variable with a cyclic pattern
    Set "pattern" option for basic/extended pattern type
    Usage:
        cyclic env ENVNAME size[,offset]
    """

    (env, size) = normalize_argv(args, 2)
    if size is None:
        _missing_argument(pattern_env)
        return

    (size, offset) = (args[1] + ",").split(",")[:2]
    size = to_int(size)
    if offset:
        offset = to_int(offset)
    else:
        offset = 0
    if size is None or offset is None:
        _missing_argument(pattern_env)
        return

    peda.execute("set env %s %s" % (env, cyclic_pattern(size, offset).decode('utf-8')))
    info("Set environment %s = cyclic_pattern(%d, %d)" % (env, size, offset))


def invoke(_peda, *args):
    """
       Generate, search, or write a cyclic pattern to memory
       Set "pattern" option for basic/extended pattern type
       Usage:
           cyclic create size [file]
           cyclic offset value
           cyclic search
           cyclic patch address size
           cyclic arg size1 [size2,offset2]
           cyclic env size[,offset]
       """
    global peda
    peda = _peda
    (opt,) = normalize_argv(args, 1)
    if opt is None or opt not in invoke.options:
        raise Exception()

    func = globals()["pattern_%s" % opt]
    func(*args[1:])


invoke.options = ["create", "offset", "search", "patch", "arg", "env"]
