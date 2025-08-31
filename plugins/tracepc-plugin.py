from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from peda.utils import *


def enable_log(peda, filename):
    peda.execute('set logging off')  # prevent nested call
    peda.execute('set height 0')  # disable paging
    peda.execute('set logging file %s' % filename)
    peda.execute('set logging overwrite on')
    peda.execute('set logging redirect on')
    peda.execute('set logging debugredirect on')
    peda.execute('set logging on')


def disable_log(peda):
    peda.execute('set logging off')


def invoke(peda, *args):
    """
    Print pc until target pc
    Usage:
        tracepc target-pc [out-file]
    """

    (target_pc, filename) = normalize_argv(args, 2)
    target_pc = to_int(target_pc)
    if target_pc is None:
        raise Exception()

    peda.deactivate_user_command("hook-stop")  # disable hook-stop to speedup
    info("Stepping through, Ctrl-C to stop...")
    if filename is not None:
        f = open(filename, 'wt')
    else:
        f = sys.stdout

    try:
        cur = peda.getpc()
        while cur != target_pc:
            print(hex(cur), file=f)
            peda.execute("stepi")
            cur = peda.getpc()
    finally:
        if filename is not None:
            f.close()
        peda.restore_user_command("hook-stop")


invoke.options = []
