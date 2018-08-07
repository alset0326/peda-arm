import os
import sys
import subprocess

from peda.utils import normalize_argv, error
from peda.core import PEDA

filepath = os.path.abspath(os.path.expanduser(__file__))
dirpath = os.path.dirname(filepath)
libheappath = os.path.join(dirpath, 'libheap')

if not os.path.exists(libheappath):
    git_path = 'https://github.com/cloudburst/libheap.git'
    cmd = (' '.join(['git', 'clone', git_path, libheappath]))
    err = subprocess.call(cmd, shell=True)
    if err != 0:
        error('git clone failed. Please reload plugin.')

# insert after peda
sys.path.insert(1, libheappath)

try:
    from libheap import *
except ImportError:
    pass


def invoke(peda, *arg):
    update, = normalize_argv(arg, 1)

    if update is not None and update.startswith('u'):
        cmd = ' '.join(['cd', libheappath, ';', 'git', 'pull', '--all'])
        err = subprocess.call(cmd, shell=True)
        if err != 0:
            error('git pull failed. Please reload plugin.')

    peda.execute('heap -h')


invoke.__doc__ = 'Use "libheap u" to update libheap\n' + PEDA.execute_redirect('heap -h')
invoke.options = ()
