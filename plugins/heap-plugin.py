from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import sys

if sys.version_info[0] == 2:
    print("This plugin only works with Python 3")
    raise NotImplementedError("This plugin only works with Python 3")

import os
import subprocess
import io
import importlib


def check_and_patch():
    """Check gef.py downloaded and patched"""

    # update should modify this hash
    patch = """# Patch based on GEF ee605f9

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

class FakeGdbCommand:
    def __init__(self, *args, **kwargs):
        pass

    def dont_repeat(self, *args, **kwargs):
        pass

    def invoke(self, *args, **kwargs):
        pass

    def complete(self, *args, **kwargs):
        pass
"""

    filepath = os.path.abspath(os.path.expanduser(__file__))
    dirpath = os.path.dirname(filepath)
    gefpath = os.path.join(dirpath, 'gef.py')

    if not os.path.exists(gefpath):
        try:
            # update should modify this hash
            url = 'https://raw.githubusercontent.com/hugsy/gef/ee605f9/gef.py'
            subprocess.check_call(['curl', '-o', gefpath, url])
        except Exception as e:
            print('Downloading failed! Please download', url, 'to', gefpath, 'manually. Or reload this plugin')
            raise e

    # if need_patch has str, it means we should patch it
    need_patch = None
    with open(gefpath, 'rt') as f:
        if f.readline() != patch.splitlines(True)[0]:
            f.seek(0)
            need_patch = f.read()

    if need_patch is not None:
        with open(gefpath, 'wt') as f:
            f.write(patch)
            s = io.StringIO(need_patch)
            for line in iter(s.readline, ''):
                if '(gdb.Command)' in line:
                    f.write(line.replace('(gdb.Command):', '(FakeGdbCommand):'))
                else:
                    f.write(line)


check_and_patch()

gef_m = importlib.import_module('plugins.gef')


class K:
    command_names = ['heap',
                     'heap arenas',
                     'heap bins',
                     'heap bins fast',
                     'heap bins large',
                     'heap bins small',
                     'heap bins tcache',
                     'heap bins unsorted',
                     'heap chunk',
                     'heap chunks',
                     'heap set-arena']
    # alias must start with heap
    command_alias = [
        ('heap fast', 'heap bins fast'),
        ('heap large', 'heap bins large'),
        ('heap small', 'heap bins small'),
        ('heap tcache', 'heap bins tcache'),
        ('heap unsorted', 'heap bins unsorted'),
    ]

    call_table = None

    is_init = False

    @staticmethod
    def init():
        if 'gef' in vars(gef_m) and gef_m.gef is not None:
            # already init
            return

        # # Cannot run if we remove any other commands since it may use some config, so whatever
        # commands_to_remove = set(x for x in gef_m.__registered_commands__ if x._cmdline_ not in K.command_names)
        # gef_m.__registered_commands__.difference_update(commands_to_remove)

        gef_m.reset()
        gef_m.gef.gdb.load()

        command_instances = gef_m.gef.gdb.commands
        K.call_table = dict((i, command_instances[i]) for i in K.command_names)
        for i, j in K.command_alias:
            K.call_table[i] = command_instances[j]

        K.is_init = True

    @staticmethod
    def usage():
        for i in K.command_names:
            K.call_table[i].usage()
        print('[!] Alias:')
        for i, j in K.command_alias:
            print('[*]', i, '=>', j)

    @staticmethod
    def invoke(args):
        if len(args) > 0 and 'help' in args:
            K.usage()
            return

        prefix = 'heap'
        if len(args) > 1:
            cmd = ' '.join((prefix, args[0], args[1]))
            if cmd in K.call_table:
                K.call_table[cmd].invoke(' '.join(args[2:]), True)
                return
        if len(args) > 0:
            cmd = ' '.join((prefix, args[0]))
            if cmd in K.call_table:
                K.call_table[cmd].invoke(' '.join(args[1:]), True)
                return
        K.call_table[prefix].invoke('', True)


def invoke(peda, *args):
    """
    Gef heap command
    Usage:
        heap chunk|chunks|bins|arenas|set-arena|help
    """
    if not K.is_init:
        K.init()
    K.invoke(args)


invoke.options = ['chunk', 'chunks', 'bins', 'arenas', 'set-arena', 'help'] + [i.split()[1] for i, _ in K.command_alias]
