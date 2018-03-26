from sys import modules
import os

from peda.six.moves import reload_module as reload
from peda.utils import import_plugin

invoke = None


def main():
    global invoke
    plugins = [i[:-3] for i in os.listdir(os.path.dirname(__file__)) if
               i.startswith('v8_plugin_') and i.endswith('.py')]
    plugins.sort(reverse=True)

    for plugin in plugins:
        if plugin in modules:
            module = reload(modules.get(plugin))
            invoke = module.invoke
            return

    prompt = '\n\t'.join(['[%d] %s' % (index, value) for index, value in enumerate(plugins)])
    prompt = 'Supported Version:\n\t%s\nPlease choose one [Default: 0]: ' % prompt
    try:
        choose = int(input(prompt))
        if choose >= len(plugins):
            raise RuntimeError
    except:
        print('Choosing default 0')
        choose = 0
    module = import_plugin(plugins[choose])
    invoke = module.invoke


main()
