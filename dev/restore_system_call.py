import subprocess
import re
import pickle
import progressbar

# {number:[function_name,name,params_num,[params...]]}
import zlib


def get_system_call(function_name='fork'):
    command = 'man 2 %s' % function_name
    P = subprocess.Popen(command, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (result, err) = P.communicate()
    if not result == '':
        name = re.search('NAME\n(.*)SYNOPSIS\n', result, re.S).group(1).strip()
        synopsis = re.search('SYNOPSIS\n(.*)DESCRIPTION\n', result, re.S).group(1)
        # print name
        # print synopsis
        params = re.search(function_name + '\(([^\)]*)\);', synopsis, re.S)

        if not params:
            params_num = 0
            params = []
        else:
            params = params.group(1)
            # print params
            params_num = params.count(',') + 1
            if params_num == 1 and params.strip() == 'void':
                params_num = 0
                params = []
            else:
                params = params.split(',')
                params = [i.strip() for i in params]

        # print params_num
        # print params
        return name, params_num, params
    print (function_name, 'not found')
    return 'description unknown', 0, []


# system_calls[22] = ['func name']
# system_calls[22].extend(get_system_call('cacheflush'))
# print system_calls

def do():
    system_calls = {}
    p = progressbar.ProgressBar(maxval=500).start()
    for index, line in enumerate(open('unistd.h', 'r').readlines()):
        # print repr(line.strip())
        try:
            if '(' in line:
                p.update(index)
                num = re.search('\((.*)\)', line).group(1)
                num = int(eval(num))
                func_name = line.split('(')[0].strip()
                system_calls[num] = [func_name]
                system_calls[num].extend(get_system_call(func_name))
                # print system_calls[num][1]
        except Exception as e:
            print (index, line, e.message)

    p.finish()
    open('system_calls', 'w').write(zlib.compress(pickle.dumps(system_calls)))


do()
# print get_system_call('readlink')
