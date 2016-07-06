source = '''
class AllocationMemento: public Struct {
 public:
  static const int kAllocationSiteOffset = HeapObject::kHeaderSize;
  static const int kSize = kAllocationSiteOffset + kPointerSize;

'''

if '=\n' in source:
    source = source.replace('=\n', '= ')

lines = source.splitlines()
class_name = super_class = None
class_line = None

# get class name and super class
for index, line in enumerate(lines):
    line_strip=line.strip()
    if line_strip.startswith('class'):
        class_line = index
        if ":" not in line_strip:
            raise RuntimeError('Not a valid v8 class')
        s = [i.split() for i in line_strip.split(':')]
        class_name = s[0][1]
        super_class = s[1][1]
        break

# generate description
class_description = []
s = lines[class_line]
if '{' in s:
    s = s.replace('{', '')
if '}' in s:
    s = s.replace('}', '')
class_description.append(s.strip() + ';')
for index, line in enumerate(lines[:class_line]):
    if line:
        s = line.strip()
        if s.startswith('//'):
            if s.startswith('// '):
                class_description.append(s[3:])
            else:
                class_description.append(s[2:])
class_description = '\n    '.join(class_description)

# generate offset define
offsets = []
offset_defines = []
for index, line in enumerate(lines[class_line + 1:]):
    s = line.strip().split()
    if '=' not in s:
        continue
    equal = s.index('=')
    tmp = s[equal - 1]
    if 'Offset' in tmp:
        offsets.append(tmp)
    tmp = ' '.join(s[equal - 1:])
    if ';' in tmp:
        tmp = tmp.replace(';', '')
    if '::' in tmp:
        tmp = tmp.replace('::', '.')
    offset_defines.append(tmp.strip())
offset_defines = '\n    '.join(offset_defines)
if 'kSize =' not in offset_defines and 'kSize=' not in offset_defines:
    if 'kHeaderSize =' in offset_defines or 'kHeaderSize=' in offset_defines:
        offset_defines += '\n    kSize = kHeaderSize  # for mem dump needed'
    else:
        offset_defines += '\n    # kSize and kHeaderSize not found. Please add it manually.'

# generate get functions
get_function_template = '''
    @staticmethod
    def %s(data):
        return get_dword(data, %s.%s)
'''
get_function_defines = []
addr_defines = []
function_names = []
for index, offset_name in enumerate(offsets):
    s = offset_name
    if s.endswith('Offset'):
        s = s[:-6] + 'Addr'
    addr_defines.append(s)
    if s.startswith('k'):
        s = s[1:]
    function_name = []
    for i in list(s):
        if i.islower():
            function_name.append(i)
        else:
            function_name.append('_%s' % i.lower())
    function_name = 'get%s' % ''.join(function_name)
    function_names.append(function_name)
    get_function_defines.append(get_function_template % (function_name, class_name, offset_name))
get_function_defines = '\n'.join(get_function_defines)

# generate do_parse function
if addr_defines:
    appends = []
    append_template = "self.append('%s: 0x%%x' %% %s.%s(self.data))"
    for i in range(len(addr_defines)):
        addr_define = addr_defines[i]
        function_name = function_names[i]
        appends.append(append_template % (addr_define, class_name, function_name))
    appends = '\n        '.join(appends)
    do_parse_function_define = '''
    def do_parse(self):
        %s.do_parse(self)
        %s
    ''' % (super_class, appends)
else:
    do_parse_function_define = ''

result = '''
class %s(%s):
    """
    %s
    """
    %s

    %s

    %s
''' % (class_name, super_class, class_description, offset_defines, get_function_defines, do_parse_function_define)

print (result)
