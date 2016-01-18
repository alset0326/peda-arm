import re
import progressbar

import requests

reply = requests.get('http://ascii.mastervb.net/')
# <option value="xhelvi.flf">xhelvi.flf</option>
pattern = re.compile('<option value="(\S+)">\S+</option>')
m = pattern.findall(reply.text)

print 'start!!'
fd = open('logo.py', 'w')
fd.write('LOGOS=[')
p = progressbar.ProgressBar(maxval=len(m)).start()
for index, option in enumerate(m):
    p.update(index + 1)
    try:
        reply = requests.get('http://ascii.mastervb.net/figlet.ajax.php', params={'message': 'PEDA-ARM',
                                                                                  'rtol': 'undefined',
                                                                                  'old_layout': 'undefined',
                                                                                  'font': str(option),
                                                                                  'html_mode': 'undefined'})
        t = str(reply.text)
        image = t[t.index('<pre>') + 5:t.index('</pre>')]
        fd.write('"""%s""",' % image.encode('base64'))
    except:
        print 'missing option: %s' % option
p.finish()
fd.write(']')
fd.close()
