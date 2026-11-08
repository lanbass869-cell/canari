# Canari multi-registry weekly scan
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)
from canari.baseline import run_multi
s = run_multi(npm_limit=100, pypi_limit=100, registry_limit=100, dsh_limit=50)
print('done: total=%d errors=%d' % (s['total'], s['errors']))
