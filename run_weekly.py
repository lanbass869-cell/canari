import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)
from canari.baseline import run
s = run(limit=50)
print("done", s["total"], s["fetch_errors"])
