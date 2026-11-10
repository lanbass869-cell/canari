import logging, sys
def setup(v=0):
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    return logging.getLogger("canari")
