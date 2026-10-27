"""
__main__.py
Method for starting inte bridge when started as a module
"""

import sys

# Fail fast with a clear message on unsupported interpreters. This must run
# before the imports below, which pull in requests/urllib3 releases that
# require Python 3.10+ (see requirements.txt and README.md).
MINIMUM_PYTHON = (3, 10)
if sys.version_info < MINIMUM_PYTHON:
    sys.exit("Intel Bridge requires Python %d.%d or newer; found %s."
             % (MINIMUM_PYTHON + (sys.version.split()[0],)))

import logging  # noqa: E402  (imports intentionally follow the version check)
from intelbridge import IntelBridge  # noqa: E402
from util.util import start_log  # noqa: E402

def main():
    """Initializes and starts intel bridge object
    returns: N/A
    """
    start_log()
    logging.info("Intel Bridge main routine starting...")
    intelbridge = IntelBridge()
    intelbridge.start()
    return


if __name__ == '__main__':
    """Calls main method when running module from root
    returns: N/A
    """
    main()





