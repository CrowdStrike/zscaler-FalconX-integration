"""
__main__.py
Method for starting inte bridge when started as a module
"""

import sys
import logging
from intelbridge import IntelBridge
from util.util import start_log

def main():
    """Initializes and starts intel bridge object
    returns: N/A
    """
    start_log()
    logging.info("Falcon X Zscaler Intel Bridge main routine starting...")
    intelbridge = IntelBridge()
    intelbridge.start()
    return


if __name__ == '__main__':
    """Calls main method when running module from root
    returns: N/A
    """
    main()





