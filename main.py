from app._util.logger import Logger
from app._util.killswitch import Killswitch
from app.integration import Integration
import sys
import time

logger = Logger()
killswitch = Killswitch()
i = Integration()
while(True):
    logger.info("CrowdStrike/Zscaler Integration initializing...")
    if killswitch.kill:                                         #Fail streak is incremented on failed runs.
        logger.info("Too many failed executions; Exiting...")   #Killswitch.kill returns true once streak reaches 10; 
        break                                                   #Fail streak is reset to 0 upon successful runs
    try:
        i.integrate(killswitch)
    except:
        e = sys.exc_info()[0]
        logger.error(str(e))
        killswitch.fail()   #reaching this line implies a failed run; increment the fail streak
        time.sleep(5)       #sleep for 5 seconds to avoid a rapid/excessive looping on failure



