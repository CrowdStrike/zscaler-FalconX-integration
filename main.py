from app._util.logger import Logger
from app._util.killswitch import Killswitch
from app.integration import Integration
import sys
import time
import signal



def main():
    logger = Logger()           #init logger
    killswitch = Killswitch()   #init killswitch
    signal.signal(signal.SIGINT, lambda x, y: sys.exit(0)) #handles keyboard interrupt for graceful exits

    logger.info("CrowdStrike/Zscaler Integration initializing...")
    print("CTRL-C to exit gracefully")


    i = Integration()           #init integration

    while(True):
        if killswitch.activated():                                  #Fail streak is incremented on failed runs; streak is reset to 0 upon successful runs.
            logger.info("Too many failed executions; Exiting...")   #Killswitch.activated() returns true once streak reaches 10; 
            break                                                   #Exit Loop
        try:
            i.integrate(killswitch)     #run integration main loop: ./app/integration.py        
        except SystemExit:
            logger.info("System Exit called; CrowdStrike/Zscaler Integration stopped.")
            break
        except:
            e = sys.exc_info()[0]
            logger.error(str(e))
            streak = killswitch.get_streak()            #get runtime error stats - number of failed loops in a row
            max_streak = killswitch.get_max_streak()    #get maximum fail streak
            failures_remaining = max_streak - streak    #max - streak = failures until forced exit
            logger.info("Error during runtime;" + streak + " Failed run(s) in a row; " + failures_remaining + " Failed runs until exit.")
            killswitch.fail()   #reaching this line implies a failed run; increment the fail streak
            time.sleep(5)       #sleep for 5 seconds to avoid a rapid/excessive looping on failure

if __name__ == "__main__":
    main()



