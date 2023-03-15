r"""
 ______          __           ___             
/\__  _\        /\ \__       /\_ \ 
\/_/\ \/     ___\ \ ,_\    __\//\ \
   \ \ \   /' _ `\ \ \/  /'__`\\ \ \
    \_\ \__/\ \/\ \ \ \_/\  __/ \_\ \_
    /\_____\ \_\ \_\ \__\ \____\/\____\
    \/_____/\/_/\/_/\/__/\/____/\/____/
 ____                   __
/\  _`\          __    /\ \
\ \ \L\ \  _ __ /\_\   \_\ \     __      __
 \ \  _ <'/\`'__\/\ \  /'_` \  /'_ `\  /'__`\
  \ \ \L\ \ \ \/ \ \ \/\ \L\ \/\ \L\ \/\  __/
   \ \____/\ \_\  \ \_\ \___,_\ \____ \ \____\
    \/___/  \/_/   \/_/\/__,_ /\/___L\ \/____/
                                 /\____/
                                 \_/__/
intelbridge.py
Main object in module; Handles intel bridge initialization and execution
"""
import logging
import time
import configparser
import sys
from indicators.indicators import get_indicators, prepare_indicators #, write_data
from zscaler.zscaler import look_up_indicators, push_indicators, save_changes, validate_category
from auth.auth import cs_auth
from auth.auth import zs_auth
from util.util import convert, next_hour

config = configparser.ConfigParser()
config.read('config.ini')
chron_config = config['CHRON']
chron = int(chron_config['disable_loop'])
class IntelBridge():
    def __init__(self):
        """Initializes the class and saves start time
        returns: N/A
        """
        logging.info("Initializing Intel Bridge")
        self.start_time = int(time.time())
        return
    
    def pull(self, falcon, deleted):
        """Handles getting new Indicators from Falcon API.
        token - Falcon API Auth token
        deleted - Boolean for pulling new or deleted indicators
        returns: List containing indicators pulled from Falcon API
        """
        indicators = get_indicators(falcon, deleted)
        return indicators

    def prepare(self, token, indicators):
        """Handles transforming indicators object into a Zscaler API ready model
        token - Falcon API Auth token
        indicators - List containing indicators pulled from Falcon API
        returns: Indicator list formatted for Zscaler API ingestion
        """
        prepared = prepare_indicators(indicators)
        ingestable = look_up_indicators(prepared, token)
        return ingestable
    
    def update(self, token, content, category, ingestable, deleted):
        """Handles updating the URL Category content
        token - Zscaler API Auth token
        category - Name of Zscaler custom URL category from config.ini
        content - Current list of URLs to be removed
        ingestable - Indicator list formatted for Zscaler API ingestion
        deleted - Boolean for pulling new or deleted indicators
        returns: N/A
        """
        #remove last batch
        if content['urls'] and len(content['urls']) > 0:
            logging.info(f"""[Zscaler API] Safely removing previous indicators;
                        [!!!] You are still protected during this phase;
                        indicator refresh won't take effect until new indicators are pushed
                        and changes are activated!""")
            push_indicators(token, category, content, True)
        # push new content
        logging.info(f"[Zscaler API] Pushing new indicators")
        push_indicators(token, category, ingestable, False)
        # activate
        save_changes(token)
        return

    def etl_loop(self, falcon, zs_token, deleted, loop):
        """Main runtime loop - pulls, prepares, and pushes new indicators
        cs_token - Falcon API Auth token
        zs_token - Zscaler API Auth token
        category - Name of Zscaler custom URL category from config.ini
        deleted - Boolean for pulling new or deleted indicators
        loop - Iteration numberå
        returns: switched deleted and new iteration number
        """
        logging.info(f"Starting Pull/Prepare/Push Loop # {loop} "
                     f"With {'deleted' if deleted else 'new'} indicators")
        if(chron == 1):
            logging.info("Looping Disabled! Exiting after this run.")
        category = validate_category(zs_token)
        category_name = category['id']
        content = category['content']
        start = int(time.time())
        indicators = self.pull(falcon, deleted)
        ingestable = self.prepare(zs_token, indicators)
        # write_data(ingestable, deleted)
        self.update(zs_token, content, category_name, ingestable, deleted)
        end = int(time.time())
        loop_delta = convert(end - start)
        total_delta = convert(end - self.start_time)

        if(chron == 1):
            sys.exit(f"Looping Disabled! Intel Bridge completed. Time elapsed: {loop_delta}")

        logging.info(f"Finished loop {loop}! Time elapsed: {loop_delta};\n"
                     f"Total run time: {total_delta};\n"
                     f"Indicators {'pushed' if not deleted else 'removed'}: {len(ingestable['urls'])};\n"
                     f"Sleeping for 12 hours...Next update:{next_hour()}.\n")
        time.sleep(60*60*12)
        return deleted, loop + 1


    def start(self):
        """Starts the main runtime loop (etl_loop)
        returns: N/A
        """
        deleted = False
        loop = 1
        while(True):
            falcon = cs_auth()
            zs_token = zs_auth()
            deleted, loop = self.etl_loop(falcon, zs_token, deleted, loop)
                
