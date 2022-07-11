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
from indicators.indicators import get_indicators, prepare_indicators
from zscaler.zscaler import look_up_indicators, push_indicators, save_changes, validate_category
from auth.auth import cs_auth
from auth.auth import zs_auth
from util.util import convert


class IntelBridge():
    def __init__(self):
        """Initializes the class and saves start time
        returns: N/A
        """
        logging.info("Initializing Intel Bridge")
        self.start_time = int(time.time())
        return
    
    def pull(self, token, del_switch):
        """Handles getting new Indicators from Falcon API.
        token - Falcon API Auth token
        del_switch - Boolean for pulling new or deleted indicators
        returns: List containing indicators pulled from Falcon API
        """
        indicators = get_indicators(token, del_switch)
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
    
    def update(self, token, content, category, ingestable, del_switch):
        """Handles updating the URL Category content
        token - Zscaler API Auth token
        category - Name of Zscaler custom URL category from config.ini
        content - Current list of URLs to be removed
        ingestable - Indicator lsit formatted for Zscaler API ingestion
        del_switch - Boolean for pulling new or deleted indicators
        returns: N/A
        """
        # remove existing content
        push_indicators(token, category, content, True)
        # push new content
        push_indicators(token, category, ingestable, False)
        # activate
        save_changes(token)
        return

    def etl_loop(self, cs_token, zs_token, del_switch, loop):
        """Main runtime loop - pulls, prepares, and pushes new indicators
        cs_token - Falcon API Auth token
        zs_token - Zscaler API Auth token
        category - Name of Zscaler custom URL category from config.ini
        del_switch - Boolean for pulling new or deleted indicators
        loop - Iteration number
        returns: switched del_switch and new iteration number
        """
        logging.info(f"Starting Pull/Prepare/Push Loop #{loop} "
                     f"With {'deleted' if del_switch else 'new'} indicators")
        del_switch = False
        category = validate_category(zs_token)
        category_name = category['id']
        content = [category['content']]
        start = int(time.time())
        indicators = self.pull(cs_token, del_switch)
        ingestable = self.prepare(zs_token, indicators)
        self.update(zs_token, content, category_name, ingestable, del_switch)
        end = int(time.time())
        loop_delta = convert(end - start)
        total_delta = convert(end - self.start_time)
        logging.info(f"Finished loop {loop}! Time elapsed: {loop_delta} "
                     f"Total run time: {total_delta}")
        return not del_switch, loop + 1


    def start(self):
        """Starts the main runtime loop (etl_loop)
        returns: N/A
        """
        cs_token = cs_auth()
        zs_token = zs_auth()
        del_switch = False
        loop = 1
        while(True):
            del_switch, loop = self.etl_loop(cs_token, zs_token, del_switch, loop)
                
