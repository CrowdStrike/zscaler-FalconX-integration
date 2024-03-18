"""
indicators.py
Includes methods for pulling and formatting Falcon Indicators
"""
import configparser
import requests
import logging
import re
import os
from auth.auth import cs_auth
from util.util import log_http_error
from util.util import write_rejected

import datetime
import urllib
config = configparser.ConfigParser()
config.read('config.ini')
cs_config = config['CROWDSTRIKE']
cs_base_url = str(cs_config['base_url'])
cs_indicator_type = str(cs_config['type']) if 'type' in cs_config else 'url'
limit = int(cs_config['limit']) if int(cs_config['limit']) <= 275000 else 275000
dir = os.path.dirname(os.path.realpath(__file__))


def refresh_token():
    """Refreshes Falcon API Auth Token
    returns: Falcon API Auth token
    """
    return cs_auth()



def request(headers, api_url, deleted):
    """Helper function for get_indicators that makes the HTTP request
    headers - HTTP response headers from Falcon API
    api_url - Falcon API URL
    deleted - boolean for deleted or new indicators
    returns: Falcon API HTTP response
    """
    logging.info(f"[Falcon API] Getting {'deleted' if deleted else 'new'} Indicators")
    response = requests.get(url=api_url, headers=headers)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logging.info(f"[Falcon API] Error getting Indicators: {err}")
        log_http_error(response)
        raise
    return response

def get_indicators(falcon, deleted):
    """Builds Falcon API HTTP request and returns new indicators
    token - Falcon API Auth token
    deleted - boolean for deleted or new indicators
    returns: unformatted list of indicators
    """
    return get_all_indicators(falcon)

def filter(prepared, rejected, i):
    """Helper function for prepare_indicators,
    filters out or transforms malformed indicators that cant be indgested to Zscaler API
    prepared - list to append prepared indicators to
    i - indicator index
    returns: a lsit of formatted URLs ready for Zscaler API ingestion
    """
    # prefix_regex - regex for removing URL type prefixes
    # http_regex - regex for removing protocol prefix from URL
    # final_regex - regex that confirms Zscaler API can handle the URL string
    # a_file - boolean that says weather or not this URL is a file
    file_regex = r"^url_file:"
    prefix_regex = r'^.*?_'
    http_regex = r"(?<=//).*"
    final_regex = r"(?!.*[-_.]$)^(https?:\/\/)*[a-z0-9-]+(\.[a-z0-9-]+)+([\/\?].+|[\/])?$"
    a_file = bool(re.search(file_regex, i))
    if not a_file:
        # removes prefix by trimming the first '_' and preceding chars
        i = re.sub(prefix_regex, '', i)
        has_http_prefix = re.search(http_regex, i)
        if has_http_prefix: i = has_http_prefix.group() 
        # remove the port suffix
        i = i.split(":", 1)[0]
        # validate ascii encoding just in case
        encoded = i.encode('ascii', 'ignore')
        i = encoded.decode()
        # confirm Indicator matches zscaler's required format
        is_prepared = re.search(final_regex, i, re.IGNORECASE)
        # confirm Indicator is not a RFC1918 local IP
        is_rfc_1918 = i[:3] == "10." or i[:4] == "172." or i[:4] == "192."
        if is_prepared and not is_rfc_1918:
            prepared.append(i)
        else:
            rejected.append(i)

    return prepared, rejected

def prepare_indicators(indicators):
    """Returns indicators ready for ingestion to Zscaler API
    indicators - list of unformatted indicators
    returns: a list of formatted URLs ready for Zscaler API ingestion
    """
    prepared = []
    rejected = []
    logging.info("Preparing Indicators for Zscaler API")
    for i in indicators:
        prepared, rejected = filter(prepared, rejected, i)
    logging.info(f"Successfully prepared {len(prepared)} Indicators for Zscaler API")
    write_rejected("regex filter rejected", rejected)
    return prepared, len(rejected)



def get_all_indicators(falcon):
        # Calculate our current timestamp in seconds (%s),
    # we will use this value for our _marker timestamp.
    current_page = datetime.datetime.now().timestamp()
    # List to hold the indicators retrieved
    indicators_list = []
    # The maximum number of records to return from the QueryIndicatorEntities operation. (1-5000)
    haul = 5000
    # Sort for our results. We will sort ascending using our _marker timestamp.
    SORT = "_marker.desc"
    # Set total to one (1) so our initial loop starts. This will get reset by the API result.
    total = 1
    # Start retrieving indicators until our total is zero (0).
    while len(indicators_list) < limit:
        # Retrieve a batch of indicators passing in our marker timestamp and limit
        returned = falcon.command("QueryIntelIndicatorIds", limit=haul, sort=SORT,
                                filter=f"_marker:<='{current_page}'+type:'{cs_indicator_type}'+malicious_confidence:'high'")
        if returned["status_code"] == 200:
            # Retrieve the pagination detail for this result
            page = returned["body"]["meta"]["pagination"]
            # Based upon the timestamp within our _marker (first 10 characters),
            # a total number of available indicators is shown in the 'total' key.
            # This value will be reduced by our position from this timestamp as
            # indicated by the unique string appended to the timestamp, so as our
            # loop progresses, the total remaining will decrement. Due to the 
            # large number of indicators created per minute, this number will also
            # grow slightly while the loop progresses as these new indicators are 
            # appended to the end of the resultset we are working with.
            total = page["total"]
            # Extend our indicators list by adding in the new records retrieved
            indicators_list.extend(returned["body"]["resources"])
            # Set our _marker to be the last one returned in our list,
            # we will use this to grab the next page of results
            if 'Next-Page' not in returned['headers']:
                logging.info(f"Missing Next-Page header")
                break
            current_page = urllib.parse.unquote(returned['headers']['Next-Page']).split("+")[2].split("'")[1][:10]
            # Display our running progress
            logging.info(f"Retrieved: {len(indicators_list)}, Remaining: {total}, Marker: {current_page}")
        else:
            # Retrieve all errors returned from the API
            errors = returned["body"]["errors"]
            # Tell the loop to stop processing
            total = 0
            # Display each error returned
            for err in errors:
                # Error code
                ecode = err["code"]
                # Error message
                emsg = err["message"]
                logging.info(f"[{ecode}] {emsg}")

    # Display the grand total of indicators retrieved
    logging.info(f"Total indicators retrieved: {len(indicators_list)}")
    return indicators_list
