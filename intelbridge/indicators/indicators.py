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


config = configparser.ConfigParser()
config.read('config.ini')
cs_config = config['CROWDSTRIKE']
cs_base_url = str(cs_config['base_url'])
limit = int(cs_config['limit'])
dir = os.path.dirname(os.path.realpath(__file__))
new_indicators_data = f"{dir}/data_new"
deleted_indicators_data = f"{dir}/data_deleted"

def refresh_token():
    """Refreshes Falcon API Auth Token
    returns: Falcon API Auth token
    """
    return cs_auth()

def write_data(entry, deleted):
    """Writes the next_page URL to disk so etl_loop can pick up where it left off
    entry - line to write to file
    deleted - boolean for deleted or new indicators
    returns: N/A
    """
    data_file = new_indicators_data if not deleted else deleted_indicators_data
    f = open(data_file, 'w')
    f.write(f"{entry}")
    f.close()
    return

def check_headers(headers, deleted):
    """Looks for next_page URL in Falcon API response headers
    headers - HTTP response headers from Falcon API
    deleted - boolean for deleted or new indicators
    returns: N/A
    """
    if 'next-page' in headers:
            next_page_route = headers['next-page'][1]
            next_page_url = f"{cs_base_url}{next_page_route}"
            write_data(next_page_url, deleted)
            logging.info(f"Next Page URL Found: {next_page_url}")
    else:
            write_data('', deleted)

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
        raise
    return response

def get_indicators(token, deleted):
    """Builds Falcon API HTTP request and returns new indicators
    token - Falcon API Auth token
    deleted - boolean for deleted or new indicators
    returns: unformatted list of indicators
    """
    del_filter = "deleted:true%2B" if deleted else ""
    headers = {"Authorization" : f"Bearer {str(token)}",
               "User-Agent" :"Zscaler-FalconX-Intel-Bridge"}
    data_file = new_indicators_data if not deleted else new_indicators_data
    with open(data_file, 'r') as f:
        if False:#os.stat(data_file).st_size != 0:
            api_url = f.readlines()[-1]
        else:
            route = "/intel/queries/indicators/v1"
            params = (f"?limit={str(limit)}&sort=published_date|desc&filter={del_filter}" 
                       "type:'url'%2Bmalicious_confidence:" 
                      f"'high'{'&include_deleted=false'if deleted else ''}")
            api_url = f"{cs_base_url}{route}{params}"
    response = request(headers, api_url, deleted)
    check_headers(response.headers._store, deleted)
    indicators = response.json()['resources']
    x = response.json()
    logging.info(f"[Falcon API] responded with {len(indicators)} Indicators")
    return indicators

def filter(prepared, i):
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
    return prepared

def prepare_indicators(indicators):
    """Returns indicators ready for ingestion to Zscaler API
    indicators - list of unformatted indicators
    returns: a list of formatted URLs ready for Zscaler API ingestion
    """
    prepared = []
    logging.info("Preparing Indicators for Zscaler API")
    for i in indicators:
        prepared = filter(prepared, i)
    logging.info(f"Successfully prepared {len(prepared)} Indicators for Zscaler API")
    return prepared


