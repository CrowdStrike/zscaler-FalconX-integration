"""
auth.py
Methods for authenticating to Falcon and Zscaler APIs
"""
import logging
import configparser
import requests
import time
import json
import argparse
from util.util import log_http_error

parser = argparse.ArgumentParser(
    description="FalconX-Zscaler-Intel-Bridge"
)
parser.add_argument(
    '-s', '--secret',
    help="Your Falcon API Client Secret", required=True
)
parser.add_argument(
    '-k', '--key',
    help='Your Zscaler ZIA API Key', required=True
)
parser.add_argument(
    '-p', '--password',
    help='Your Zscaler ZIA password', required=True
)

config = configparser.ConfigParser()
config.read('config.ini')
args = parser.parse_args()
cs_config = config['CROWDSTRIKE']
cs_client = str(cs_config['client'])
cs_base_url = str(cs_config['base_url'])
zs_config = config['ZSCALER']
zs_hostname = str(zs_config['hostname'])
zs_username = str(zs_config['username'])

cs_secret = args.secret
zs_password = args.password
zs_api_key = args.key

def cs_auth():
    """Returns a new Falcon API Auth Token, hot off the press
    returns: Falcon API Auth token
    """
    logging.info(f"Authenticating client {cs_client} to Falcon API")
    url = f"{cs_base_url}/oauth2/token"
    data = f"client_id={cs_client}&client_secret={cs_secret}"
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    response = requests.post(url=url, data=data, headers=headers)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logging.info(f"Error authenticating to Falcon API: {err}")
        log_http_error(response)
        raise
    token = response.json()["access_token"]
    return token

def obfuscateApiKey(now):
    """Helper function for Zscaler's fancy auth method
    now - current datetime
    retuns: Zscaler API Auth key (for generating token)
    """
    seed = zs_api_key
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ''
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]
    return key

def zs_auth():
    """Generates a new Zscaler API Auth Token, hot off the press
    returns: Zscaler API Auth token
    """
    logging.info(f"Authenticating user {zs_username} to Zscaler API")
    now = int(time.time() * 1000)
    url = f"{zs_hostname}/api/v1/authenticatedSession"
    obfuscated_api_key = obfuscateApiKey(now)
    payload = {"username": zs_username, "password": zs_password,
               "apiKey": obfuscated_api_key, "timestamp": now}
    headers = {'Content-Type': 'application/json','cache-control': "no-cache"}
    response = requests.request("POST", url, headers=headers, data=json.dumps(payload))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        logging.info(f"Error authenticating to Zscaler API: {err}")
        log_http_error(response)
        raise
    token = response.cookies['JSESSIONID']
    return token

