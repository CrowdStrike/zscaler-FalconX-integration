from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import json
import sys
import time


class ZscalerAuth():
    def __init__(self):
        self.hostname = config.zs_hostname
        self.username = config.zs_username
        self.password = config.zs_password
        self.apikey = config.zs_apiKey
        self.url = self.hostname + "/api/v1/authenticatedSession"
        self.headers = {'Content-Type': 'application/json',
                        'cache-control': "no-cache"}
        self.token = False
        self.logger = Logger()

    def obfuscateApiKey(self, now):
        seed = self.apikey
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ''
        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j])+2]
        return key

    def refresh_token(self):
        self.logger.info("Zscaler Authentication: Refreshing token.")

        # configure the appropriate info for the call
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        str(int(n) >> 1).zfill(6)

        # call obfuscate method
        obfuscated_api_key = self.obfuscateApiKey(now)

        # call to Zscaler to get authentication Cookie
        try:
            payload = {"username": self.username, "password": self.password,
                       "apiKey": obfuscated_api_key, "timestamp": now}
            response = requests.request(
                "POST", self.url, headers=self.headers, data=json.dumps(payload))
            self.token = response.cookies['JSESSIONID']
            results = str(response.status_code)
            if results.startswith('20'):
                response.raise_for_status()

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            sys.exit()

        # return Zscaler auth cookie
        self.logger.info("Zscaler Authentication: Successfully authenticated.")
        return self.token

    def get_token(self):
        return self.token
