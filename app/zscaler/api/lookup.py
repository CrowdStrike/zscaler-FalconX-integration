from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import json
import time
import sys

class LookUp():
    def __init__(self, auth):
        self.auth = auth
        self.token = auth.get_token()
        self.logger = Logger()
        self.hostname = config.zs_hostname
        self.lookup_url = self.hostname + "/api/v1/urlLookup"
        self.headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(self.token)
        }

    def auth_refresh(self):
        self.auth.refresh_token()
        self.token = self.auth.get_token()
        self.headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(self.token)
        }

    def url_model(self, classified_urls_json):
        urls = []
        db_categorized_urls = []
        if type(classified_urls_json) is not list:
            empty_model = {
                'urls': [],
                "dbCategorizedUrls": []
            }
            return empty_model
        for url in classified_urls_json:
            try:
                if url['urlClassificationsWithSecurityAlert']:
                    pass
                elif 'urlClassifications' not in url:
                    urls.append(url['url'])
                elif 'MISCELLANEOUS_OR_UNKNOWN' in url['urlClassifications']:
                    urls.append(url['url'])
                else:
                    db_categorized_urls.append(url['url'])
            except:
                e = sys.exc_info()[0]
                self.logger.error(str(e))
                pass

        ingestable_model = {
            'urls': urls,
            "dbCategorizedUrls": db_categorized_urls
        }
        return ingestable_model

    def url_look_up(self, url_list):
        payload = url_list
        response = requests.request(
            "POST", self.lookup_url, headers=self.headers, data=json.dumps(payload))
        if response.status_code == 401:
            self.logger.error("401 at " + self.lookup_url +
                              "; Attempting to reauthenticate")
            self.auth_refresh()
            return self.url_look_up(url_list)
        else:
            classified_urls_json = response.json()

            # URL Look Up rate limit exceeded
            # This shouldn't happen unless debugging
            if 'Retry-After' in classified_urls_json:
                return classified_urls_json

            time.sleep(1)
            ingestable_model = self.url_model(classified_urls_json)
            return ingestable_model
