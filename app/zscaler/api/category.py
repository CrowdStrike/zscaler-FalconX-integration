from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import json
import sys


class Category():
    def __init__(self, auth):
        self.token = auth.get_token()
        self.hostname = config.zs_hostname
        self.category_check_url = self.hostname + \
            "/api/v1/urlCategories?customOnly=true"
        self.category_post_url = self.hostname + "/api/v1/urlCategories"
        self.cat_name = config.cs_category_name
        self.headers = headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(self.token)
        }
        self.payload = {
            "configuredName": self.cat_name,
            "customCategory": "true",
            "superCategory": "USER_DEFINED",
            "urls": ["mine.ppxxmr.com:5555"]
        }
        self.logger = Logger()

    def custom_category_check(self):
        try:
            custom_url_cat = requests.request(
                "GET", self.category_check_url, headers=self.headers)
            str(custom_url_cat.status_code)

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            sys.exit()

        custom_cats = custom_url_cat.json()

        if len(custom_url_cat.json()) == 0:
            category_id = 'none found'
            return category_id
        else:
            for cat in custom_cats:
                #if crowdstrike category exists, return its ID
                if self.cat_name == cat['configuredName']:
                    category_id = cat['id']
                    custom_urls = cat['urls']
                    self.write_intel_raw(custom_urls, "zscaler_urls.json")
                    return category_id
            #if crowdstrike category does not exist, create it
            self.create_cs_cat()

    def create_cs_cat(self):
        try:
            cs_cat = requests.request(
                "POST", url=self.category_post_url, headers=self.headers, data=json.dumps(self.payload))
            cs_cat_results = str(cs_cat.status_code)
            cs_cat_result = cs_cat.json()
            category_id = cs_cat_result['id']
            return category_id

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            self.logger.error(
                'Error contacting Zscaler URL category API: ' + str(e))
            self.logger.error('System will now exit')
            sys.exit()

    def write_intel_raw(self, intel, file):
        intel_raw = {'urls': intel}
        with open("app/zscaler/queuing/" + file, 'w', encoding='utf-8') as f:
            json.dump(intel_raw, f, ensure_ascii=False, indent=4)
