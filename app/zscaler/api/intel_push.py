from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import json
import sys

class IntelPush:
    def __init__(self, auth, cat_id):
        self.logger = Logger()
        self.auth = auth
        self.token = auth.get_token()
        self.cat_id = cat_id
        self.hostname = config.zs_hostname
        self.cat_name = config.cs_category_name
        self.push_new_url = self.hostname + '/api/v1/urlCategories/' + \
            str(self.cat_id) + '?action=ADD_TO_LIST'
        self.push_deleted_url = self.hostname + '/api/v1/urlCategories/' + \
            str(self.cat_id) + '?action=REMOVE_FROM_LIST'
        self.status_url = self.hostname + "/api/v1/status"
        self.activate_url = self.hostname + "/api/v1/status/activate"
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

    def push_new(self, model):
        if not model['urls'] and not model['dbCategorizedUrls']:
            return
        payload = {
            "customCategory": "true",
            "superCategory": "USER_DEFINED",
            "urls": model['urls'],
            "dbCategorizedUrls": model['dbCategorizedUrls'],
            "configuredName": self.cat_name
        }
        push_results = requests.request(
            "PUT", url=self.push_new_url, data=json.dumps(payload), headers=self.headers)
        if push_results.status_code == 401:
            self.logger.error("401 at " + self.push_new_url +
                              "; Attempting to reauthenticate")
            self.auth_refresh()
            self.push_new(model)
        else:
            push_results = push_results.json()

    def push_deleted(self, urls):
        payload = {
            "customCategory": "true",
            "superCategory": "USER_DEFINED",
            "urls": urls,
            "dbCategorizedUrls": [],
            "configuredName": self.cat_name
        }
        push_results = requests.request(
            "PUT", url=self.push_deleted_url, data=json.dumps(payload), headers=self.headers)
        if push_results.status_code == 401:
            self.logger.error("401 at " + self.push_deleted_url +
                              "; Attempting to reauthenticate")
            self.auth_refresh()
            self.push_deleted(urls)
        else:
            push_results = push_results.json()

    def activate_changes(self):
        self.logger.info('Committing changes to Zscaler.')
        self.status_url = self.hostname + "/api/v1/status"
        try:
            status_resp = requests.request("GET", url = self.status_url, headers = self.headers)
            self.logger.info("Current status of commits for Zscaler: " + str(status_resp))

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            self.logger.error('Error checking Zscaler commit status: ' + str(e))
            self.logger.error('System will now exit')
            sys.exit()

        
        activate_resp = requests.request("POST", url = self.activate_url, headers = self.headers)
        print (activate_resp.status_code)