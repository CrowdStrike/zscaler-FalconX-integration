from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import sys


class CrowdStrikeAuth():
    def __init__(self):
        self.clientID = config.cs_clientID  # CS API ClientID
        self.secret = config.cs_secret  # CS API Secret
        self.base_url = config.cs_base_url  # CS API Base URL
        self.token_url = "/oauth2/token"  # OAuth2 token url
        self.headers = {'content-type': 'application/x-www-form-urlencoded'}
        self.data = 'client_id=%s&client_secret=%s' % (
            self.clientID, self.secret)
        self.auth_URL = self.base_url + self.token_url
        self.token = False
        self.logger = Logger()

    def token_failure(self, response_code, error):
        return 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error)

    def token_failure_trace(self, response_code, error, trace_id):
        return 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error) + 'Provide this Trace ID to CrowdStrike Support: ' + str(trace_id)

    def refresh_token(self):
        self.logger.info("CrowdStrike Authentication: Refreshing token.")
        try:
            response = requests.post(
                url=self.auth_URL, data=self.data, headers=self.headers)
            response_code = str(response.status_code)
            r = response.json()

        except HTTPError as http_err:
            # catch an HTTP error
            result = 'failure'
            failure_message = 'HTTP Error: ' + http_err
            if 'errors' in list(r.keys()):
                error = r['errors'][0]['message']
                failure_message = self.token_failure(response_code, error)
            if 'trace_id' in list(r['meta'].keys()):
                # if there's an error CS support will ask for any trace IDs returned by the API
                trace_id = r['meta']['trace_id']
                failure_message = self.token_failure_trace(
                    response_code, error, trace_id)
            return result, failure_message

        except:
            # catch all exception
            result = 'failure'
            failure_message = sys.exc_info()[0]
            return result, failure_message

        if response_code.startswith('20'):
            if 'access_token' in list(r.keys()):
                result = r['access_token']
                message = 'success'
                self.token = result
                self.logger.info(
                    "CrowdStrike Authentication: Successfully authenticated.")
                return result, message

        else:
            error = r['errors'][0]['message']
            if 'trace_id' in list(r['meta'].keys()):
                # if there's an error CS support will ask for any trace IDs returned by the API
                trace_id = r['meta']['trace_id']
                failure_message = self.token_failure_trace(
                    response_code, error, trace_id)

            elif 'errors' in list(r.keys()):
                # if there's an error CS support will ask for any trace IDs returned by the API
                result = 'failure'
                failure_message = failure_message(response_code, error)
                if 'trace_id' in list(r['meta'].keys()):
                    trace_id = r['meta']['trace_id']
                    failure_message = self.token_failure_trace(
                        response_code, error, trace_id)

            else:
                failure_message = 'Unknown error retrieving token'
                result = 'failure'

        return result, failure_message

    def get_token(self):
        return self.token
