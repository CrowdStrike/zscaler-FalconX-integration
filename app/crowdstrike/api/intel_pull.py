from app._util.intel_format import IntelFormat
from app._util.logger import Logger
from requests.exceptions import HTTPError
import config as config
import requests
import json
import os


class IntelPull():
    def __init__(self, auth):
        self.logger = Logger()
        self.auth = auth
        self.token = auth.get_token()
        self.base_url = config.cs_base_url
        self.limit = 10000
        self.indicators_remaining = 10000
        self.payload = {}
        self.indicators_api = "/intel/queries/indicators/v1"
        self.indicators_params = "?limit=" + \
            str(self.limit) + \
            "&filter=type:'url'%2Bmalicious_confidence:'high'&include_deleted=false"
        self.deleted_indicators_params = "?limit=" + \
            str(self.limit) + \
            "&filter=deleted:true%2Btype:'url'%2Bmalicious_confidence:'high'"
        self.headers = {'Authorization': 'Bearer ' + str(self.token)}
        self.indicators_url = self.base_url + \
            self.indicators_api + self.indicators_params
        self.deleted_indicators_url = self.base_url + \
            self.indicators_api + self.deleted_indicators_params
        self.next_page_url = self.check_next_page_url('../queuing/intel.json')
        self.deleted_next_page_url = self.check_next_page_url(
            '../queuing/intel_deleted.json')

    def check_next_page_url(self, file):
        working_dir = os.path.dirname(os.path.abspath(__file__))
        file_loc = os.path.join(working_dir, file)
        try:
            with open(file_loc) as f:
                data = json.load(f)
            return data['next_page']
        except:
            return ""

    def reauthenticate(self):
        self.auth.refresh_token()
        self.token = self.auth.get_token()
        self.headers = {'Authorization': 'Bearer ' + str(self.token)}

    def get_indicators(self):
        self.logger.info(
            "Querying CrowdStrike Intel Indicators API for new indicators.")
        if self.next_page_url:
            self.holding = self.next_page_url
            self.logger.info(
                "CrowdStrike Intel Indicators API: next_page_url found - continuing paginated requests.")
            response = requests.request(
                "GET", self.next_page_url, headers=self.headers, data=self.payload)
        else:
            self.logger.info(
                "CrowdStrike Intel Indicators API: next_page_url not found - initiating paginated requests.")
            response = requests.request(
                "GET", self.indicators_url, headers=self.headers, data=self.payload)

        intel_results = str(response.status_code)

        if intel_results == '401':
            self.reauthenticate()
            return self.get_indicators()

        indicator_json = response.json()

        response_headers = response.headers._store
        self.indicators_remaining = response_headers['x-ratelimit-remaining'][1]

        if 'next-page' in response_headers:
            self.next_page_url = self.base_url + \
                response_headers['next-page'][1]
        else:
            self.next_page_url = ""

        indicator_json['meta']
        intel = indicator_json['resources']

        # format before writing
        self.intel_format = IntelFormat()
        self.intel_format.format_intel(intel)
        intel = self.intel_format.get_lookup_ready_urls()
        self.write_intel(intel, 'intel.json', self.next_page_url)
        return intel

    def get_deleted_indicators(self):
        self.logger.info(
            "Querying CrowdStrike Intel Indicators API for deleted indicators.")
        if self.deleted_next_page_url:
            self.holding_deleted = self.deleted_next_page_url
            self.logger.info(
                "CrowdStrike Intel Indicators API: next_page_url found for deleted indicators - continuing paginated requests.")
            response = requests.request(
                "GET", self.deleted_next_page_url, headers=self.headers, data=self.payload)
        else:
            self.logger.info(
                "CrowdStrike Intel Indicators API: next_page_url not found for deleted indicators - initiating paginated requests.")
            response = requests.request(
                "GET", self.deleted_indicators_url, headers=self.headers, data=self.payload)

        intel_results = str(response.status_code)
        if intel_results == '401':
            self.reauthenticate()
            return self.get_deleted_indicators()

        indicator_json = response.json()
        response_headers = response.headers._store
        self.indicators_remaining = response_headers['x-ratelimit-remaining'][1]

        if 'next-page' in response_headers:
            self.deleted_next_page_url = self.base_url + \
                response_headers['next-page'][1]
        else:
            self.deleted_next_page_url = ''

        indicator_json['meta']
        intel = indicator_json['resources']

        # format before writing
        self.deleted_intel_format = IntelFormat()
        self.deleted_intel_format.format_intel(intel)
        intel = self.deleted_intel_format.get_lookup_ready_urls()
        self.write_intel(intel, 'intel_deleted.json',
                         self.deleted_next_page_url)
        return intel

    def write_intel(self, intel, file, next_page):
        content = {
            'next_page': str(next_page),
            'urls': intel
        }
        with open("app/crowdstrike/queuing/" + file, 'w', encoding='utf-8') as f:
            json.dump(content, f, ensure_ascii=False, indent=4)

    def revert_next_page(self):
        self.logger.info("Reverting to previous Intel ")
        self.next_page_url = self.holding
        self.deleted_next_page_url = self.holding_deleted

    def get_lookup_ready_urls(self):
        return self.intel_format.get_lookup_ready_urls()

    def get_deleted_lookup_ready_urls(self):
        return self.deleted_intel_format.get_lookup_ready_urls()
