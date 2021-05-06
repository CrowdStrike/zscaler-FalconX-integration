from app._util.logger import Logger
from requests.exceptions import HTTPError
import requests
import re


class IntelFormat():
    def __init__(self):
        self.excl_regex = r"^url_file:"
        self.http_regex = r"(?<=//).*"
        self.final_regex = r"(?!.*[-_.]$)^(https?:\/\/)*[a-z0-9-]+(\.[a-z0-9-]+)+([\/\?].+|[\/])?$"
        self.cs_indicators = []
        self.lookup_ready = []

    def format_intel(self, intel):

        for indicators in intel:
            # identifies file based URLs
            form_check = re.search(self.excl_regex, indicators)
            if form_check == None:
                # removes 'http' & 'https' from URLs per Zscaler requirements
                matches = re.search(self.http_regex, indicators)
                match = matches.group()
                # trim the port
                sep = ":"
                match = match.split(sep, 1)[0]
                encoded_string = match.encode("ascii", "ignore")
                match = encoded_string.decode()
                self.pre_lookup_url_validator(match)
                self.cs_indicators.append(match)
            else:
                # skips file formated URLs
                pass
        return self.cs_indicators

    def write_rejected(self, url):
        with open("app/crowdstrike/queuing/rejected.txt", 'a') as f:
            f.write('"' + url + '"' + ",\n")

    def pre_lookup_url_validator(self, url):
        matches = re.search(self.final_regex, url, re.IGNORECASE)
        if matches:
            self.lookup_ready.append(url)
        else:
            self.write_rejected(url)

    def get_lookup_ready_urls(self):
        return self.lookup_ready
