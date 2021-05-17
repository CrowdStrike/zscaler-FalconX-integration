from app._util.logger import Logger
from app.crowdstrike.crowdstrike_auth import CrowdStrikeAuth
from app.crowdstrike.api.intel_pull import IntelPull
from app.zscaler.zscaler_auth import ZscalerAuth
from app.zscaler.api.category import Category
from app.zscaler.api.lookup import LookUp
from app.zscaler.api.intel_push import IntelPush
import config as config
import time
import datetime


class Integration():
    def __init__(self):
        self.logger = Logger()
        self.logger.info("CrowdStrike/Zscaler Integration starting...")

        self.authenticate()

        # time keeping & rate limit monitoring
        self.rate_limit_monitor = 0
        self.start_time = time.time()
        self.last_hour = self.start_time
        # store intermediary urls from ZScaler URL look up responses
        self.zs_payload = {
            'urls': [],
            'dbCategorizedUrls': []
        }
        self.zs_payload_deleted = []

        self.zs_max_calls_hourly = config.zs_max_calls_hourly
        self.zs_max_payload_size = config.zs_max_payload_size

    def authenticate(self):
        # auth service modules for both parties
        self.cs_auth = CrowdStrikeAuth()  # CrowdStrike auth init
        self.zs_auth = ZscalerAuth()  # ZScaler auth init
        self.cs_auth.refresh_token()  # use this funciton to refresh CrowdStrike bearer token
        self.zs_auth.refresh_token()  # use this function to refresh ZScaler cookie

        # instantiate modules, each module has a specific task
        self.cs_intel = IntelPull(self.cs_auth)  # CS intel controller init
        self.zs_cat = Category(self.zs_auth)  # category controller init
        # category check; returns CrowdStrike custom category ID
        self.zs_cat_id = self.zs_cat.custom_category_check()
        self.zs_lookup = LookUp(self.zs_auth)  # URL Lookup controller init
        # ZScaler ingest controller init
        self.zs_ingest = IntelPush(self.zs_auth, self.zs_cat_id)

    def integrate(self, killswitch):
        # query CrowdStrike Intel API for indicators + deleted indicators
        # returns formatted indicator urls from Intel API
        cs_indicators = self.cs_intel.get_indicators()
        # returns formatted deleted indicator urls from Intel API
        cs_deleted_indicators = self.cs_intel.get_deleted_indicators()

        cs_indicators_chunks = [cs_indicators[i:i + 100]
                                for i in range(0, len(cs_indicators), 100)]
        cs_deleted_indicators_chunks = [cs_deleted_indicators[i:i + 1000]
                                        for i in range(0, len(cs_deleted_indicators), 1000)]

        for chunk in cs_indicators_chunks:
            # before looping, check if approaching rate limit for URL look up (40000 url/hr)
            # wait 39000(default config) hits (1000 hits of wiggle room)
            if(self.rate_limit_monitor > self.zs_max_calls_hourly):
                self.logger.info(
                    "Approaching rate limit; Removing deleted URLs.")
                # handle deleted urls while we wait for rate limit to reset
                self.remove_deleted_urls(cs_deleted_indicators_chunks)

                now = time.time()  # wait until hour since last reset
                # 1 hour (3600s) - time since last hour (60s of wiggle room)
                wait_time = 3660 - (now - self.last_hour)
                wait_time_str = str(datetime.timedelta(seconds=wait_time))
                self.logger.info(
                    "Finished removing deleted URLs; Activating changes.")

                self.zs_ingest.activate_changes()
                self.logger.info(
                    "Activated Changes; Sleeping for " + wait_time_str + " seconds.")
                time.sleep(wait_time)  # idle for remainder of hour; rate-limit resets

                
                    
                self.logger.info(
                    "Waking up; Resetting rate limit monitoring variables and continuing execution.")
                self.last_hour = time.time()  # reset last hour
                self.rate_limit_monitor = 0  # reset rate limit



            # add length of eligible urls to rate limit monitor
            number_new_urls = len(chunk)
            self.rate_limit_monitor = self.rate_limit_monitor + number_new_urls

            # classify indicators, model return values for ZScaler ingestion
            self.logger.info("Classifying " + str(number_new_urls) +
                             " new URLs; Rate limit monitor: " + str(self.rate_limit_monitor) + "/" + str(self.zs_max_calls_hourly))
            zs_ingestable_chunk = self.zs_lookup.url_look_up(
                chunk)  # returns indicators formatted for ingestion

            # URL Look Up rate limit exceeded
            # This shouldn't happen unless debugging
            if 'Retry-After' in zs_ingestable_chunk:
                wait_time = int(
                    zs_ingestable_chunk['Retry-After'].split(" ")[0]) + 10
                self.logger.info(
                    "URL Look Up rate limit exceeded. Waiting " + str(wait_time) + " seconds.")
                time.sleep(wait_time)  # idle
                self.logger.info(
                    "Waking up; Resetting rate limit monitoring variables and continuing execution.")
                self.last_hour = time.time()  # reset last hour
                self.rate_limit_monitor = 0  # reset rate limit
                return

            # append to new indicator payload
            self.zs_payload['urls'] = self.zs_payload['urls'] + \
                zs_ingestable_chunk['urls']
            self.zs_payload['dbCategorizedUrls'] = self.zs_payload['dbCategorizedUrls'] + \
                zs_ingestable_chunk['dbCategorizedUrls']
            zs_payload_size = len(
                self.zs_payload['urls']) + len(self.zs_payload['dbCategorizedUrls'])
            self.logger.info("New indicators payload size: " +
                             str(zs_payload_size) + "/" + str(self.zs_max_payload_size) + ".")

            # push new indicators once new payload reaches maxium payload size
            if zs_payload_size >= self.zs_max_payload_size:
                self.logger.info(
                    "New Indicators exceeds maximum payload size; Posting URLs to Zscaler and emptying payload.")
                self.zs_ingest.push_new(self.zs_payload)
                self.zs_payload['urls'] = []
                self.zs_payload['dbCategorizedUrls'] = []

        # reaching this line implies a successful run; reset the fail streak
        killswitch.succeed()

    def remove_deleted_urls(self, chunks):
        for chunk in chunks:
            # append to deleted indicator payload
            self.zs_payload_deleted = self.zs_payload_deleted + chunk
            zs_payload_deleted_size = len(self.zs_payload_deleted)
            self.logger.info("Deleted indicators payload size: " +
                             str(zs_payload_deleted_size) + "/" + str(self.zs_max_payload_size) + ".")

            # push deleted indicators once deleted payload reaches maxium payload size
            if zs_payload_deleted_size >= self.zs_max_payload_size:
                self.logger.info(
                    "Deleted Indicators exceeds maximum payload size; Posting URLs to Zscaler and emptying payload.")
                self.zs_ingest.push_deleted(self.zs_payload_deleted)
                self.zs_payload_deleted = []
