from app._util.logger import Logger
from app.crowdstrike.crowdstrike_auth import CrowdStrikeAuth
from app.crowdstrike.api.intel_pull import IntelPull
from app.zscaler.zscaler_auth import ZscalerAuth
from app.zscaler.api.category import Category
from app.zscaler.api.lookup import LookUp
from app.zscaler.api.intel_push import IntelPush
import time


class Integration():
    def __init__(self):
        self.logger = Logger()
        self.logger.info("CrowdStrike/Zscaler Integration starting...")
        
       
        self.authenticate()

        #time keeping & rate limit monitoring
        self.rate_limit_monitor = 0
        self.start_time = time.time()
        self.last_hour = self.start_time

        #store intermediary urls from ZScaler URL look up responses
        self.zs_payload = {
            'urls': [],
            'dbCategorizedUrls': []
        }

        self.zs_payload_deleted = []
    
    def authenticate(self):
        #auth service modules for both parties
        self.cs_auth = CrowdStrikeAuth()     #CrowdStrike auth init
        self.zs_auth = ZscalerAuth()         #ZScaler auth init
        self.cs_auth.refresh_token()         #use this funciton to refresh CrowdStrike bearer token
        self.zs_auth.refresh_token()         #use this function to refresh ZScaler cookie

        #instantiate modules, each module has a specific task
        self.cs_intel = IntelPull(self.cs_auth)                  #CS intel controller init
        self.zs_cat = Category(self.zs_auth)                     #category controller init
        self.zs_cat_id = self.zs_cat.custom_category_check()[1]  #category check; returns CrowdStrike custom category ID
        self.zs_lookup = LookUp(self.zs_auth)                    #URL Lookup controller init
        self.zs_ingest = IntelPush(self.zs_auth, self.zs_cat_id)      #ZScaler ingest controller init
    
    def integrate(self, killswitch):
        #main loop

        #before looping, check if approaching rate limit for URL look up (40000 url/hr)
        if(self.rate_limit_monitor > 30000):        #30000 (10000 buffer)
            now = time.time()                       #wait until hour since last reset
            wait_time = 3660 - (now - last_hour)    #1 hour (3600s) - time since last hour
            self.logger.info("Approaching rate limit; Sleeping for " + str(wait_time) + " seconds.")
            
            time.sleep(wait_time)                   #idle
            
            self.logger.info("Waking up; Resetting rate limit monitoring variables and continuing execution.")
            self.last_hour = time.time()            #reset last hour
            self.rate_limit_monitor = 0             #reset rate limit

        #query CrowdStrike Intel API for indicators + deleted indicators 
        cs_indicators = self.cs_intel.get_indicators()                  #returns formatted indicator urls from Intel API
        cs_deleted_indicators = self.cs_intel.get_deleted_indicators()  #returns formatted deleted indicator urls from Intel API            

        #add length of eligible urls to rate limit monitor
        number_new_urls = len(cs_indicators)
        self.rate_limit_monitor = self.rate_limit_monitor + number_new_urls
        
        #classify indicators, model return values for ZScaler ingestion
        self.logger.info("Classifying " + str(number_new_urls) + " new URLs; Rate limit monitor: " + str(self.rate_limit_monitor) + "/40000.")
        zs_ingestable_cs_indicators = self.zs_lookup.url_look_up(cs_indicators) #returns indicators formatted for ingestion
        
        #URL Look Up rate limit exceeded
        #This shouldn't happen unless debugging
        if 'Retry-After' in zs_ingestable_cs_indicators:
            wait_time = int(zs_ingestable_cs_indicators['Retry-After'].split(" ")[0]) + 10
            self.logger.info("URL Look Up rate limit exceeded. Waiting " + str(wait_time) + " seconds.")
            time.sleep(wait_time)                   #idle      
            self.logger.info("Waking up; Resetting rate limit monitoring variables and continuing execution.")
            self.last_hour = time.time()                 #reset last hour
            self.rate_limit_monitor = 0                  #reset rate limit
            return

        
        #append to new indicator payload
        self.zs_payload['urls'] = self.zs_payload['urls'] + zs_ingestable_cs_indicators['urls']
        self.zs_payload['dbCategorizedUrls'] = self.zs_payload['dbCategorizedUrls'] + zs_ingestable_cs_indicators['dbCategorizedUrls']
        zs_payload_size = len(self.zs_payload['urls']) + len(self.zs_payload['dbCategorizedUrls'])
        self.logger.info("New indicators payload size: " + str(zs_payload_size) + "/1000.")
        
        #append to deleted indicator payload
        self.zs_payload_deleted = self.zs_payload_deleted + cs_deleted_indicators
        zs_payload_deleted_size = len(self.zs_payload_deleted)
        self.logger.info("Deleted indicators payload size: " + str(zs_payload_deleted_size) + "/1000.")

        #push new indicators once new payload reaches 1000 urls
        if zs_payload_size >= 1000:
            self.logger.info("New Indicators Payload length exceeds 1000; Posting URLs to ZScaler and emptying payload.")
            self.zs_ingest.push_new(self.zs_payload) 
            self.zs_payload['urls'] = []
            self.zs_payload['dbCategorizedUrls'] = []
            
        #push deleted indicators once deleted payload reaches 1000 urls
        if zs_payload_deleted_size >= 1000:
            self.logger.info("Deleted Indicators Payload length exceeds 1000; Posting URLs to ZScaler and emptying payload.")
            self.zs_ingest.push_deleted(self.zs_payload_deleted)  
            self.zs_payload_deleted = []
        
        #reaching this line implies a successful run; reset the fail streak
        killswitch.succeed()

