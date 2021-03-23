

#Zscaler - CrowdStrike Intel Bridge

import logging
import time
import sys
import datetime

#Local inputs
from CIB_Logging import CIB_Logger
import ZScaler_Intel_Bridge_config as config
from ZScaler_Intel_Bridgev2 import Zscaler
from CrowdStrike_Intel_Bridgev2 import CrowdStrike

class CS_ZS_Intel_Bridge():

    #CrowdStrike variables
    current_cs_urls = []
    cs_token = ''
    cs_deleted_urls = []
    next_page = ''

    
    #Zscaler variables
    current_zs_urls = []        #current URLs in Zscaler category
    zs_initial_size = 0         #current size of URL list
    zs_url_update = []          #list of URLs to check for update to ZScaler
    zs_url_remove = []          #list of URLs to remove from ZScaler

    zs_update_custom = []       #list of URLs that will attempt to be pushed
    zs_already_cat_urls = []    #list of URLs with existing Zscaler  categories
    zs_cat_id = ''              #Custom Category ID from Zscaler
    zs_cookie = ''              #Zscaler authentication cookie
    zs_quota = ''               #Zscaler custom URL quota

    #Other
    end_time=''                 #datetime stamp for start of process -> tracker key
    post_type = ''              #used to post partial pulls because of 429 errors
    json_429 = ''               #stores 429 header response

    def starting(self):

        CIB_Logger().logging_data('info', 'Zscaler - CrowdStrike Intel Bridge Starting Up.')

    def zs_auth(self):
        #calls Zscaler Intel Bridge file
        #creates the Zscaler authentication cookie
        CIB_Logger().logging_data('debug', 'Calling the Zscaler authentication function.')
        self.zs_cookie = Zscaler().authenticate()
    
    def cs_auth(self):
        #calls CrowdStrike Intel Bridge file
        #creates a CrowdStrike OAuth2 Token
        result, message = CrowdStrike().get_token()
        
        if message == 'success':
            self.cs_token = result
            CIB_Logger().logging_data('info', message)
        
        else:
            print (message)
            CIB_Logger().logging_data('error', message)
    
    def zs_quota(self):
        self.zs_auth()

        #calls Zscaler Intel Bridge file
        #retrieves the Zscaler custom URL quota

        real_zs_quota = Zscaler().url_quota(self.zs_cookie)

        #take 10% off the quota just to be safe
        self.zs_quota = int(real_zs_quota - int(real_zs_quota * .10))
        CIB_Logger().logging_data('info', 'Current available Zscaler quota is:' + str(self.zs_quota))

    def zs_create(self):

        self.zs_auth
        #calls Zscaler Intel Bridge file
        #commits the changes to the Zscaler platform

        Zscaler().activate_changes(self.zs_cookie)
        if self.post_type == 'partial':
            Bridge_Intel.starting()
            Bridge_Intel.zs_auth()
            Bridge_Intel.zs_quota()
            Bridge_Intel.zs_cat_check()
            Bridge_Intel.cs_auth()
            Bridge_Intel.cs_check()
            Bridge_Intel.zs_update_urls()
            Bridge_Intel.zs_create()


    def zs_cat_check(self):
        self.zs_auth()

        #calls Zscaler Intel Bridge file
        #checks for and retrieves the custom CrowdStrike category

        CIB_Logger().logging_data('debug', 'Calling the Zscaler URL category check function.')
        result, self.zs_cat_id, self.current_zs_urls = Zscaler().custom_cat_check(self.zs_cookie)

        if result == "Category Exists":
            CIB_Logger().logging_data('info', 'The CrowdStrike category exists in Zscaler. Identified URLs will be added to this category.')
            self.zs_initial_size = len(self.current_zs_urls)

        else:
            CIB_Logger().logging_data('info', 'The CrowdStrike category does not exists in Zscaler. Creating a new category.')
            zs_cat_id = Zscaler().create_cs_cat(self.zs_cookie)

    def zs_check_classification(self):
        self.zs_auth()

        #calls Zscaler Intel Bridge file
        #Checks for CS URL classification in ZScaler - quota impacted

        CIB_Logger().logging_data('info', 'The CrowdStrike category exists in Zscaler URL category creating URL list and category ID.')

        #retrives categorized and uncategories URL lists, run type, and 429 responses from Zscaler API calls to identify any current classifications for the CrowdStrike URLs
        self.zs_update_custom, self.zs_already_cat_urls, run_type, response_429 = Zscaler().check_url(self.zs_cat_id, self.zs_url_update, self.zs_cookie)
        total_update = (len(self.zs_update_custom)) + (len(self.zs_already_cat_urls))

        CIB_Logger().logging_data('info', 'Total URLs to post to Zscaler: ' + str(total_update))
        if total_update > self.zs_quota:
            print('WARNING - Total Exceeds the Quota Available.')
        
        else:
            print ('The current quota is enough to handle the update')

        if run_type:
            self.post_type = 'partial'
            if response_429 != 'none':
                self.json_429 = response_429

            CIB_Logger().logging_data('info', 'Partial run due to 429 error.')

        else:
            self.post_type = 'complete'
            CIB_Logger().logging_data('info', 'Complete run. ' + str(total_update))

    def cs_check(self):
        #calls CrowdStrike Intel Bridge file
        #Checks for new URL sets from CrowdStrike Intel

        pattern = '%Y-%m-%d %H:%M:%S.%f'
        self.end_time = str(datetime.datetime.now())
        end_time = int(time.mktime(time.strptime(self.end_time, pattern)))

        #calls CIB Logger file to determine if previous call attempts were made and set time accordingly
        start_time = CIB_Logger().tracker_last()

        if start_time:
            CIB_Logger().logging_data('info', 'Start time from tacker file: ' + str(start_time))
        else:
            CIB_Logger().logging_data('info', 'There was no start time identified from the tacker file')

        #construct the API query syntax based on the presence or lack of a start_time value
        if start_time == 'none found':
            indicators = "?limit=8000&filter=type:'url'%2Bmalicious_confidence:'high'&include_deleted=false"

            deleted = "?limit=8000&filter=deleted:true%2Btype:'url'%2Bmalicious_confidence:'high'"

        else:
            indicators  = "?limit=8000&filter=last_updated:>" + str(start_time) + "%2Blast_updated:<" + str(end_time) + "%2Btype:'url'%2Bmalicious_confidence:'high'&include_deleted=false"

            deleted = "?limit=8000&filter=last_updated:>"+ str(start_time) + "%2Blast_updated:<" + str(end_time) + "%2Bdeleted:true%2Btype:'url'%2Bmalicious_confidence:'high'"
        
        #if there was a previous call that exceed 24k indicators the 'next_page' value will replace the API query syntax to continue
        if self.next_page:
            indicators = self.next_page

        #Get CS indicators and next_page value if available
        self.current_cs_urls, self.next_page = CrowdStrike().get_intel(self.cs_token, indicators)     
        num_cs_urls = len(self.current_cs_urls)   
        CIB_Logger().logging_data('info', 'Total number of active CrowdStrike URLs retrieved was: ' + str(num_cs_urls))

        #Get CS deleted indicators
        self.cs_deleted_urls, self.next_page = CrowdStrike().get_intel(self.cs_token, deleted)
        num_del_urls = len(self.cs_deleted_urls)

        #log the results of the URL pull and compare that to the available Zscaler quota - not all URLs may be transfered so only a warning will be issued 
        CIB_Logger().logging_data('info', 'Total number of deleted CrowdStrike URLs retrieved was: ' + str(num_del_urls))

        CIB_Logger().logging_data('info', 'Total number of current Zscaler URLs in CrowdStrike Category: ' + str(len(self.current_zs_urls)))

        if num_cs_urls > self.zs_quota:
            CIB_Logger().logging_data('warning', 'The number of retrieved CrowdStrike URLs may exceed the safe quota amount.') 
        
        else:
            CIB_Logger().logging_data('info', 'The number of retrieved CrowdStrike URLs appears to currently be under the safe quota amount.') 

        if num_del_urls > 0:
            #determine if the current list has URLs that need to be deleted
            self.zs_url_remove = [x for x in self.cs_deleted_urls if x in self.current_zs_urls]

            #remove the URLs if any where identified        
            url_remove_num = (len(self.zs_url_remove))
            if url_remove_num > 0:
                CIB_Logger().logging_data('info', 'The number of URls that need to be removed from Zscaler: ' + str(url_remove_num))
                for del_url in self.zs_url_remove:
                    Zscaler().remove_url(self.zs_cookie, self.zs_cat_id, self.zs_url_update)
                    self.current_zs_urls = self.current_zs_urls.remove(del_url)
                    CIB_Logger().logging_data('info', 'Removed CrowdStrike URL: ' + str(del_url))
            else:
                CIB_Logger().logging_data('info', 'There are no CrowdStrike URLs that need to be removed at this time.')

        if num_cs_urls > 0:
            #determines if the URLs are in the current category list or need to be sent for classification
            self.zs_url_update = [x for x in self.current_cs_urls if x not in self.current_zs_urls]
            url_add_num = len(self.zs_url_update)
            CIB_Logger().logging_data('info', 'URLs that need to be check for potential addition: ' + str(url_add_num))

            if url_add_num > 0:
                self.zs_check_classification()
            else:
                CIB_Logger().logging_data('info', 'There are no new CrowdStrike URLs that need to be added at this time.')
        else:
            CIB_Logger().logging_data('info', 'No new CrowdStrike URLs to update.')
            CIB_Logger().logging_data('info', 'System will now exit')
            sys.exit()

    def zs_update_urls(self):
        #calls Zscaler Intel Bridge file

        #identifies if the URL was interupted by a 429 error
        if self.post_type == 'partial':
            CIB_Logger().logging_data('info', 'Calling Zscaler handle reply function for 429 hold period time.')
            self.cookie = Zscaler().handle_reply('429', self.json_429)
            CIB_Logger().logging_data('info', 'Hold period is over. Posting process URLs and restarting collection. ')

        self.zs_auth()

        result, total_count = Zscaler().update_url(self.zs_cookie, self.zs_cat_id, self.zs_url_update, self.zs_already_cat_urls)

        if result == 'Completed':

            CIB_Logger().tracker_record(self.end_time, self.zs_quota, len(self.current_cs_urls), len(self.zs_url_remove), len(self.zs_url_update), self.zs_initial_size, self.post_type)
            CIB_Logger().logging_data('info', 'URLs have successfully been uploaded and tracker record has been recorded.')

        else:
            CIB_Logger().logging_data('error', 'There was an error uploading the URLs or updating the tracker record.')
        
        if self.next_page == 'None':
            pass
        else:
            CIB_Logger().logging_data('info', 'A next page value has been detected, executing next page restart to continue collection.')
            self.cs_auth()
            self.cs_check()




Bridge_Intel = CS_ZS_Intel_Bridge()

Bridge_Intel.starting()
Bridge_Intel.zs_auth()
Bridge_Intel.cs_auth()
Bridge_Intel.zs_quota()
Bridge_Intel.zs_cat_check()
Bridge_Intel.cs_check()
Bridge_Intel.zs_update_urls()
Bridge_Intel.zs_create()