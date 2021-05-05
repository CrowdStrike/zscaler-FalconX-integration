import logging
import config as config

# This class provides logging utility throughout the app
# Initialize the class with logger = Logger()
# Use functions to log at desired level
#Example:           logger.info("Message")
# Log File Result:   2021-03-29 18:03:09,154   47631 INFO   Message.


class Logger():
    logger = logging.getLogger()
    logging_level = config.logging_level
    logger.setLevel(logging_level)
    logging.basicConfig(filename='./cs_zscaler_intel_log.log',
                        format='%(asctime)s   %(process)d %(levelname)s   %(message)s')
    ref_file = './cs_zscaler_intel_log_tracker.json'

    def info(self, message):
        content = str(message)
        print(message)
        logging.info(content)

    def debug(self, message):
        content = str(message)
        logging.debug(content)

    def error(self, message):
        content = str(message)
        logging.error(content)


# deprecated logging statements for reference

# ('info', 'CrowdStrike base URL: ' + str(self.base_url))
# ('info', 'API endpoint: ' + auth_URL)
# ('info', "Attempting to get a CrowdStrike OAuth2 token.")
# ('info', 'Response when contacting the CrowdStrike Intel Indicators API: ' + intel_results)
# ('info', 'CrowdStrike Intel Indicators API has been successfully queried. \n    Response code: ' + intel_results)
# ('info', 'Zscaler - CrowdStrike Intel Bridge Starting Up.')
# ('info', message)
# ('info', 'Current available Zscaler quota is:' + str(self.zs_quota))
# ('info', 'The CrowdStrike category exists in Zscaler. Identified URLs will be added to this category.')
# ('info', 'The CrowdStrike category does not exists in Zscaler. Creating a new category.')
# ('info', 'The CrowdStrike category exists in Zscaler URL category creating URL list and category ID.')
# ('info', 'Total URLs to post to Zscaler: ' + str(total_update))
# ('info', 'Partial run due to 429 error.')
# ('info', 'Complete run. ' + str(total_update))
# ('info', 'Start time from tacker file: ' + str(start_time))
# ('info', 'There was no start time identified from the tacker file')
# ('info', 'Total number of active CrowdStrike URLs retrieved was: ' + str(num_cs_urls))
# ('info', 'Total number of deleted CrowdStrike URLs retrieved was: ' + str(num_del_urls))
# ('info', 'Total number of current Zscaler URLs in CrowdStrike Category: ' + str(len(self.current_zs_urls)))
# ('info', 'The number of retrieved CrowdStrike URLs appears to currently be under the safe quota amount.')
# ('info', 'The number of URls that need to be removed from Zscaler: ' + str(url_remove_num))
# ('info', 'Removed CrowdStrike URL: ' + str(del_url))
# ('info', 'There are no CrowdStrike URLs that need to be removed at this time.')
# ('info', 'URLs that need to be check for potential addition: ' + str(url_add_num))
# ('info', 'There are no new CrowdStrike URLs that need to be added at this time.')
# ('info', 'No new CrowdStrike URLs to update.')
# ('info', 'System will now exit')
# ('info', 'Calling Zscaler handle reply function for 429 hold period time.')
# ('info', 'Hold period is over. Posting process URLs and restarting collection. ')
# ('info', 'URLs have successfully been uploaded and tracker record has been recorded.')
# ('info', 'A next page value has been detected, executing next page restart to continue collection.')
# ('info', 'Zscaler quota response code: ' + quota_result)
# ('info', 'Successfully retrieved quota: ' + str(quota_amount))
# ('info', 'Successfully retrieved Zscaler cookie.')
# ('info', 'A authentication cookie has been successful retrieved data from the Zscaler URL categories API. \n    Response code: ' + cat_result + '\n ')
# ('info', 'The API response shows that no custom categories exist')
# ('info', 'The API response shows the category ' + str(self.cat_name) + ' exists.')
# ('info', 'The API response shows the category ' + str(self.cat_name) + ' does not exists.')
# ('info', "Current status of commits for Zscaler: " + str(status_resp))
# ('info', 'Creating the CrowdStrike URL category: ' + str(self.cat_name))
# ('info', 'Results of API call to create custom CrowdStrike category in Zscaler: ' + cs_cat_results)
# ('info', 'Waking back up at: ' + str(delay_time))
# ('info', 'Unauthenticated error - attempting to refresh Zscaler cookie.')
# ('info', 'Checking for URL categorization in Zscaler.')
# ('info', 'The identified URLs do not meet the accepted format')
# ('info', 'URL Classfication Counter: ' + str(total))
# ('info', 'Runs: ' + str(runs) + ' of ' + str(total_runs) + ' remaining.')
# ('info', 'URL Categorization Completed.')
# ('info','Removing deleted URLs from Zscaler')
# ('info', 'Preparing to send update to Zscaler')
# ('info', 'Sent URL update to ZScaler with response of: ' + response_code)
# ('info', 'Preparing to resend URLs without identified error URL(s).')
# ('info', 'Resend URLs without identified error URL(s) result was: ' + resend_code)
