#CrowdStrike - ZScaler Intel Bridge
#ZScaler API functions

import http.client
import json
import requests
import time
import datetime
import urllib.parse
from urllib.parse import unquote
import re
import sys
import logging

import ZScaler_Intel_Bridge_config as config
from CIB_Logging import CIB_Logger


class Zscaler():

    hostname = config.zs_hostname
    username = config.zs_username
    password = config.zs_password
    apikey = config.zs_apiKey
    cat_name = config.cs_category_name

    def error_shutdown(self):
        CIB_Logger().logging_data('error', 'Please correct the issue and restart the Intel Bridge.')
        sys.exit()
    
    def url_quota(self, cookie):
        quota_url=self.hostname +  '/api/v1/urlCategories/urlQuota'
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(cookie)
        }
        
        try:
            quota_check = requests.request("GET", quota_url, headers=headers)
            quota_result = str(quota_check.status_code)

            ###LOG RESPONSE
            CIB_Logger().logging_data('info', 'Zscaler quota response code: ' + quota_result)

            if quota_result.startswith('20'):
                quota_data = quota_check.json()
                quota_amount = quota_data['remainingUrlsQuota']
                print('Quota amount '+ str(quota_amount))
                CIB_Logger().logging_data('info', 'Successfully retrieved quota: ' + str(quota_amount))

            else:
                CIB_Logger().logging_data('error', 'Error retrieving quota with status code: ' + quota_result)

        except:
            CIB_Logger().logging_data('error', 'Error retrieving quota.' )
        
        return quota_amount

    def obfuscateApiKey (self, now):
        CIB_Logger().logging_data('debug', 'Starting Zscaler key obfuscation process.')
        seed = self.apikey
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ''
        for i in range(0, len(str(n)), 1):
            key += seed[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += seed[int(str(r)[j])+2]
        CIB_Logger().logging_data('debug','Zscaler key obfuscation process successfully completed.')
        return key

    def authenticate(self):
        #configure the appropriate info for the call
        url = self.hostname + "/api/v1/authenticatedSession"
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)

        #call components
        api_key = self.obfuscateApiKey(now)
        payload={"username":self.username,"password":self.password,"apiKey": api_key ,"timestamp": now}
        headers = {'Content-Type': 'application/json', 'cache-control': "no-cache"}

        #call to Zscaler to get authentication Cookie
        CIB_Logger().logging_data('debug', 'Calling the Zscaler authentication API for authentication cookie.')
        
        try:
            response = requests.request("POST", url, headers=headers, data=json.dumps(payload))

            #LOG RESPONSE
            print(response.status_code)
            print(response.text)
            print(response.headers)

            cookie = response.cookies['JSESSIONID']
            results = str(response.status_code)
            if results.startswith('20'):
                CIB_Logger().logging_data('info', 'Successfully retrieved Zscaler cookie.')
            response.raise_for_status()

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error contacting Zscaler cookie API: ' + str(e))
            CIB_Logger().logging_data('error', 'System will now exit')
            sys.exit()

        #return Zscaler auth cookie
        return cookie

    def custom_cat_check(self, cookie):
        #checks for a CrowdStrike custom URL category with the name in the config file
        CIB_Logger().logging_data('debug', 'Preparing to validate if the CrowdStrike custom category exists.')
        
        custom_cat_check_url = self.hostname+"/api/v1/urlCategories?customOnly=true"
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(cookie)
        }

        CIB_Logger().logging_data('debug', 'Calling the Zscaler custom category API to check for a CrowdStrike category.')
        
        try:
            custom_url_cat = requests.request("GET", custom_cat_check_url, headers=headers)
            cat_result = str(custom_url_cat.status_code)
        
        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error contacting Zscaler URL category API: ' + str(e))
            CIB_Logger().logging_data('error', 'System will now exit')
            sys.exit()
       

        CIB_Logger().logging_data('info', 'A authentication cookie has been successful retrieved data from the Zscaler URL categories API. \n    Response code: ' + cat_result + '\n ')

        custom_cats = custom_url_cat.json()

        if len(custom_url_cat.json()) == 0:
            CIB_Logger().logging_data ('info', 'The API response shows that no custom categories exist')
            result = 'No Category Matches'
            category_id = 'none found'
            custom_urls = 'none found'
            return result, category_id, custom_urls

        else:

            for cat in custom_cats:
                if self.cat_name == cat['configuredName']:
                    CIB_Logger().logging_data('info', 'The API response shows the category ' + str(self.cat_name) + ' exists.')
                    result = "Category Exists"
                    category_id = cat['id']
                    custom_urls = cat['urls']

                else:
                    CIB_Logger().logging_data('info', 'The API response shows the category ' + str(self.cat_name) + ' does not exists.')
                    result = 'No Category Matches'
                    category_id = 'none found'
                    custom_urls = 'none found'

                return result, category_id, custom_urls
    
    def activate_changes(self, cookie):
        CIB_Logger().logging_data('debug', 'Committing changes to Zscaler.')

        status_url = self.hostname + "/api/v1/status"
        
        headers = { 
            'content-type': "application/json", 
            'cache-control': "no-cache", 
            'cookie': "JSESSIONID=" + str(cookie) }

        try:
            status_resp = requests.request("GET", url = status_url, headers = headers)
            CIB_Logger().logging_data('info', "Current status of commits for Zscaler: " + str(status_resp))

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error checking Zscaler commit status: ' + str(e))
            CIB_Logger().logging_data('error', 'System will now exit')
            sys.exit()

        activate_url = self.hostname + "/api/v1/status/activate"
        
        activate_resp = requests.request("POST", url = activate_url, headers = headers)

        print (activate_resp.status_code)

    def create_cs_cat(self, cookie):
        CIB_Logger().logging_data('info', 'Creating the CrowdStrike URL category: ' + str(self.cat_name))

        url=self.hostname + "/api/v1/urlCategories"

        #payload URLs field needs to include 1 URL to be  valid
        payload = {
        "configuredName" : self.cat_name,
        "customCategory" : "true",
        "superCategory" : "USER_DEFINED",
        "urls" : [  "mine.ppxxmr.com:5555" ]
        }

        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(cookie)
        }
    
        try:
            cs_cat = requests.request("POST", url=url, headers=headers, data=json.dumps(payload))
            cs_cat_results = str(cs_cat.status_code)
            CIB_Logger().logging_data('info', 'Results of API call to create custom CrowdStrike category in Zscaler: ' + cs_cat_results)
            cs_cat_result = cs_cat.json()
            category_id = cs_cat_result['id']
            return category_id
        
        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error contacting Zscaler URL category API: ' + str(e))
            CIB_Logger().logging_data('error', 'System will now exit')
            sys.exit()
    
    def handle_reply(self, response_code, rep_results):

        #Zscaler quotas may not be large enough to accomidate all CS data
        # Need to add the ability to post processed data before 429 and record partial   
        if response_code == '429':
            print(rep_results)
            stand_off = rep_results['Retry-After']
            stand_off_regex = r"(^[\d]*)"
            seconds_match = re.search(stand_off_regex, stand_off)
            seconds = seconds_match.group(1)
            time_now = datetime.datetime.now()
            pause_time = int(seconds) + 120
            delay_time = time_now + datetime.timedelta(seconds=pause_time)
            while time_now < delay_time:
                CIB_Logger().logging_data('info', 'Waking back up at: ' + str(delay_time))
                time_now = datetime.datetime.now()
                time.sleep(60)
                print(time_now)
            cookie = self.authenticate()
            return cookie
    
        if response_code == '401':
            CIB_Logger().logging_data('info', 'Unauthenticated error - attempting to refresh Zscaler cookie.')
            cookie = self.authenticate()
            return cookie


    def check_url(self, cat_id, cs_urls, cookie):
        #this checks to see if the URL has a Zscaler category

        CIB_Logger().logging_data('debug', 'Starting URL Category checks')
        url_check = self.hostname + "/api/v1/urlLookup"

        for url in cs_urls:
            if url.isascii():
                print('This is an ACSII URL.')
            else:
                print('This is not an ACSII URL.')
                CIB_Logger().logging_data('debug', 'Non-ACSII characters detected, removing URL: ' + str(url))
                cs_urls.remove(url)

        total_count = len(cs_urls)
        urls_to_check = total_count

        #Zscaler only allows 100 URls to be checked at a time - counter for number of runs needed
        runs = 1 if total_count < 99 else round(urls_to_check/99)
        CIB_Logger().logging_data('debug', 'Projected number of runs required without accounting for syntax errors: ' + str(runs) + ' for ' + str(total_count) + ' URLs.')

        #tracking variables 
        total_runs = runs       #total number of cycles to run through
        urls_checked = 0        #tracks urls checked
        processed_list = []     #hold the processed URL list
        url_counter = 0         #counts total number of URLs checked
        no_urls = False         #used to identify if all URLs are removed for syntax issues
        
        #lists to send to ZScaler
        update_list = []
        categorized_urls = []

        #variable to use for 429 partial posts
        run_type_part = False
        rep_results_429 = 'none'    #for 429 will hold the response with hold down time

        while runs > 0:
            #Need to slice the CS list into 100 URL sets for ZS to process
            number_to_check = urls_checked + 99
            
            #account for negative count 
            if urls_to_check < 0:
                number_to_check = number_to_check + urls_to_check

            #slice for data
            processed_urls = cs_urls[urls_checked:number_to_check]

            #create a list of URLs to validate in Zscaler
            for url in processed_urls:
                #check for URL encoding and select non-encoded versions
                decoded = unquote(unquote(url))
                if decoded == url:
                    processed_list.append(url)
                else:
                    processed_list.append(decoded)

            payload = processed_urls
            headers = {'Content-Type': 'application/json','Cookie': 'JSESSIONID='+str(cookie)}

            CIB_Logger().logging_data('info', 'Checking for URL categorization in Zscaler.')

            #check for categorization in Zscaler
            try:
                rep_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                response_code = str(rep_response.status_code)
                url_counter = url_counter + urls_checked
                CIB_Logger().logging_data('debug', 'Zscaler URL categorization response: ' + response_code)
            
            except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
                CIB_Logger().logging_data('error', 'Error attempting to check URL categroization in Zscaler. Response: ' + str(e))
                return
    
            print('++++++++++++++++++++++++++++++++')
            print('rep results')
            print (response_code)
            print('++++++++++++++++++++++++++++++++')
        

            if response_code == '401':
                #calls error handling function
                rep_results = ''
                cookie = self.handle_reply(cat_id, response_code)
                #recreate headers with new auth cookie
                headers = {'Content-Type': 'application/json','Cookie': 'JSESSIONID='+str(cookie)}

                try:
                    rep_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                    url_counter = url_counter + urls_checked
                    response_code = str(rep_response.status_code)
                    CIB_Logger().logging_data('debug', 'Standard Category check for ZScaler 401 Code Corrected: ' + response_code)
                
                except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
                    CIB_Logger().logging_data('error', 'Error attempting to resume check URL categroization in Zscaler after 401 reply. Response: ' + str(e))
                    CIB_Logger().logging_data('error', 'System is unable to continue.' )
                    sys.exit()
                
            #API is over it's hourly quota
            elif response_code == '429':
                rep_results = rep_response.json()
                run_type_part = True
                error_check = True
                rep_results_429 = rep_results
                break

            else:
                rep_results = rep_response.json()
                print (rep_results)
                error_check = response_code.startswith('20')
                print(error_check)
                
            while error_check != True:
                #checks for incompatible URL format to Zscaler requirements
                if 'Urls not provided' in rep_results.values():
                    CIB_Logger().logging_data('debug', 'URLs not provided returned in Zscaler API response.')
                    no_urls = True
                    update_list = 0
                    categorized_urls = 0
                    run_type_part = 'complete'
                    rep_results_429 = 'none'
                    return update_list, categorized_urls, run_type_part, rep_results_429 

                if 'INVALID_INPUT_ARGUMENT' in rep_results.values():
                    #identify the invalid URLs
                    print(rep_results.values())
                    print(len(rep_results))
                    print(rep_results)
                    regex = r"\[(.*?)\]"
                    message = rep_results['message']
                    error_match = re.search(regex, message)
                    removal = error_match.group(1)
                    CIB_Logger().logging_data('debug', 'URL reported as invalid was: ' + str(removal))

                    if removal in processed_urls:
                        processed_urls.remove(removal)
                    
                    else:
                        processed_urls = processed_urls

                    try:
                        #remove the urls and recheck - could be removed to increase speed of the process
                        #processed_urls.remove(removal)
                        payload = processed_urls
                        time.sleep(2)
                        rep_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                        response_code = str(rep_response.status_code)
                        print (response_code)
                        if response_code == '401':
                            cookie=self.authenticate()
                            headers['Cookie']= 'JSESSIONID='+str(cookie)
                            rep_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                        else:
                            pass
                        rep_results = rep_response.json()
                        CIB_Logger().logging_data('debug', 'The invalid URL  check resend response: ' + response_code)
                        error_check = response_code.startswith('20')
                        
                    except ValueError:
                        CIB_Logger().logging_data('error', 'URL for removal was not found in the URL list to check') 
                        error_check = True
                        continue
                    
                    if error_check == True:
                        url_counter = url_counter-1
                    
                    elif response_code == '429':
                        run_type_part = True
                        rep_results_429 = rep_results
                        break
                    
                    elif response_code == '401':
                        cookie=self.handle_reply(response_code, rep_results)
                        headers['Cookie']= 'JSESSIONID='+str(cookie)
                        rep_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))

                else:
                    retry_counter = 0
                    retry_result = False
                    while retry_result == False:
                        time.sleep(2)
                        retry_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                        retry_code = str(retry_response.status_code)
                        ###LOG
                        print (retry_code)
                        retry_results = retry_response.text
                        print (retry_results)
                        retry_check = retry_code.startswith('20')
                        if retry_check == False:
                            if retry_code == '429':
                                run_type_part = True
                                rep_results_429 = rep_results
                                break    

                            elif retry_code == '401': 
                                cookie=self.handle_reply(response_code, rep_results)
                                headers['Cookie']= 'JSESSIONID='+str(cookie)
                                retry_response = requests.request("POST", url_check, headers=headers, data=json.dumps(payload))
                                retry_code = str(retry_response.status_code)
                                retry_check = retry_code.startswith('20')

                            retry_counter = retry_counter + 1
                        else:
                            retry_counter = 0
                            break
                        if retry_counter > 5:
                            print("exceeded retries")
                            sys.exit()
                            
            if no_urls == True:
                CIB_Logger().logging_data('info', 'The identified URLs do not meet the accepted format')
                        
            else:
                for result in rep_results:
                    print(result)
                    if result['urlClassificationsWithSecurityAlert']:
                        #there is no reason to include URLs with established alerts
                        pass
                    elif 'urlClassifications' not in result:
                        #there's no URL classification present
                        update_list.append(result['url'])
                    elif 'MISCELLANEOUS_OR_UNKNOWN' in result['urlClassifications']:
                        #there's no real URL classification
                        update_list.append(result['url'])
                    else:
                        #everything else should have a category
                        categorized_urls.append(result['url'])

            
            total = len(update_list) + len(categorized_urls)
            CIB_Logger().logging_data('info', 'URL Classfication Counter: ' + str(total))
            CIB_Logger().logging_data('info', 'Runs: ' + str(runs) + ' of ' + str(total_runs) + ' remaining.')

            urls_checked = len(processed_list)
            urls_to_check = urls_to_check - 99
            runs = runs -1

            if runs == 0:
                break
            time.sleep(5)

        CIB_Logger().logging_data('info', 'URL Categorization Completed.')
            
        return update_list, categorized_urls, run_type_part, rep_results_429    


    def remove_url(self, cookie, cat_id, urls_to_remove):
        #removed indicators that CS had deleted


        CIB_Logger().logging_data('info','Removing deleted URLs from Zscaler')
        encode_cat_name = urllib.parse.quote(self.cat_name)
        remove_url = self.hostname + '/api/v1/urlCategories/' + str(cat_id) + '?action=REMOVE_FROM_LIST'

        payload = {
        "customCategory": "true",
        "superCategory" : "USER_DEFINED",
        "urls" : cs_urls,
        "id" : cat_id,
        "configuredName" : self.cat_name}

        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(cookie)
        }


        try:
            zs_update = requests.request("PUT", url=remove_url, headers=headers, data=json.dumps(payload))
            response_code = str(zs_update_results)
            put_results = zs_update.json()
            zs_update_results = zs_update.status_code

        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error attempting to remove URL from category. Response: ' + str(e))
            return
        
        return response_code

    def update_url(self, cookie, cat_id, cs_urls, already_cat_urls):
        #sends updates to Zscaler

        removal_list_count = 0 

        CIB_Logger().logging_data('info', 'Preparing to send update to Zscaler')

        encode_cat_name = urllib.parse.quote(self.cat_name)
        update_url = self.hostname + '/api/v1/urlCategories/' + str(cat_id) + '?action=ADD_TO_LIST'
        print (update_url)

        print(encode_cat_name)
        payload = {
        "customCategory": "true",
        "superCategory" : "USER_DEFINED",
        "urls" : cs_urls,
        "dbCategorizedUrls": already_cat_urls,
        "id" : cat_id,
        "configuredName" : self.cat_name}

        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': "JSESSIONID=" + str(cookie)}

        try:
            zs_update = requests.request("PUT", url=update_url, headers=headers, data=json.dumps(payload))
            response_code = str(zs_update.status_code)
            CIB_Logger().logging_data('info', 'Sent URL update to ZScaler with response of: ' + response_code)

        
        except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
            CIB_Logger().logging_data('error', 'Error attempting to send URL update to ZScaler. Response: ' + str(e))
            return
        
        reworked_succeeded = 0
        zs_update_results = zs_update.status_code
        error_check = response_code.startswith('20')
        put_results = zs_update.json()

        if error_check != True:
   
            if 'INVALID_INPUT_ARGUMENT' in put_results.values():
                regex = r"\[(.*?)\]"
                message = put_results['message']
                print('Message:')
                print(message)
                error_match = re.search(regex, message)
                removal_list_str = error_match.group()
                removal_list = removal_list_str.strip('][').split(', ')
                removal_list_count = len(removal_list)
                CIB_Logger().logging_data('debug', 'Update URL: Error was: ' + str(removal_list))
                resend_list = [x for x in cs_urls if x not in removal_list]

                CIB_Logger().logging_data('info', 'Preparing to resend URLs without identified error URL(s).')
                payload["urls"] = resend_list
                time.sleep(2)

                try:
                    zs_update2 = requests.request("PUT", url=update_url, headers=headers, data=json.dumps(payload))             
                    resend_code = str(zs_update2.status_code)
                    CIB_Logger().logging_data('info', 'Resend URLs without identified error URL(s) result was: ' + resend_code)
                    resend_result = zs_update2.json()
                
                except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
                    CIB_Logger().logging_data('error', 'Error attempting to send URL update to ZScaler. Response: ' + str(e))
                    return

                if resend_code.startswith('20'):
                    print ("Resend was successful")
                    post_result = 'success'
                
                else:
                    post_result = 'failed'
                             
                for i in removal_list:
                    print(i)
                    decoded = unquote(unquote(i))
                    print (decoded)
                    modified_list = []
                    if decoded == i:
                        print('Does not appear to be an encoding error.')

                    else:
                        print('Potentially an encoding error')
                        modified_list.append(decoded)

                        payload["urls"] = modified_list
                        print ("moved and removed encoded url")
                        time.sleep(2)
                        zs_decode = requests.request("PUT", url=update_url, headers=headers, data=json.dumps(payload))             
                        decode_code = str(zs_decode.status_code)
                        print (decode_code)
                        print (zs_decode.text)
                        decode_result = zs_decode.json()
                        print( 'Decode Results for Url '+ str(i) +': \n '  + decode_code + '    ' + str(decode_result))
                        encoding = True
                
                        if decode_code.startswith('20') :
                            print('Resent URL Successfully')
                            reworked_succeeded = reworked_succeeded + 1

            else:    
                print("Update complete")
                post_result = 'success'
        
        else:
            print ("Sent successfully")
            post_result = 'success'

        if post_result == 'success':
            status = 'Completed'
            total = removal_list_count + reworked_succeeded
        
        else:
            status = 'Failed: ' + resend_result
            total = 0

        print(cs_urls)
        
        return status, total



#Zscaler = Zscaler()
 
#Zscaler.authenticate()

#Zscaler.check_url()
#Zscaler.custom_cat_check()
#Zscaler.update_cat_data()
#Zscaler.create_cs_cat()
#Zscaler.back_off(110)
