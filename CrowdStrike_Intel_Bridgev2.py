#!/usr/bin/env python

#CrowdStrike - ZScaler Intel Bridge
#CrowdStrike API functions

# Python imports
import requests
import json
import logging
import sys
import urllib
import re
from datetime import datetime
from datetime import timedelta
from requests.exceptions import HTTPError
import time

# Local imports
import ZScaler_Intel_Bridge_config as config
from CIB_Logging import CIB_Logger

class CrowdStrike():

    #imports from config file
    clientID = config.cs_clientID   #CS API ClientID
    secret = config.cs_secret       #CS API Secret
    base_url = config.cs_base_url   #CS cloud base URL

    #local variables
    token_url = "/oauth2/token"                         #OAuth2 token url
    intel_indict = '/intel/combined/indicators/v1'      #intel indicators url
    proxy = config.proxy
    #####################  Need to add proxy configs to requests
    token = ''
    expires = ''
    user_agent = 'CZIB 1.0'


    def get_token(self):
        #Gets the API token using the information provided in the config file

        CIB_Logger().logging_data('info', 'CrowdStrike base URL: ' + str(self.base_url))
        auth_URL = self.base_url + self.token_url  
        CIB_Logger().logging_data('info', 'API endpoint: ' + auth_URL)
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        data = 'client_id=%s&client_secret=%s' %(self.clientID, self.secret)

        try:
            CIB_Logger().logging_data('info', "Attempting to get a CrowdStrike OAuth2 token.")
            response =  requests.post(url=auth_URL, data=data, headers=headers)
            response_code = str(response.status_code)
            r = response.json()
                
        except HTTPError as http_err:
            #catch an HTTP error
            result = 'failure'
            failure_message = 'HTTP Error: ' + http_err
            if 'errors' in list(r.keys()):
                error = r['errors'][0]['message']
                failure_message = 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error)
            if 'trace_id' in list(r['meta'].keys()):
                #if there's an error CS support will ask for any trace IDs returned by the API
                trace_id = r['meta']['trace_id']
                failure_message = 'An error occurred retrieving an access token. Error Code: ' + str(rresponse_code) + ' Error Message: ' + str(error) + 'Provide this Trace ID to CrowdStrike Support: ' + str(trace_id)
            return result, failure_message
        
        except:
            #catch all exception
            result = 'failure'
            failure_message = sys.exc_info()[0]
            return result, failure_message 

        if response_code.startswith('20'):
            if 'access_token' in list(r.keys()):
                result = r['access_token']
                message = 'success'
                return result, message

        else:
            if 'trace_id' in list(r['meta'].keys()):
                #if there's an error CS support will ask for any trace IDs returned by the API
                trace_id = r['meta']['trace_id']
                failure_message = 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error) + 'Provide this Trace ID to CrowdStrike Support: ' + str(trace_id)

            elif 'errors' in list(r.keys()):
                #if there's an error CS support will ask for any trace IDs returned by the API
                error = r['errors'][0]['message']
                result = 'failure'
                failure_message = 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error) + ' Keys: ' 
                if 'trace_id' in list(r['meta'].keys()):
                    trace_id = r['meta']['trace_id']
                    failure_message = 'An error occurred retrieving an access token. Error Code: ' + str(response_code) + ' Error Message: ' + str(error) + ' Provide this Trace ID to CrowdStrike Support: ' + str(trace_id)


            else:
                failure_message = 'Unknown error retrieving token'
                result = 'failure'

        return result, failure_message


    def get_intel(self, token, url_filters):

        if '/intel/queries' in url_filters:
            #determines if a 'next-page' URL is being passed
            print('next page URL detected')
            indicators_url = url_filters
        else:
            #defaults to a basic URL call
            self.intel_indict = "/intel/queries/indicators/v1"
            print('regular indicators query')
            indicators_url = self.base_url + self.intel_indict + url_filters

        payload={}                  #empty payload for request call
        cont_collecting = True      #tracks if continued collecting is needed
        more_indicators = True      #tracks if there are more indicators to collect
        cs_indicators = []          #stores indicators
        max_cycles = 3              #accounts for Zscaler's 25k max URL upload limit
        next_page = ''              #stores next_page value from the header

        while cont_collecting == True:
            #continued indicator collection is indicated
            headers = {'Authorization': 'Bearer ' + token}#, 'User-agent': self.user_agent}
            while max_cycles > 0:
                try: 
                    response = requests.request("GET", indicators_url, headers=headers, data=payload)
                    intel_results = str(response.status_code)
                    CIB_Logger().logging_data('info', 'Response when contacting the CrowdStrike Intel Indicators API: ' + intel_results)

                except (requests.exceptions.Timeout, requests.exceptions.TooManyRedirects, requests.exceptions.HTTPError, requests.exceptions.RequestException) as e:
                    CIB_Logger().logging_data('error', 'An occured contacting the CrowdStrike Intel Indicators API: ' + str(e))
                    if 'trace_id' in list(response['meta'].keys()):
                        #if there's an error CS support will ask for any trace IDs returned by the API
                        trace_id = response['meta']['trace_id']
                        CIB_Logger().logging_data('error', 'Provide this Trace ID to CrowdStrike Support: ' + str(trace_id))
                    CIB_Logger().logging_data('error', 'System will now exit')
                    sys.exit()

                if intel_results.startswith('20'):
                    #logs successful call
                     CIB_Logger().logging_data('info', 'CrowdStrike Intel Indicators API has been successfully queried. \n    Response code: ' + intel_results)
                    
                else:
                    if 'trace_id' in list(response['meta'].keys()):
                        #if there's an error CS support will ask for any trace IDs returned by the API
                        trace_id = response['meta']['trace_id']
                        CIB_Logger().logging_data('error', 'An error occurred attempting to retrieve Intel Indicators . Error Code: ' + str(intel_results) + 'Provide this Trace ID to CrowdStrike Support: ' + str(trace_id))
                    else:
                        CIB_Logger().logging_data('error', 'An error occurred attempting to retrieve Intel Indicators . Error Code: ' + str(intel_results) + 'No Trace ID was identified')

                try:
                    #check to see if there's a processable response
                    indicator_json = response.json()
                    response_headers = response.headers
                    meta = indicator_json['meta']
                    intel = indicator_json['resources']
                
                except ValueError as e:
                    CIB_Logger().logging_data('error', 'An occured contacting or processing the return from the CrowdStrike Intel Indicators API: ' + str(e))
                    CIB_Logger().logging_data('error', 'System will now exit')
                    sys.exit()

                if len(intel) == 0:
                    #identify if there are no indicators collected
                    cont_collecting = False
            
                else:
                    for indicators in intel:
                        #identifies file based URLs 
                        excl_regex = r"^url_file:"
                        form_check = re.search(excl_regex, indicators)

                        if form_check == None:
                            #removes 'http' & 'https' from URLs per Zscaler requirements
                            regex = r"(?<=//).*"
                            matches = re.search(regex, indicators)
                            match = matches.group()
                            cs_indicators.append(match)
                            
                        else:
                            #skips file formated URLs
                            pass

                    if more_indicators == False:
                        #if there are no more indicators there's no reason to continue
                        cont_collecting = False

                    if 'Next-Page' not in response_headers:
                        #determines if this is the last or only page  by looking for a 'next-page' value in the response header
                        more_indicators = False

                    else:
                        more_indicators  = True
                        #handles additional indicators by identifying a 'next-page' value in the response header
                        cont_collecting = True
                        indicators_url = self.base_url + response_headers['Next-page']

                #reduces cycle counter
                max_cycles = max_cycles - 1

                if max_cycles == 0:
                    #prevents over 24k indicators from being retrieve to align with Zscaler custom URL posting requirements
                    next_page = indicators_url
                    cont_collecting = False
                else:
                    next_page = 'None'      
                    
        return cs_indicators, next_page
