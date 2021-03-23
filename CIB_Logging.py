import logging
import json
import os
import time
import datetime
import os.path
from os import path
from json.decoder import JSONDecodeError
from os import walk


import ZScaler_Intel_Bridge_config as config
    
    
class CIB_Logger():

    logger = logging.getLogger()
    logging_level = config.logging_level
    logger.setLevel(logging_level)
    logging.basicConfig(filename='./CS_Intel_Bridge.log' , format='%(asctime)s   %(process)d %(levelname)s   %(message)s')

    ref_file = './CS_Intel_Bridge_Tracker.json'


    def logging_data(self, log_level, log_message):
        spacing = '\n    '
        if log_level ==  'info':
            logging.info( spacing + str(log_message))
        elif log_level == 'debug':
            logging.debug( spacing + str(log_message))
        elif log_level == 'error':
            logging.error( spacing + str(log_message))
        elif log_level == 'error':
            logging.error( spacing + str(log_message))


    def tracker_last(self):
        current_time = str(datetime.datetime.now())

        dates = []
        tracking_list = []
        complete_found = False
        
        if path.isfile(self.ref_file):
            open_type = 'r+'
            with open(self.ref_file, open_type) as f:
                try:
                    f.seek(0)
                    tracking = json.load(f)
                    for t in tracking:
                        if "Post Type" in tracking[t]:
                            if tracking[t]['Post Type'] == "complete":
                                tracking_list.append(t)
                                complete_found = True
                        else:
                            pass
                    if complete_found == True:
                        tracking_list.sort()
                        last_time = tracking_list[-1]
                        pattern = '%Y-%m-%d %H:%M:%S.%f'
                        epoch = int(time.mktime(time.strptime(last_time, pattern)))
                        last_run = str(epoch)
                    else:
                        last_run='none found' 


                except Exception as e:
                    print('Error accessing JSON file:  %s on json.load()' % e)
                    '''with open(self.ref_file, open_type) as f:
                        tracking_orig = {}
                        json.dump(tracking_orig, f, sort_keys=True, indent=4)'''
                    last_run='none found'

        else:
            open_type = 'w'
            try:
                with open(self.ref_file, open_type) as f:
                    print('creating entry')
                    tracking_orig = {}
                    json.dump(tracking_orig, f, sort_keys=True, indent=4)
                    print ('done')
                    last_run='none found'
            except Exception as e:
                print("got 2 %s on json.load()" % e)

        f.close() 
        print('Last run value: ' + str(last_run))
        return last_run

    
    def tracker_record(self, end_time, zs_quota, cs_total, urls_removed, zs_update, zs_current, post_type):

        tracking_data= {end_time:{"Zscaler Quota":zs_quota, "Current Category Size": zs_current, "Total CrowdStrike Indicators Retrieved":cs_total, "Number of URLs Removed":urls_removed,  "URLs added to Zscaler":zs_update, "Post Type": post_type}}
        

        #tracking_data = {'2021-03-01 19:48:33.488516': {'Zscaler Quota': 16895, 'Current Category Size': 7536, 'Total CrowdStrike Indicators Retrieved': 748, 'Number of URLs Removed': 0, 'URLs added to Zscaler': 502}}

        with open(self.ref_file, 'r+') as f:
            try: 
                tracking_orig = json.load(f)
                print(tracking_orig)
                print(len(tracking_orig))
                tracking_orig.update(tracking_data)
                for i in sorted (tracking_orig.keys()) :
                    print(i)

                f.seek(0)
                json.dump(tracking_orig, f, sort_keys=True, indent=4)
                
            
            except Exception as e:
                print("got 3 %s on json.load()" % e)
        
        f.close() 

    def backlog(self):#, time):
        backlog_dir = './backlog'
        f=[]
        for (dirpath, dirnames, filenames) in walk(backlog_dir):
            f.extend(filenames)
        print(f)

#CIB_Logger().tracker_last()
#CIB_Logger().tracker_record()
#CIB_Logger().backlog()