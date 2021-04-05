from app._util.logger import Logger
import json
import os
class Compare():
    def __init__(self):
        self.crowdstrike_new_intel = self.read_json("crowdstrike/intel.json")
        self.crowdstrike_deleted_intel = self.read_json("crowdstrike/intel_deleted.json")
        self.zscaler_stored_intel = self.read_json("zscaler/intel_zscaler.json")
        self.updated_url_list = []
        self.records_to_delete = []
        self.duplicate_records = []
        self.new_intel_trimmed = []

    def read_json(self, file):
        working_dir = os.path.dirname(os.path.abspath(__file__))
        file_loc = os.path.join(working_dir, file)
        with open(file_loc) as f:
            data = json.load(f)
        return data['urls']

    def new_intel_remove_duplicates(self):
        diff_new_intel_zscaler_list = list(set(self.crowdstrike_new_intel) - set(self.zscaler_stored_intel))
        self.new_intel_trimmed = diff_new_intel_zscaler_list
        return diff_new_intel_zscaler_list

    def append_new_intel(self):
        if(len(self.new_intel_trimmed) == 0):
            self.new_intel_remove_duplicates
        self.updated_url_list = self.zscaler_stored_intel + self.new_intel_trimmed 

    def list_difference(self, a, b):
        diff_a_b = list(set(a) - set(b))
        diff_b_a = list(set(b) - set(a))
        total_diff = diff_a_b + diff_b_a
        return total_diff
    
    def remove_duplicates(self):
        res = []
        [res.append(url) for url in self.updated_url_list if url not in res]
        self.updated_url_list = res
    
    def remove_deleted(self):
        #new_records += (zscaler_stored_intel - crowdstrike_deleted_intel)
        self.updated_url_list = self.list_difference(self.zscaler_stored_intel, self.crowdstrike_deleted_intel) 





    
