"""
util.py
Helper methods for intel bridge module
"""
import logging
import time
from requests_toolbelt.utils import dump




def start_log():
    """Utility method for configuring logger
    returns: configured logging object
    """
    date_time = time.strftime("%Y-%m-%d-%H_%M_%S", time.gmtime())
    file = f"logs/{date_time}_intel_bridge_log.log"
    logging.basicConfig(
        level=logging.INFO, format='%(asctime)s %(message)s',
        datefmt='%m/%d/%Y %I:%M:%S %p',
        handlers=[
            logging.FileHandler(file),
            logging.StreamHandler()
        ]
    )
    logging.info(f"Log utility started. Writing to ./{file}")
    return logging

def convert(seconds):
    """Utility method for runtime formatting
    seconds - integer value of seconds
    returns: formatted time string
    """
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%d:%02d:%02d" % (hour, minutes, seconds)

def listSplit(srcList, subLists=1):
    length = len(srcList)
    return [ srcList[i*length // subLists: (i+1)*length // subLists] 
             for i in range(subLists) ]

def buffer(msg, progress, len):
    """Utility method for updating progress bar
    msg - message to print
    progress - current progress 0-4
    len - value being progressed to
    returns: new progress 
    """
    bars = ["\\", "|", "/", "-"]
    if progress >= 4:
        progress = 0
    i = bars[progress]
    dots = "." * progress
    print(f"{i*12} {msg} qty: {len}{dots}{' '*20}", end='\r')
    progress = progress + 1
    return progress

def increment(p, len):
    """Utility method used with buffer() to increment progress by 1
    p - progress object
    len - value being progressed to
    returns: updated progress object
    """
    p[1] = p[1] + 1
    p[0] = buffer(f"{p[3]} {p[1]}/{p[2]}", p[0], len)
    return p

def next_hour():
       return time.strftime("%I:%M:%p",time.localtime(time.time()+43200))

def log_http_error(resp):
    data = dump.dump_all(resp)
    logging.info(("HTTP related failure:\n" + data.decode('utf-8')))

def write_data(entry, deleted):
    """Writes the next_page URL to disk so etl_loop can pick up where it left off
    entry - line to write to file
    deleted - boolean for deleted or new indicators
    returns: N/A
    """    
    new_indicators_data = f"logs/data_log/data_new"
    deleted_indicators_data = f"logs/data_log/data_deleted"
    data_file = new_indicators_data if not deleted else deleted_indicators_data
    data_file = data_file + "_" + time.strftime("%Y-%m-%d-%H_%M_%S", time.gmtime()) +".log"
    f = open(data_file, 'w')
    f.write(f"{entry}")
    f.close()
    return    