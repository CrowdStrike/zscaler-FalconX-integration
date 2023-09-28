# ZIA/Falcon Integration: The Intel Bridge

This tool seemlessly integrates CrowdStrike's Falcon's Threat Intelligence with zscaler's Zero Trust Exchange to provide an extra layer of security and visibility for web access. CrowdStrike's Falcon Intel module includes access to  cutting edge database of Indicators of Compromise curated by intelligence experts. 

During runtime, the integration maintains a custom URL category in zscaler ZIA. Left to run indefinitely and unsupervised, it will automatically populate its URL Category with the newest Falcon Intel Indicators. This occurs in a 12 hour loop, and can be left running on a server for eternity or scheduled as a chron job.

# Getting Started
First, remove any CrowdStrike related URL Categories from your ZIA tenant from previous iterations of the integration. You only need to do this once, the script handles its creation and maintenence.
## Requirements
- zscaler ZIA
- CrowdStrike Falcon Intel
- Python 3+ (Python 2 will not work due to string parsing incompatibilities)

[zscaler URL Category documentation](https://help.zscaler.com/zia/adding-custom-url-categories)

## CrowdStrike OAuth2 Token Scope
In the Falcon UI, navigate to API Clients and Keys. Then, click Add a New API Client. Create a client with READ permissions for Indicators (Falcon Intel). Save the resulting values, as you will need them to run the integration.

## Download Repository
```bash
git clone https://github.com/CrowdStrike/zscaler-FalconX-integration.git
cd zscaler-FalconX-integration
```

## Install Dependencies with pip3
```bash
pip3 install -r requirements.txt
```

## Configure
Input your configurations in config.ini. Do not use quotes or ticks for any of these values.

Most of the fields are self-explanatory, but be sure to put some thought into the LIMIT field. This field determines how many malicious URLs the Intel Bridge will maintain in your ZIA tenant. Zscaler offers different subscription tiers with varying maximum custom URLs (from 25K to 275K). Consider this, as well as your existing custom URL categories when you choose a value, as going over the limit will cause runtime errors. So for example, if you have a limit of 25K, and are already using 10K in another URL category, consider a value like 14000. That way, you won't go over the limit, and you leave yourself some wiggle room.


```ini
[CROWDSTRIKE]
client=Your Falcon API Client ID
secret=Your Falcon API Client Secret
base_url=Your Falcon API Base URL (ex: https://api.crowdstrike.com)
limit=Number of indicators to maintain (Max: 275,000 Default 10,000)
[ZSCALER]
hostname=Your zscaler Hostname (Hostname only requires the base URL (i.e. https://zsapi.zscalerthree.net))
username=Your ZIA Username
password=Your ZIA Passsword
token=Your ZIA API token
[CHRON]
disable_loop=Change this value to 1 if you are running the Intel Bridge via Chron job. This will force the program to quit after running. (Default 0, looping enabled)
[LOG]
log_indicators=Change this value to 1 for indicators to be logged in logs/data_log as they are deleted and loaded.
```
# Running the Integration
With Python 3.7+ installed:
```bash
python3 intelbridge
```

# Patch Notes

Added a new logging destination. Now, indicators that were rejected by the regex filter or by Zscaler will be logged in ./logs/rejected_log/. Also, the total rejected indicators count will be logged and displayed after a successfull run along side the number of successfully pushed indicators.

example: 

```
Total run time: 0:00:49;
Indicators pushed: 263;
Indicators rejected: 736;
```

Added error handling for the ZIA API's 412 response code.


# Support & Community Forums

:fire: Is something going wrong? :fire:<br/>
GitHub Issues are used to report bugs. Submit a ticket here:<br/>
[https://github.com/CrowdStrike/zscaler-FalconX-integration/issues/new/choose](https://github.com/CrowdStrike/zscaler-FalconX-integration/issues/new/choose)

**Be sure to include details from the most recent files in the ./log directory**