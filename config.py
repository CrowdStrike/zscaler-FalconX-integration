# CrowdStrike - Zscaler Intel Bridge Configuration File
# Enter values prior to first launch
# Confirm that your Zscaler URL Categories contains a User-Defined category named 'CrowdStrike Malicious URLs - High'
proxy = None
logging_level = 'DEBUG'

# CrowdStrike configurations
cs_clientID = ""
cs_secret = ""
cs_base_url = "https://api.crowdstrike.com"

# ZScaler configurations
zs_hostname = 'https://admin.zscalertwo.net'
cs_category_name = 'CrowdStrike Malicious URLs - High'
zs_username = ''
zs_password = ''
zs_apiKey = ''
zs_max_calls_hourly = 39000  # Maximum URL Look Up requests per hour; Default = 39000
zs_max_payload_size = 10000  # Maximum URLs to POST to Zscaler per request; Default = 10000

