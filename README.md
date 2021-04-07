# -zscaler-FalconX-integration-revision

## Overview:
CrowdStrike’s Falcon X threat intelligence and Falcon Endpoint Protection device telemetry data can be easily shared with Zscaler Zero Trust Exchange for seamless usage when integrations are activated to provide stronger protection and increased visibility.

While running, the integration maintains a collection of malicious URLs from CrowdStrike’s Intel platform by submitting new URLs and removing false positives, or deleted indicators, from the Zscaler platform’s URL block list feature. The integration is rate limited by Zscaler’s URL look-up API. Only 40,000 URLs can be queried per hour, so the integration was designed assuming that the service bottle necks at this particular phase of execution. The result is a slow and steady Extract-Transform-Load loop built for stability. 

# Getting Started

With Python 3.7+ installed:
```bash
git clone https://github.com/CrowdStrike/zscaler-FalconX-integration.git
cd zscaler-FalconX-integration
```
Now, open config.py and enter config variables

```bash
python main.py
```

# Project
![Integration architecture](zscalerintegration.jpg)
# /app/integration.py
## integration.py

called by main module - provides flow control.


# /app/crowdstrike/
## crowdstrike_auth.py
Handles Falcon API OAuth2 Authenticaation
## api/intel_pull.py
Controller for handling HTTP connection with the Intel API
## queuing/*
contains intermediary URL lists - during runtime, files are populated with sets of malicious URLs pending transfer.
----

# /app/zscaler/* 
## zscaler_auth.py
Handles zscaler authentication
## api/category.py
Controller for Zscaler's custom category API
## api/intel_push.py
Controller for pushing new Indicators to Zscaler custom category
## api/lookup.py
Controller for Zscaler's URL Look Up API
## queuing/*
contains intermediary URL lists - during runtime, files are populated with sets of malicious URLs pending transfer.
----
# app/_util/*
## intel_format.py
## logger.py

miscellaneous utilities for formatting and edge case handling



