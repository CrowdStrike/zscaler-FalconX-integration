# -zscaler-FalconX-integration-revision
## Getting Started
With Python 3.7+ installed:

```bash
git clone [REPO]
cd [PROJECT]
python main.py
```

# Project
## /app/integration.py
called by main module - provides flow control.

## /app/crowdstrike/*
### crowdstrike_auth.py
Handles Falcon API OAuth2 Authenticaation
### api/intel_pull.py
Controller for handling HTTP connection with the Intel API
### queuing/*
contains intermediary URL lists - during runtime, files are populated with sets of malicious URLs pending transfer.


## /app/zscaler/*
### zscaler_auth.py
Handles zscaler authentication
### api/category.py
Controller for Zscaler's custom category API
### api/intel_push.py
Controller for pushing new Indicators to Zscaler custom category
### api/lookup.py
Controller for Zscaler's URL Look Up API
### queuing/*
contains intermediary URL lists - during runtime, files are populated with sets of malicious URLs pending transfer.

## app/_util/*
### intel_format.py
### logger.py

miscellaneous utilities for formatting and edge case handling



