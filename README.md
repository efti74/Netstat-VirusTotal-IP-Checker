# Netstat VirusTotal IP Checker

## Description

This Python script actively monitors your system's network connections using the `psutil` library. For every established connection, it extracts the remote IP address and uses the VirusTotal API to check for potential threats. The script will print a "Malicious IP found" warning if the IP address has been flagged by one or more security vendors on VirusTotal.

## Features

-   Lists all established network connections.
-   Extracts the remote IP address from each connection.
-   Queries the VirusTotal API to check the reputation of the IP address.
-   Reports if an IP is considered malicious based on VirusTotal's analysis.
-   Includes a 15-second delay between API requests to adhere to the public API rate limits.

## Prerequisites

-   Python 3.6 or newer
-   A free VirusTotal API key

## Setup and Installation

Follow these steps to set up and run the script on your local machine.

### 1. Get a VirusTotal API Key

1.  Go to [VirusTotal.com](https://www.virustotal.com/) and create a free account.
2.  Once logged in, navigate to your profile settings by clicking your user icon in the top right corner.
3.  Select **"API Key"** from the dropdown menu.
4.  Copy your personal API key.

### 2. Configure the Script

1.  Open the `4_netstat_virustotal.py` file in a text editor.
2.  Find the following line:
    ```python
    VIRSUTOTAL_API_KEY = "Own_API_Key_Here"
    ```
3.  Replace the placeholder key with the API key you copied from your VirusTotal account.

### 3. Install Required Libraries

Before running the script, you need to install the necessary Python libraries. Open your terminal or command prompt and run the following command:

```bash
pip install psutil requests
```

## How to Run

Once you have completed the setup, you can run the script from your terminal or command prompt:

```bash
python 4_netstat_virustotal.py
```

The script will start scanning your connections and printing the status of each IP address it checks.

### Example Output

```
Scanning active connections...
✅ IP 192.0.2.1 is clean.
⚠️ Malicious IP found: 203.0.113.10 | Count: 5
✅ IP 198.51.100.5 is clean.
...
```
