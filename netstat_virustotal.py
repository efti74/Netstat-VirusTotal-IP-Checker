import psutil
import requests
import time

# Define your VirusTotal API Key here.
# IMPORTANT: The key below is an example and will not work.
# You must get your own free API key from VirusTotal.com
VIRSUTOTAL_API_KEY = "OWN_API_KEY_FROM_VIRUSTOTAL"

# 1. Define the checker function
def check_ip(ip):
    headers = { "x-apikey": VIRSUTOTAL_API_KEY }
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to VirusTotal: {e}")
        return None

print("Scanning active connections...")

# 2. Get network connections
connections = psutil.net_connections()

for net in connections:
    if net.status == "ESTABLISHED":
        ip = None # initialize ip to None
        try:
            # Get the remote IP address
            if net.raddr:
                ip = net.raddr.ip
            
                # Call the function to check VirusTotal
                result = check_ip(ip)
                
                if result:
                    if 'data' in result:
                        if 'attributes' in result['data'] and 'last_analysis_stats' in result['data']['attributes']:
                            # Get the malicious count from the result
                            malicious_count = result['data']['attributes']['last_analysis_stats']['malicious']

                            # Your decision logic
                            if malicious_count > 0:
                                print(f"⚠️ Malicious IP found: {ip} | Count: {malicious_count}")
                            else:
                                print(f"✅ IP {ip} is clean.")
                        else:
                            print(f"Could not scan {ip}: Missing attributes or stats in response.")
                    elif 'error' in result:
                        print(f"Could not scan {ip}: API error: {result['error'].get('message', 'Unknown error')}")
                    else:
                        print(f"Could not scan {ip}: Unexpected API response.")
        
        except AttributeError:
            # This might happen if raddr is empty
            print("Skipping connection: No remote IP found")
        except KeyError as e:
            # This will catch errors if the response structure is not what's expected
            if ip:
                print(f"Could not parse VirusTotal response for {ip}: Missing key {e}")
            else:
                print(f"Could not parse VirusTotal response: Missing key {e}")
        except Exception as e:
            # It's good to catch other API errors too
            if ip:
                print(f"An error occurred while scanning {ip}: {e}")
            else:
                print(f"An unexpected error occurred: {e}")
        
        time.sleep(15)  # To respect API rate limits
