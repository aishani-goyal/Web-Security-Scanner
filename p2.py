import requests
import time

api_key = "ce5974c8fcaf624d89e8306254c887071e9b6b32f25cd950d647383d7f8245ed"

def check_url_malware(url):
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.utils.quote(url, safe="")

    headers = {
        "x-apikey": api_key
    }

    response = requests.post(url_scan_endpoint, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        print(f"Scan initiated for {url}. Scan ID: {scan_id}")
        
        report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        
        for attempt in range(10):
            report_response = requests.get(report_endpoint, headers=headers)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                if report_data["data"]["attributes"]["status"] == "completed":
                    positives = report_data["data"]["attributes"]["stats"]["malicious"]
                    print(f"Malicious content detected in {positives} sources.")
                    if positives > 0:
                        print("Warning: The URL is flagged as malicious!")
                    else:
                        print("No malware detected. The URL is safe.")
                    break
                else:
                    print("Scan still in progress... retrying in 10 seconds.")
            else:
                print(f"Failed to retrieve scan report. Status code: {report_response.status_code}")
                break

            time.sleep(10)
        else:
            print("The scan did not complete within the retry limit. Try again later.")
    else:
        print(f"Failed to initiate scan. Status code: {response.status_code}")

check_url_malware("http://www.tekdefense.com/downloads/malware-samples/")
