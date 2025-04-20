'''cd "C:\Program Files\ZAP\Zed Attack Proxy"
 .\zap.bat -daemon -port 8090

and stop the daemon mode: with ctrl+c

for shutdown
 .\zap.bat -shutdown
'''


from zapv2 import ZAPv2
import time
import json  

zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

target_url = 'https://www.example.com'
print(f'Spidering target: {target_url}')
zap.spider.scan(target_url)

while int(zap.spider.status()) < 100:
    print(f'Spider progress: {zap.spider.status()}%')
    time.sleep(5)

print('Spider completed')
print(f'Starting Active Scan on target: {target_url}')
zap.ascan.scan(target_url)

while int(zap.ascan.status()) < 100:
    print(f'Active Scan progress: {zap.ascan.status()}%')
    time.sleep(5)

print('Active Scan completed')

alerts = zap.core.alerts(baseurl=target_url)

vulnerabilities = []
def format_description(alert):
    vulnerability_type = alert['name']  # Assuming 'name' holds the type of vulnerability
    detailed_description = alert['description'].replace('\u2014', '-')
    
    formatted_desc = (
        f"Type of Vulnerability: {vulnerability_type}\n"
        f"Description: {detailed_description}\n"
    )
    return formatted_desc

if alerts:
    for alert in alerts:
        vulnerability = {
            "risk_level": alert['risk'],
            "url": alert['url'],
            "description": format_description(alert)  
        }
        vulnerabilities.append(vulnerability)

    risk_order = {'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
    vulnerabilities.sort(key=lambda x: risk_order.get(x['risk_level'], 5))  
    print(f'\nTotal Vulnerabilities Found: {len(vulnerabilities)}\n')
    for vuln in vulnerabilities:
        print(f"Risk Level: {vuln['risk_level']}")
        print(f"URL: {vuln['url']}")
        print(f"Description: {vuln['description']}")
        print('-' * 80)  
else:
    print(f'No vulnerabilities found on {target_url}')




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
