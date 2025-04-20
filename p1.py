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

if alerts:
    for alert in alerts:
        vulnerability = {
            "risk_level": alert['risk'],
            "url": alert['url'],
            "description": alert['description'].replace('\u2014', '-')  
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
