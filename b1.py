from bs4 import BeautifulSoup as bs
import requests
import re
import pandas as pd
from urllib.parse import urlparse
from zapv2 import ZAPv2
import time
import ssl
import socket
from datetime import datetime
import whois

# ZAP vulnerability scanning setup
zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

# URL for both vulnerability and malware scanning
target_url = 'https://www.example.com'

# Backlink detection functions
def detect_backlink(url, name):
    # Fetch HTML content from the provided URL
    response = requests.get(url)
    html_content = bs(response.content, 'html.parser')
    # Find all HTTP links that do not contain the specified domain name (indicating external links)
    http_links = html_content.find_all('a', href=re.compile(r'^http'))
    back_links = [link for link in http_links if link['href'].find(name) == -1]
    return back_links

def get_domain(url):
    # Extract domain from a URL
    parsed_url = urlparse(url)
    return parsed_url.netloc

def parse_backlinks(backlinks):
    # Parse backlinks to gather detailed information
    back_links = {'title': [], 'link': [], 'domain': [], 'link_type': [], 'is_secure': []}

    for link in backlinks:
        url = link['href']
        title = link.text
        domain = get_domain(url)
        link_type = 'no-follow' if link.get('rel') == ['nofollow'] else 'follow'
        is_secure = url.startswith("https")

        back_links['title'].append(title.strip() if title else "No Title")
        back_links['link'].append(url.strip())
        back_links['domain'].append(domain)
        back_links['link_type'].append(link_type)
        back_links['is_secure'].append(is_secure)

    return back_links

# Function to calculate Trust Score
def calculate_trust_score(domain, vulnerabilities, malicious_count, secure_backlinks):
    ssl_result = check_ssl_certificate(domain)
    domain_info = get_domain_info(domain)

    score = 0

    # Trust score for SSL Certificate
    if "Valid SSL Certificate" in ssl_result:
        score += 10
        ssl_status = "Valid SSL Certificate"
    else:
        ssl_status = "Invalid or Expired SSL Certificate"

    # Trust score for Domain Age
    if isinstance(domain_info, dict):  # Check if domain info was fetched correctly
        domain_age = domain_info.get('domain_age', 0)
        if domain_age > 20:
            score += 10  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years (Older than 20 years)"
        if 20 > domain_age > 10:
            score += 5  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years (Between 10 and 20 years)"
        if 10 > domain_age > 5:
            score += 3  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years (Between 5 and 10 years)"
        else:
            score += 0  # Add fewer points for newer domains
            domain_status = f"Domain Age: {domain_age} years (Less than or equal to 5 years)"
    else:
        domain_status = domain_info  # WHOIS lookup failed

    # Trust score adjustment based on vulnerabilities and malicious content
    if high_count == 0:
        score += 15

    if medium_count == 0:
        score += 10

    if low_count == 0:
        score += 5

    if malicious_count == 0:
        score += 20
    if 5 > malicious_count > 0:
        score += 15
    if 10 > malicious_count > 5:
        score += 10
    if 15 > malicious_count > 10:
        score += 5
    else:
        score += 0

    # Add +30 if secure backlinks are found
    if secure_backlinks > 0  :
        score += 30

    # Combine results
    return {
        'Trust Score': f"{max(0, score)}/100",  # Ensure the score doesn't go below 0
        'SSL Info': ssl_status,
        'Domain Info': domain_status,
        'Vulnerabilities Found': len(vulnerabilities),
        'Malicious Content Sources': malicious_count
    }

# Function to check SSL Certificate
def check_ssl_certificate(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(5.0)

    try:
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

        if expiry_date > datetime.now():
            return f"Valid SSL Certificate. Expires on {expiry_date}"
        else:
            return "SSL Certificate expired"
    except Exception as e:
        return f"SSL validation failed: {str(e)}"

# Function to get domain information and age
def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # Handle case where creation_date could be a list (WHOIS sometimes returns a list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate the domain age in years
        domain_age_years = (datetime.now() - creation_date).days // 365 if creation_date else 0
        return {
            'domain_name': domain_info.domain_name,
            'registrar': domain_info.registrar,
            'creation_date': creation_date,
            'expiration_date': domain_info.expiration_date,
            'domain_age': domain_age_years,
            'name_servers': domain_info.name_servers
        }
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

# ZAP vulnerability scanning setup
zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

# Spider and Active Scan for ZAP
print(f'Spidering target: {target_url}')
zap.spider.scan(target_url)

while int(zap.spider.status()) < 100:
    print(f'Spider progress: {zap.spider.status()}%')
    time.sleep(5)

print('Spider completed')
zap.ascan.scan(target_url)

while int(zap.ascan.status()) < 100:
    print(f'Active Scan progress: {zap.ascan.status()}%')
    time.sleep(5)

print('Active Scan completed')

# Retrieve alerts from ZAP and sort vulnerabilities
alerts = zap.core.alerts(baseurl=target_url)
vulnerabilities = []

high_count = 0
medium_count = 0
low_count = 0
informational_count = 0

if alerts:
    for alert in alerts:
        vulnerability = {
            "risk_level": alert['risk'],
            "url": alert['url'],
            "description": alert['description'].replace('\u2014', '-')  
        }
        vulnerabilities.append(vulnerability)

        if alert['risk'] == 'High':
            high_count += 1
        elif alert['risk'] == 'Medium':
            medium_count += 1
        elif alert['risk'] == 'Low':
            low_count += 1
        elif alert['risk'] == 'Informational':
            informational_count += 1

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

api_key = "ce5974c8fcaf624d89e8306254c887071e9b6b32f25cd950d647383d7f8245ed"

def check_url_malware(url):
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.utils.quote(url, safe="")

    headers = {
        "x-apikey": api_key
    }

    # Initiate malware scan on VirusTotal
    response = requests.post(url_scan_endpoint, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        print(f"Scan initiated for {url}. Scan ID: {scan_id}")
        
        report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        
        # Check scan report status and result
        for attempt in range(10):
            report_response = requests.get(report_endpoint, headers=headers)
            
            if report_response.status_code == 200:
                report_data = report_response.json()
                
                if report_data["data"]["attributes"]["status"] == "completed":
                    positives = report_data["data"]["attributes"]["stats"]["malicious"]
                    print(f"Malicious content detected in {positives} sources.")
                    return positives  # Return the number of malicious sources
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
        return 0

# Check the target URL for malware
malicious_count = check_url_malware(target_url)

# Backlink analysis
backlinks = detect_backlink(target_url, "example.com")
backlink_details = parse_backlinks(backlinks)
secure_backlinks = len([b for b in backlink_details['is_secure'] if b])

# Final trust score
trust_score_data = calculate_trust_score(get_domain(target_url), vulnerabilities, malicious_count, secure_backlinks)
print(f"\nTrust Score: {trust_score_data['Trust Score']}")
print(f"SSL Certificate Info: {trust_score_data['SSL Info']}")
print(f"Domain Info: {trust_score_data['Domain Info']}")
print(f"Vulnerabilities Found: {trust_score_data['Vulnerabilities Found']}")
print(f"Malicious Content Sources: {trust_score_data['Malicious Content Sources']}")
