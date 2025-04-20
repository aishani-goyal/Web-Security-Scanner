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
        if domain_age >= 20:
            score += 10  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years"
        elif 20 > domain_age >= 10:
            score += 5  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years"
        elif 10 > domain_age >= 5:
            score += 3  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years"
        else:
            score += 0  # Add fewer points for newer domains
            domain_status = f"Domain Age: {domain_age} years"
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
    elif 5 >= malicious_count > 0:
        score += 15
    elif 10 >= malicious_count > 5:
        score += 10
    elif 15 >= malicious_count > 10:
        score += 5
    else:
        score += 0

    # Add +30 if secure backlinks are found
    if secure_backlinks > 0:
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

# Function to initiate ZAP scan
def zap_scan(target_url):
    zap.spider.scan(target_url)

    while int(zap.spider.status()) < 100:
        time.sleep(5)

    zap.ascan.scan(target_url)

    while int(zap.ascan.status()) < 100:
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=target_url)
    return alerts

# Function to test a URL
def test_url(url):
    # Start by initiating a ZAP scan
    print(f"Initiating scan for {url}...")
    alerts = zap_scan(url)
    
    # Process the vulnerabilities found
    vulnerabilities = []
    high_count = 0
    medium_count = 0
    low_count = 0
    informational_count = 0

    if alerts:
        for alert in alerts:
            risk_level = alert['risk']
            vulnerability = {
                "risk_level": alert['risk'],
                "url": alert['url'],
                "description": alert['description']   
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

        # Summarize Vulnerabilities
        print(f"\nVulnerability Summary for {url}:")
        print(f"High: {high_count}")
        print(f"Medium: {medium_count}")
        print(f"Low: {low_count}")
        print(f"Informational: {informational_count}")
        
        for vuln in vulnerabilities:
            print(f"Risk Level: {vuln['risk_level']}")
            print(f"URL: {vuln['url']}")
            print(f"Description: {vuln['description']}")
            print('-' * 80)
    else:
        print(f'No vulnerabilities found on {url}')

    # Malware check
    malicious_count = check_url_malware(url)

    # Backlink analysis
    backlinks = detect_backlink(url, get_domain(url))
    backlink_details = parse_backlinks(backlinks)
    secure_backlinks = len([b for b in backlink_details['is_secure'] if b])

    # Calculate the trust score
    trust_score_data = calculate_trust_score(get_domain(url), vulnerabilities, malicious_count, secure_backlinks)
    
    # Output the results
    print(f"\nTrust Score: {trust_score_data['Trust Score']}")
    print(f"SSL Certificate Info: {trust_score_data['SSL Info']}")
    print(f"Domain Info: {trust_score_data['Domain Info']}")
    print(f"Vulnerabilities Found: {trust_score_data['Vulnerabilities Found']}")
    print(f"Malicious Content Sources: {trust_score_data['Malicious Content Sources']}")

# Example usage
test_url('https://www.example.com')
