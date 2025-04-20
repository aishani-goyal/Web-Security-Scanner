from flask import Flask, jsonify, request
from zapv2 import ZAPv2
import requests
from bs4 import BeautifulSoup as bs
import re
import time
from datetime import datetime
import ssl
import socket
import whois
from urllib.parse import urlparse

app = Flask(__name__)

# ZAP vulnerability scanning setup
zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

# URL for both vulnerability and malware scanning (will be provided by user)
target_url = "https://www.example.com"

@app.route('/vul', methods=['POST'])
def scan_url():
    target_url =  request.get_json()
    try:
        # Call functions to process vulnerabilities and calculate trust score
        alerts = zap_scan(target_url)
        vulnerabilities = process_alerts(alerts)
        malicious_count = check_url_malware(target_url)
        backlinks = detect_backlink(target_url, "example.com")
        backlink_details = parse_backlinks(backlinks)
        secure_backlinks = len([b for b in backlink_details['is_secure'] if b])

        trust_score_data = calculate_trust_score(get_domain(target_url), vulnerabilities, malicious_count, secure_backlinks)


        response_data = {
        "target_url": target_url,
        "vulnerabilities": vulnerabilities,
        "malicious_count": malicious_count,
        "secure_backlinks": secure_backlinks,
        "trust_score": trust_score_data
        }


        # Return JSON response
        return jsonify({response_data}), 200


    except Exception as e:
        return jsonify({"error": str(e)}), 500


def zap_scan(target_url):
    zap.spider.scan(target_url)
    while int(zap.spider.status()) < 100:
        time.sleep(5)
    zap.ascan.scan(target_url)
    while int(zap.ascan.status()) < 100:
        time.sleep(5)
    alerts = zap.core.alerts(baseurl=target_url)
    return alerts


def process_alerts(alerts):
    vulnerabilities = []
    for alert in alerts:
        vulnerability = {
            "risk_level": alert.get('risk', ''),
            "url": alert.get('url', ''),
            "description": alert.get('description', '')
        }
        vulnerabilities.append(vulnerability)
    return vulnerabilities


def check_url_malware(url):
    api_key = "your-api-key-here"  # Replace with actual VirusTotal API key
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    encoded_url = requests.utils.quote(url, safe="")
    response = requests.post(url_scan_endpoint, headers=headers, data={"url": url})
    if response.status_code == 200:
        scan_id = response.json()["data"]["id"]
        report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        report_response = requests.get(report_endpoint, headers=headers)
        if report_response.status_code == 200:
            positives = report_response.json()["data"]["attributes"]["stats"]["malicious"]
            return positives
    return 0


def detect_backlink(url, name):
    response = requests.get(url)
    html_content = bs(response.content, 'html.parser')
    http_links = html_content.find_all('a', href=re.compile(r'^http'))
    back_links = [link for link in http_links if link['href'].find(name) == -1]
    return back_links


def parse_backlinks(backlinks):
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


def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def calculate_trust_score(domain, vulnerabilities, malicious_count, secure_backlinks):
    score = 0
    ssl_status = "Valid SSL Certificate" if check_ssl_certificate(domain) else "Invalid SSL Certificate"
    if malicious_count == 0:
        score += 20
    if secure_backlinks > 0:
        score += 30
    return {'Trust Score': f"{max(0, score)}/100", 'SSL Info': ssl_status}


def check_ssl_certificate(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(5.0)
    try:
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        return expiry_date > datetime.now()
    except Exception:
        return False



if __name__ == "__main__":
    app.run(debug=True)   
#python file ye middleware pe code  run ho jaye 