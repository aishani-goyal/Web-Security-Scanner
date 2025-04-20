from flask import Flask, jsonify, request
from zapv2 import ZAPv2
import requests
from bs4 import BeautifulSoup as bs
import re
import time
from datetime import datetime
import ssl
from ssl import create_default_context

import socket
socket.getaddrinfo('127.0.0.1', 5000)
import whois
from flask_cors import CORS
from urllib.parse import urlparse
import pandas as pd

app = Flask(__name__)
CORS(app)

# ZAP vulnerability scanning setup
zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

# URL for both vulnerability and malware scanning (will be provided by user)
#target_url = "https://www.example.com"

@app.route('/scan', methods=['POST'])
def scan_url():
    target_url = request.get_json().get('url', '')
    
    try:
        response_data = vul(target_url)
        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def vul(target_url):
    tooMany_vuls = []
    zap = ZAPv2(apikey='74ghf5qvfcj2ne3nr0bl8buqtg', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

    # Spider and Active Scan for ZAP
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
    
    high_count = 0
    medium_count = 0
    low_count = 0
    informational_count = 0
    vulnerability_score = 0
    vulnerabilities = []

    def format_description(alert):
        detailed_description = alert['description'].replace('\u2014', '-')
        return (
            f"Type of Vulnerability: {alert['name']}\n"
            f"Description: {detailed_description}\n"
        )

    if alerts:
        for alert in alerts:
            vulnerability = {
                "risk_level": alert['risk'],
                "url": alert['url'],
                "name": alert['name'],
                "alert_url": alert['url'],
                "description": format_description(alert)  
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

        # Scoring logic for High risks
        if high_count == 0:
            vulnerability_score += 40
        elif 1 <= high_count <= 5:
            vulnerability_score += 20
        elif 6 <= high_count <= 10:
            vulnerability_score += 10
        else:
            vulnerability_score += 0

        # Scoring logic for Medium risks
        if medium_count == 0:
            vulnerability_score += 30
        elif 1 <= medium_count <= 10:
            vulnerability_score += 20
        elif 11 <= medium_count <= 20:
            vulnerability_score += 10
        else:
            vulnerability_score += 0

        # Scoring logic for Low risks
        if low_count == 0:
            vulnerability_score += 30
        elif 1 <= low_count <= 15:
            vulnerability_score += 20
        elif 16 <= low_count <= 30:
            vulnerability_score += 10
        else:
            vulnerability_score += 0

        # Sorting vulnerabilities based on risk level
        risk_order = {'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
        vulnerabilities.sort(key=lambda x: risk_order.get(x['risk_level'], 5))
        tooMany_vuls.extend(vulnerabilities) 

    else:
        print(f'No vulnerabilities found on {target_url}')

    # Structuring the response data
    vulData = {
        "Total_Vuls": len(vulnerabilities),
        "RiskLevels": [high_count, medium_count, low_count, informational_count],
        "vulScore": vulnerability_score,
        "list_of_vuls": tooMany_vuls,
    }
    return vulData



# ---------------------------------------------------------------------------

@app.route('/mals', methods=['POST'])
def mals():
    try:
        target_url = request.get_json().get('url', '')
        api_key = "ce5974c8fcaf624d89e8306254c887071e9b6b32f25cd950d647383d7f8245ed"
        positives = check_url_malware(target_url, api_key)  # Get the malware positives count
        response = {"Malware": positives}  # Return the positives count as a JSON response
        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def check_url_malware(url, key):
    positives = 0
    url_scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    encoded_url = requests.utils.quote(url, safe="")

    headers = {
        "x-apikey": key
    }

    # Initiate URL scan
    response = requests.post(url_scan_endpoint, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        scan_id = response.json().get("data", {}).get("id", "")
        if scan_id:
            print(f"Scan initiated for {url}. Scan ID: {scan_id}")
            
            report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            
            for attempt in range(10):
                # Fetch scan report
                report_response = requests.get(report_endpoint, headers=headers)
                
                if report_response.status_code == 200:
                    report_data = report_response.json()
                    
                    # Check scan completion status
                    if report_data["data"]["attributes"]["status"] == "completed":
                        positives = report_data["data"]["attributes"]["stats"]["malicious"]
                        print(f"Malicious content detected in {positives} sources.")
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
            print("Failed to initiate scan. No scan ID returned.")
    else:
        print(f"Failed to initiate scan. Status code: {response.status_code}")
    
    return positives  # Return the count of malicious sources detected





# ---------------------------------------------------------------------------

# SSL CERTIFICATE

@app.route('/ssl' , methods=['POST'])
def ssl():
    url = request.json['url']
    protocol, domain = url.split("://")
    if domain[-1]=='/':
        new,extra=domain.split('/')
    else:
        new=domain
    s= check_ssl_certificate(new)
    
    return {"SSL Verification": s}
    
import socket
import requests
from ssl import create_default_context
from datetime import datetime

def check_ssl_certificate(domain):
    try:
        # Retrieve IP address
        ip_address = socket.gethostbyname(domain)
        
        # Initialize SSL context and connection
        context = create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)
        
        # Connect to the server and get the certificate
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()  # Close connection immediately after fetching cert
        
        # Extract certificate details
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        issue_date = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        issuer = cert['issuer'][0][0][1]
        common_name = cert['subject'][0][0][1]
        domain_match = (domain == common_name)
        is_self_signed = (issuer == common_name)
        
        # Prepare the SSL certificate info
        expiry_date_str = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
        issue_date_str = issue_date.strftime("%Y-%m-%d %H:%M:%S")
        exp = 1 if expiry_date > datetime.now() else 0
        
        # Fetch hosting location (country)
        hosting_location = get_hosting_location(domain)

        # Return the combined result
        return {        
            "ip": ip_address,
            "connection Type": "Secure (HTTPS)" if cert else "Not Secure",
            "IsExpired": exp,
            "Issuer": issuer,
            "domain": domain_match,
            "Revoked": is_self_signed,
            "IssueDate": issue_date_str,
            "expiryDate": expiry_date_str,
            "Hosting Location": hosting_location
        }

    except Exception as e:
        print(f"An error occurred: {str(e)}")  # Catch-all for other errors
        return {"error": f"An error occurred: {str(e)}"}

def get_hosting_location(domain):
    try:
        # Retrieve the IP address of the domain
        ip_address = socket.gethostbyname(domain)
        
        # Use ipinfo.io API to get geolocation data for the IP address
        response = requests.get(f"http://ipinfo.io/{ip_address}/json")
        data = response.json()
        
        # Extract the country from the response
        country = data.get('country', 'Unknown')
        return country
    except Exception as e:
        return f"Error fetching hosting location: {str(e)}"

    

# ---------------------------------------------------------------------------
# 


@app.route('/backlinks', methods=['POST'])
def Backlinks():
    try:
        # Extracting URL from the incoming request
        url = request.json['url']
        backlinks = detect_backlink(url, 'wikipedia')
        data = parse_backlinks(backlinks)
        df = pd.DataFrame(data)
        summary = summarize_data(df)
        
        # Debugging: Print the summary to inspect its contents
        print("Summary Data being returned:", summary)
        
        return jsonify(summary)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

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

def summarize_data(df):
    # Generate summary statistics
    total_backlinks = len(df)
    follow_links = df['link_type'].value_counts().get('follow', 0)
    no_follow_links = df['link_type'].value_counts().get('no-follow', 0)
    secure_links = df['is_secure'].sum()  # Count of secure links
    not_secure_links = total_backlinks - secure_links  # Count of non-secure links

    s = {
        "Total Backlinks": str(total_backlinks),
        "Follow Links": str(follow_links),
        "No-Follow Links": str(no_follow_links),
        "Secure Links": str(secure_links),
        "Not Secure Links": str(not_secure_links)    
    }

    # Convert DataFrame rows to a serializable format (list of dicts or strings)
    learnMore = []
    for idx, row in df.iterrows():
        security_icon = "🟢" if row['is_secure'] else "🔴"
        # Convert tuple to a dictionary to ensure it's serializable
        kheer = {"security_icon": security_icon, "link": row['link']}
        learnMore.append(kheer)

    # Debugging: Print to check the structure of the response
    print("Learn More Data being returned:", learnMore)

    # Return the result as a serializable dictionary
    return {"summary": s, "Learn More": learnMore}

# Usage example


# Display the DataFrame with detailed backlink information
# print("Detailed Backlink Data:\n", df[['title', 'link', 'link_type', 'is_secure']])

# Display the summary statistics

# print("\nSummary Statistics:\n", summary)

# Display links with security status (green checkmark for secure, red cross for not secure)
print("\nLinks with Security Status:")




# ---------------------------------------------------------------------------
# 

@app.route('/Tscore', methods=['POST'])
def Tscore():
    url=request.json['url']
    
    s=calculate_trust_score(url)
    return s
# Function to calculate Trust Score
    
def calculate_trust_score(url):
    protocol, domain = url.split("://")
    if domain[-1]=='/':
        new,extra=domain.split('/')
    else:
        new=domain
    ssl_result = check_ssl_certificate(new)
    #domain_info = get_domain_info(domain)

    score = 0

    # Trust score for SSL Certificate
    if ssl_result["IsExpired"]==0:
        score += 10
        ssl_status = "Valid SSL Certificate"
    else:
        ssl_status = "Invalid or Expired SSL Certificate"

    # Trust score for Domain Age
    if isinstance(domain, dict):  # Check if domain info was fetched correctly
        domain_age = domain.get('domain_age', 0)
        if domain_age >= 20:
            score += 10  # Add points for older domains
            domain_status = f"Domain Age: {domain_age} years"
        if 20 > domain_age >= 10:
             score += 5  # Add points for older domains
             domain_status = f"Domain Age: {domain_age} years"
        if 10 > domain_age >= 5:
             score += 3  # Add points for older domains
             domain_status = f"Domain Age: {domain_age} years"
        else:
             score += 0  # Add fewer points for newer domains
             domain_status = f"Domain Age: {domain_age} years"
    else:
         domain_status = domain  # WHOIS lookup failed
    RiskLevels='RiskLevels'
    data=vul(url)
    h=data["RiskLevels"][0]
    m=data["RiskLevels"][1]
    l=data["RiskLevels"][2]
    
    
    # Trust score adjustment based on vulnerabilities and malicious content
    if h == 0:
        score += 15

    if m == 0:
        score += 10

    if l == 0:
        score += 5

    api_key = "ce5974c8fcaf624d89e8306254c887071e9b6b32f25cd950d647383d7f8245ed"

    mal_count=check_url_malware(url,api_key)
    if mal_count == 0:
        score += 20
    if 5 >= mal_count > 0:
        score += 15
    if 10 >= mal_count > 5:
        score += 10
    if 15 >= mal_count > 10:
        score += 5
    else:
        score += 0

    # Add +30 if secure backlinks are found
    secureBacklink=summarize_data(pd.DataFrame(parse_backlinks(detect_backlink(url,'wikipedia'))))['summary']['Secure Links']
    
    if int(secureBacklink) > 0  :
        score += 30

    # Combine results
    return {
        'Trust Score': score}
    
#---------------------------------------------------------------------------------- 
@app.route('/whois', methods=['POST'])
def whois_info():
    url = request.json.get('url', '')
    domain_info = get_domain_info(url)
    return {"Domain Information": domain_info}
    

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # Handle case where creation_date could be a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate the domain age in years
        domain_age_years = (datetime.now() - creation_date).days // 365 if creation_date else 0

        return {
            'Domain Name': domain_info.domain_name,
            'Registrar': domain_info.registrar,
            'Creation Date': creation_date.strftime("%Y-%m-%d") if creation_date else None,
            'Expiration Date': domain_info.expiration_date.strftime("%Y-%m-%d") if domain_info.expiration_date else None,
            'Domain_Age': domain_age_years,
            'Name Servers': domain_info.name_servers
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}
#---------------------------------------------------------------------------
   
@app.route('/runAllScans', methods=['POST'])
def run_all_scans():
    try:
        # Get the URL from the request
        data = request.get_json()
        url = data.get('url')
        results = {}
        domain=whois_info()
        results['DomainInformation'] = domain
        vulner=vul(url)
        results['vulners']=vulner
        ss=ssl()
        results['SSLinfo'] = ss
        #mal=mals()
        #results["malware"]=mal
        #backlink=Backlinks()
        #results['backlinks']=backlink
        Trust=Tscore()
        results['Trust']=Trust

        return jsonify(results)

    except Exception as e:
        return jsonify({"error": str(e)}), 500





   
def f():
    return 2
    
if __name__ == "__main__":
    app.run(debug=True) 