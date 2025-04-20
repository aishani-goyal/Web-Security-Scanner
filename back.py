from flask import Flask, request, jsonify
from zapv2 import ZAPv2
import time

app = Flask(__name__)

# Configuration for OWASP ZAP
ZAP_PORT = 8080
ZAP_API_KEY = '74ghf5qvfcj2ne3nr0bl8buqtg'  # Use an API key if needed, or remove for no auth
ZAP_URL = f'http://localhost:{ZAP_PORT}'

# Create ZAP instance
zap = ZAPv2(apikey=ZAP_API_KEY)  # Remove baseurl from here
zap.baseurl = ZAP_URL  # Set baseurl after instantiation

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    target_url = data['url']
    print(f"Received scan request for URL: {target_url}")  # Debugging output

    # Start the scan
    print(f"Starting scan for: {target_url}")
    scan_id = zap.ascan.scan(target_url)
    print(f"Scan ID: {scan_id}")

    # Wait for the scan to complete
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(5)  # Wait for 5 seconds before checking again

    print("Scan completed.")

    # Fetch the alerts
    alerts = zap.core.get_alerts(baseurl=target_url)
    print(f"Number of alerts: {len(alerts)}")

    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True)
