import ssl
import socket
from datetime import datetime
import whois

def check_ssl_certificate(domain):
    try:
        # Retrieve IP address
        ip_address = socket.gethostbyname(domain)
        
        # Initialize SSL context and connection
        context = ssl.create_default_context()
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
        
        # Prepare the summary
        summary = f"SSL Certificate Validation - Summary\n"
        summary += f"* IP Address: {ip_address}\n"
        summary += f"* Connection: {'Secure (HTTPS)' if cert else 'Not Secure'}\n"
        summary += f"* SSL Certificate: {'Valid' if expiry_date > datetime.now() else 'Expired'}\n"
        summary += f"* Issuer: {issuer}\n"
        summary += f"* Domain: {'Matches SSL Certificate' if domain_match else 'Does Not Match SSL Certificate'}\n"
        summary += f"* Revocation: Not Revoked (Revocation check not implemented in this example)\n"
        if is_self_signed:
            summary += f"* Warning: Self-Signed (May not be trusted by all browsers)\n"
        summary += f"* Issue Date: {issue_date.strftime('%B %d, %Y')}\n"
        summary += f"* Expiration Date: {expiry_date.strftime('%B %d, %Y')}\n"
        
        print(summary)  # Print summary directly
        return summary

    except ssl.SSLError as e:
        print(f"SSL error occurred: {str(e)}")  # Print error details
        return f"SSL error occurred: {str(e)}"
    except socket.timeout:
        print("Connection timed out.")  # Timeout feedback
        return "Connection timed out."
    except socket.gaierror as e:
        print(f"Failed to retrieve IP address for {domain}: {e}")
        return f"Failed to retrieve IP address for {domain}: {e}"
    except Exception as e:
        print(f"An error occurred: {str(e)}")  # Catch-all for other errors
        return f"An error occurred: {str(e)}"

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # Handle case where creation_date or expiration_date could be a list (WHOIS sometimes returns a list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # Format the creation and expiration dates for readability
        formatted_creation_date = creation_date.strftime('%B %d, %Y') if creation_date else "N/A"
        formatted_expiration_date = expiration_date.strftime('%B %d, %Y') if expiration_date else "N/A"

        # Calculate the domain age in years
        domain_age_years = (datetime.now() - creation_date).days // 365 if creation_date else 0
        
        domain_info_summary = {
            'domain_name': domain_info.domain_name,
            'registrar': domain_info.registrar,
            'creation_date': formatted_creation_date,
            'expiration_date': formatted_expiration_date,
            'domain_age': domain_age_years,
            'name_servers': domain_info.name_servers
        }
        
        # Prepare the readable output
        readable_summary = f"Domain Information - Summary\n"
        readable_summary += f"* Domain Name: {domain_info.domain_name}\n"
        readable_summary += f"* Registrar: {domain_info.registrar}\n"
        readable_summary += f"* Creation Date: {formatted_creation_date}\n"
        readable_summary += f"* Expiration Date: {formatted_expiration_date}\n"
        readable_summary += f"* Domain Age: {domain_age_years} years\n"
        readable_summary += f"* Name Servers: {', '.join(domain_info.name_servers) if domain_info.name_servers else 'N/A'}\n"

        print(readable_summary)
        return readable_summary

    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

# Test the function with your desired domain, e.g., "eas.com"
domain = "eas.com"  # Replace with the domain you want to test
ssl_info = check_ssl_certificate(domain)
domain_info = get_domain_info(domain)

print(ssl_info)
print(domain_info)
