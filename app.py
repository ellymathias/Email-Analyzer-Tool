from flask import Flask, render_template, request, jsonify
import re
import requests
from email.utils import parseaddr

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Get the header from the POST request
    header = request.json.get('header', '')
    if not header:
        return jsonify({'error': 'No header provided'}), 400

    # Perform the analysis
    analysis_results = analyze_header(header)

    # Return the results as JSON
    return jsonify(analysis_results)

def analyze_header(header):
    # --- IP Address Extraction ---
    # Regex for IPv4 and IPv6 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(header)
    
    private_ip_pattern = re.compile(r'(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)')
    private_ips = [ip for ip in ips if private_ip_pattern.match(ip)]
    public_ips = [ip for ip in ips if not private_ip_pattern.match(ip)]
    
    origin_ip = public_ips[0] if public_ips else None

    # --- IP Reputation Lookup ---
    ip_reputation = None
    if origin_ip:
        try:
            # Using ip-api.com for reputation lookup. It's free and requires no key.
            api_url = f"http://ip-api.com/json/{origin_ip}?fields=status,message,country,isp,org,proxy"
            response = requests.get(api_url, timeout=5) # 5-second timeout
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            
            reputation_data = response.json()
            if reputation_data.get('status') == 'success':
                ip_reputation = {
                    'country': reputation_data.get('country', 'N/A'),
                    'isp': reputation_data.get('isp', 'N/A'),
                    'org': reputation_data.get('org', 'N/A'),
                    'is_proxy': reputation_data.get('proxy', False)
                }
        except requests.exceptions.RequestException:
            ip_reputation = {'error': 'Could not fetch reputation data.'}

    # --- Authentication Results ---
    spf_match = re.search(r'spf=(\w+)', header, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(\w+)', header, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(\w+)', header, re.IGNORECASE)
    
    spf_result = spf_match.group(1) if spf_match else 'Not Found'
    dkim_result = dkim_match.group(1) if dkim_match else 'Not Found'
    dmarc_result = dmarc_match.group(1) if dmarc_match else 'Not Found'

    # --- Spoofing Detection ---
    from_match = re.search(r'^From: (.*)', header, re.MULTILINE)
    reply_to_match = re.search(r'^Reply-To: (.*)', header, re.MULTILINE)
    
    from_field = from_match.group(1).strip() if from_match else 'Not Found'
    reply_to_field = reply_to_match.group(1).strip() if reply_to_match else 'Not Found'
    
    # Extract email addresses to compare, ignoring display names
    from_email = parseaddr(from_field)[1]
    reply_to_email = parseaddr(reply_to_field)[1]

    # Only flag if Reply-To is present and the actual email addresses differ
    if reply_to_field != 'Not Found' and reply_to_email:
        mismatched_senders = from_email.lower() != reply_to_email.lower()
    else:
        mismatched_senders = False

    # --- General Metadata ---
    subject_match = re.search(r'^Subject: (.*)', header, re.MULTILINE)
    date_match = re.search(r'^Date: (.*)', header, re.MULTILINE)
    
    subject = subject_match.group(1).strip() if subject_match else 'Not Found'
    date = date_match.group(1).strip() if date_match else 'Not Found'

    # --- Suspicious Patterns ---
    received_hops = len(re.findall(r'^Received:', header, re.MULTILINE))
    unusual_hops = received_hops > 5 # Arbitrary threshold for "unusual"

    # --- Attachment Analysis ---
    suspicious_extensions = {'exe', 'scr', 'vbs', 'js', 'bat', 'cmd', 'ps1', 'jar', 'msi', 'reg', 'pif'}
    # Regex to find filenames in Content-Type or Content-Disposition
    attachment_matches = re.findall(r'(?:name|filename)\s*=\s*"([^"]+)"', header, re.IGNORECASE)
    
    found_suspicious_attachments = []
    for filename in attachment_matches:
        if '.' in filename:
            ext = filename.rsplit('.', 1)[1].lower()
            if ext in suspicious_extensions:
                found_suspicious_attachments.append(filename)

    # --- Risk Score Calculation ---
    risk_score = 0
    suspicious_indicators = []

    if spf_result.lower() == 'fail':
        risk_score += 3
        suspicious_indicators.append('SPF check failed')
    if dkim_result.lower() == 'fail':
        risk_score += 3
        suspicious_indicators.append('DKIM check failed')
    if dmarc_result.lower() == 'fail':
        risk_score += 2
        suspicious_indicators.append('DMARC check failed')
    if mismatched_senders:
        risk_score += 2
        suspicious_indicators.append('From and Reply-To fields do not match')
    if unusual_hops:
        risk_score += 1
        suspicious_indicators.append(f'Multiple unusual "Received" hops ({received_hops})')
    if found_suspicious_attachments:
        risk_score += 4
        suspicious_indicators.append(f'Suspicious attachment extension(s) found: {", ".join(found_suspicious_attachments)}')
    # Add risk based on IP reputation
    if ip_reputation and ip_reputation.get('is_proxy'):
        risk_score += 3
        suspicious_indicators.append(f'Origin IP ({origin_ip}) is a known proxy or VPN, which can hide the true source.')
    
    if risk_score >= 5:
        risk_assessment = 'High'
    elif risk_score >= 2:
        risk_assessment = 'Medium'
    else:
        risk_assessment = 'Low'

    return {
        'metadata': {
            'subject': subject,
            'date': date
        },
        'ips': {
            'all': ips,
            'public': public_ips,
            'private': private_ips,
            'origin_ip': origin_ip
        },
        'ip_reputation': ip_reputation,
        'authentication': {
            'spf': spf_result,
            'dkim': dkim_result,
            'dmarc': dmarc_result
        },
        'spoofing': {
            'from': from_field,
            'reply_to': reply_to_field,
            'mismatched': mismatched_senders
        },
        'suspicious_indicators': suspicious_indicators,
        'risk_assessment': risk_assessment
    }

if __name__ == '__main__':
    app.run(debug=True)
