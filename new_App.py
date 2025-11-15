import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import google.generativeai as genai
import re
from collections import Counter
import time
import io
import hashlib
import os
import ipaddress
from urllib.parse import urlparse, parse_qs

# Try to import PCAP libraries
try:
    from scapy.all import rdpcap, TCP, Raw, IP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    PCAP_SUPPORT = True
except ImportError:
    PCAP_SUPPORT = False

try:
    import dpkt
    DPKT_SUPPORT = True
except ImportError:
    DPKT_SUPPORT = False

# Page configuration
st.set_page_config(
    page_title="Advanced Cyber Attack Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E90FF;
        text-align: center;
        padding: 1rem 0;
    }
    .stat-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .attack-card {
        border-left: 4px solid #FF4444;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
    .success-card {
        border-left: 4px solid #FF6B35;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #fff3cd;
        border-radius: 5px;
    }
    .attempt-card {
        border-left: 4px solid #FFA500;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
    .safe-card {
        border-left: 4px solid #44FF44;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'attacks_db' not in st.session_state:
    st.session_state.attacks_db = []
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'api_key' not in st.session_state:
    st.session_state.api_key = ""
if 'gemini_model' not in st.session_state:
    st.session_state.gemini_model = "gemini-1.5-flash"
if 'performance_stats' not in st.session_state:
    st.session_state.performance_stats = {
        'total_analyses': 0,
        'ai_calls_saved': 0,
        'ai_calls_made': 0,
        'cache_hits': 0,
        'successful_attacks': 0,
        'attempted_attacks': 0
    }

# Available Gemini models
GEMINI_MODELS = [
    "gemini-1.5-flash",
    "gemini-1.5-pro", 
    "gemini-1.0-pro"
]

# Cache management
CACHE_FILE = 'gemini_cache.json'

def load_cache():
    """Load cache from file"""
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_cache(cache):
    """Save cache to file"""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except:
        pass

def get_url_signature(url):
    """Create normalized hash of URL for caching"""
    clean_url = re.sub(r'user_token=[^&]+', 'user_token=REMOVED', url)
    clean_url = re.sub(r'timestamp=[^&]+', 'timestamp=REMOVED', clean_url)
    clean_url = re.sub(r'[0-9a-f]{32}', 'HASH_REMOVED', clean_url)
    return hashlib.md5(clean_url.encode()).hexdigest()

def get_cached_result(url):
    """Get cached result for URL"""
    cache = load_cache()
    url_sig = get_url_signature(url)
    
    if url_sig in cache:
        cached_data = cache[url_sig]
        cache_time = datetime.fromisoformat(cached_data['timestamp'])
        if datetime.now() - cache_time < timedelta(hours=24):
            st.session_state.performance_stats['cache_hits'] += 1
            return cached_data['result']
    return None

def cache_result(url, result):
    """Cache result for URL"""
    cache = load_cache()
    url_sig = get_url_signature(url)
    
    cache[url_sig] = {
        'timestamp': datetime.now().isoformat(),
        'result': result
    }
    save_cache(cache)

# Enhanced Attack Detection Functions
def detect_sql_injection(url):
    """Detect SQL injection patterns"""
    indicators = []
    patterns = {
        r"(\bOR\b|\bAND\b).*=.*": "Logical operator with comparison",
        r"'.*--": "SQL comment syntax",
        r"\bUNION\b.*\bSELECT\b": "UNION-based injection",
        r"(sleep|waitfor|benchmark)\s*\(": "Time-based blind SQLi",
        r"@@version|version\(\)": "Database version query",
        r"1\s*=\s*1|'1'='1": "Tautology condition",
        r"(admin|root|user)'?\s*(--|#|/\*)": "Authentication bypass attempt",
        r"insert\s+into|update\s+\w+\s+set|delete\s+from": "Data manipulation attempt"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_xss(url):
    """Detect XSS patterns"""
    indicators = []
    patterns = {
        r"<script[^>]*>": "Script tag detected",
        r"javascript:": "JavaScript protocol",
        r"on\w+\s*=": "Event handler",
        r"<iframe": "Iframe injection",
        r"<img[^>]*onerror": "Image with onerror handler",
        r"eval\(|alert\(|prompt\(": "JavaScript execution function",
        r"document\.(write|cookie|location)": "DOM manipulation",
        r"<svg[^>]*onload": "SVG with onload handler"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_path_traversal(url):
    """Detect path traversal patterns"""
    indicators = []
    patterns = {
        r"\.\./|\.\.\\": "Directory traversal sequence",
        r"%2e%2e[/\\]": "Encoded traversal",
        r"/etc/passwd|/etc/shadow": "Unix system file access",
        r"C:\\Windows|C:\\boot\.ini": "Windows system file access",
        r"%00": "Null byte injection",
        r"\.\.%252f": "Double encoded traversal",
        r"\.\.%c0%af": "Unicode traversal"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_command_injection(url):
    """Detect command injection patterns"""
    indicators = []
    patterns = {
        r"[;&|`$]": "Command separator",
        r"\$\(.*\)|`.*`": "Command substitution",
        r"\b(cat|ls|whoami|ping|curl|wget|nc|netcat)\b": "System command",
        r"[|&]{2}": "Command chaining",
        r">\s*[/\\]": "Output redirection",
        r"\|\s*base64": "Base64 encoding attempt"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_ssrf(url):
    """Detect SSRF patterns"""
    indicators = []
    patterns = {
        r"(localhost|127\.0\.0\.1|0\.0\.0\.0)": "Localhost reference",
        r"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)": "Internal IP address",
        r"169\.254\.169\.254": "Cloud metadata endpoint",
        r"file://|gopher://|dict://": "Suspicious protocol",
        r"@.*\.(local|internal|lan)": "Internal domain",
        r"metadata\.google\.internal": "GCP metadata service"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_lfi_rfi(url):
    """Detect Local/Remote File Inclusion"""
    indicators = []
    patterns = {
        r"php://|data://|expect://|zip://": "PHP wrapper protocol",
        r"file=.*\.\.": "File parameter with traversal",
        r"(include|require)=": "Include/require parameter",
        r"\.php.*\x00": "Null byte with PHP",
        r"http[s]?://.*\.(txt|php|asp|jsp)": "Remote file URL",
        r"\.\./\.\./": "Multiple directory traversal"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_xxe(url):
    """Detect XXE injection"""
    indicators = []
    patterns = {
        r"<!DOCTYPE": "DOCTYPE declaration",
        r"<!ENTITY": "ENTITY declaration",
        r"SYSTEM\s+['\"]": "SYSTEM keyword",
        r"file://": "File protocol in XML",
        r"%[0-9a-f]{2}": "URL encoded characters"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_web_shell(url):
    """Detect web shell upload attempts"""
    indicators = []
    patterns = {
        r"\.(php|asp|aspx|jsp|jspx)(\?|$)": "Executable file extension",
        r"(cmd|shell|backdoor|webshell)\.(php|asp|jsp)": "Suspicious filename",
        r"upload.*\.(php|asp|jsp)": "Upload with executable extension",
        r"\.(war|jar|ear)(\?|$)": "Java archive upload",
        r"cmd=|\?cmd=|\&cmd=": "Command parameter"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_typosquatting(url):
    """Detect typosquatting/URL spoofing"""
    indicators = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        patterns = {
            r"([a-zA-Z]{2,})\.(com|org|net)": "Potential domain spoofing",
            r"([0-9]+\.){3}[0-9]+": "IP address in URL",
            r"@.*http": "URL obfuscation",
            r"\.(cm|om|comm|ne|orgn|netl)": "Common typos",
            r"faceboook|goggle|micorsoft": "Common brand typos",
            r"\-facebook|\-google|\-microsoft": "Brand name with hyphen"
        }
        
        for pattern, description in patterns.items():
            if re.search(pattern, domain, re.IGNORECASE):
                indicators.append(description)
        
        # Check for homograph attacks (basic)
        if any(char in domain for char in ['℀', 'ⅽ', 'ⅾ', 'ℯ', 'ℊ']):
            indicators.append("Homograph attack characters detected")
            
    except:
        pass
    
    return len(indicators) > 0, indicators

def detect_credential_stuffing(url):
    """Detect credential stuffing/brute force patterns"""
    indicators = []
    patterns = {
        r"login.*[0-9]{5,}": "Rapid login attempts pattern",
        r"password=.*&password=.*&password=": "Multiple password attempts",
        r"user=admin&pass=.*&user=admin&pass=": "Credential repetition",
        r"failed.*attempt.*[0-9]+": "Failed attempt counters",
        r"try=[0-9]+&attempt=[0-9]+": "Multiple attempt parameters",
        r"username=.*&username=.*": "Multiple username attempts"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def detect_parameter_pollution(url):
    """Detect HTTP Parameter Pollution"""
    indicators = []
    
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check for duplicate parameters
        for param, values in query_params.items():
            if len(values) > 1:
                indicators.append(f"Duplicate parameter: {param}")
        
        patterns = {
            r"&[a-z]+=.*&[a-z]+=.*&[a-z]+=.*&": "Excessive parameters",
            r"input=.*&input=.*&input=.*": "Multiple same parameter values",
            r"param=.*&param=.*": "Duplicate parameter pattern"
        }
        
        for pattern, description in patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(description)
                
    except:
        pass
    
    return len(indicators) > 0, indicators

def enhanced_quick_detection(url):
    """Enhanced detection with all required attack types"""
    results = {
        "SQL Injection": detect_sql_injection(url),
        "Cross-Site Scripting (XSS)": detect_xss(url),
        "Path Traversal": detect_path_traversal(url),
        "Command Injection": detect_command_injection(url),
        "SSRF": detect_ssrf(url),
        "LFI/RFI": detect_lfi_rfi(url),
        "XXE Injection": detect_xxe(url),
        "Web Shell Upload": detect_web_shell(url),
        "Typosquatting": detect_typosquatting(url),
        "Credential Stuffing": detect_credential_stuffing(url),
        "HTTP Parameter Pollution": detect_parameter_pollution(url)
    }
    
    detected_attacks = []
    all_indicators = []
    
    for attack_type, (detected, indicators) in results.items():
        if detected:
            detected_attacks.append(attack_type)
            all_indicators.extend([f"{attack_type}: {ind}" for ind in indicators])
    
    return detected_attacks, all_indicators

# Success Detection Functions
def determine_attack_success(url, attack_type, server_response=None, response_code=None):
    """
    Determine if an attack was successful based on various indicators
    """
    success_indicators = {
        "SQL Injection": {
            "url_patterns": [
                r"union.*select.*1,2,3",
                r"insert.*into.*values",
                r"drop.*table",
                r"update.*set.*=",
                r"exec\(|execute\(|sp_"
            ],
            "response_patterns": [
                r"error.*mysql|mysql.*error",
                r"warning.*mysql", 
                r"you have an error in your sql syntax",
                r"column.*not.*found",
                r"table.*not.*found",
                r"ODBC.*Driver",
                r"SQLServer.*Exception"
            ],
            "success_codes": [200, 500],  # Success or error revealing info
            "behavior": "Database errors or data disclosure"
        },
        "XSS": {
            "url_patterns": [
                r"<script>alert\(1\)</script>",
                r"javascript:alert\(1\)",
                r"onload=alert\(1\)",
                r"><script>alert"
            ],
            "response_patterns": [
                r"<script>.*</script>",
                r"alert\(.*\)",
                r"onload=.*",
                r"onerror=.*",
                r"javascript:"
            ],
            "success_codes": [200],
            "behavior": "Script reflection in response"
        },
        "Path Traversal": {
            "url_patterns": [
                r"\.\./\.\./etc/passwd",
                r"\.\.\\\.\.\\boot\.ini",
                r"\.\./\.\./\.\./etc/shadow",
                r"\.\.%2f\.\.%2fetc%2fpasswd"
            ],
            "response_patterns": [
                r"root:.*:0:0:",
                r"\[boot loader\]",
                r"default=multi",
                r"Permission denied",
                r"No such file",
                r"Access is denied"
            ],
            "success_codes": [200, 403, 404],
            "behavior": "File content or access errors"
        },
        "Command Injection": {
            "url_patterns": [
                r";cat.*etc/passwd",
                r"&dir.*c:\\",
                r"\|whoami",
                r"`id`"
            ],
            "response_patterns": [
                r"root:.*:0:0:",
                r"Volume in drive",
                r"Directory of",
                r"uid=.*gid=.*",
                r"cmd\.exe",
                r"bin/bash"
            ],
            "success_codes": [200],
            "behavior": "Command output in response"
        },
        "LFI/RFI": {
            "url_patterns": [
                r"include=.*http://",
                r"file=.*\.\./\.\.",
                r"page=.*\.\./\.\."
            ],
            "response_patterns": [
                r"<\?php",
                r"<asp:",
                r"<%@ Page",
                r"root:",
                r"Warning.*include"
            ],
            "success_codes": [200],
            "behavior": "File inclusion evidence"
        }
    }
    
    attack_config = success_indicators.get(attack_type, {})
    evidence = []
    
    # Check URL patterns
    for pattern in attack_config.get("url_patterns", []):
        if re.search(pattern, url, re.IGNORECASE):
            evidence.append(f"URL contains successful {attack_type} payload")
            break
    
    # Check response patterns
    if server_response:
        for pattern in attack_config.get("response_patterns", []):
            if re.search(pattern, server_response, re.IGNORECASE):
                evidence.append(f"Server response contains {attack_type} success indicators")
                break
    
    # Check response codes
    if response_code and response_code in attack_config.get("success_codes", []):
        evidence.append(f"Response code {response_code} indicates potential success")
    
    if evidence:
        return True, evidence
    
    return False, ["No success indicators found - likely attempt only"]

def analyze_attack_success(url, detected_attacks, server_response=None, response_code=None):
    """
    Analyze all detected attacks for success indicators
    """
    successful_attacks = []
    success_evidence = []
    attack_status = "attempt"
    
    for attack_type in detected_attacks:
        is_successful, evidence = determine_attack_success(url, attack_type, server_response, response_code)
        if is_successful:
            successful_attacks.append(attack_type)
            success_evidence.extend(evidence)
            attack_status = "success"
    
    return successful_attacks, success_evidence, attack_status

# Gemini API Configuration and Analysis
def configure_gemini(api_key, model_name="gemini-1.5-flash"):
    """Configure Google Gemini API with specific model"""
    try:
        genai.configure(api_key=api_key)
        st.session_state.gemini_model = model_name
        return True
    except Exception as e:
        st.error(f"Error configuring Gemini API: {str(e)}")
        return False

def should_use_gemini(quick_attacks, quick_indicators):
    """Smart decision making for Gemini API usage"""
    if not quick_attacks and len(quick_indicators) == 0:
        return False
    
    obvious_attacks = [
        "SQL comment syntax",
        "Script tag detected", 
        "Directory traversal sequence",
        "Command separator",
        "Localhost reference"
    ]
    
    if any(any(obvious in ind for ind in quick_indicators) for obvious in obvious_attacks):
        return False
    
    complex_cases = [
        len(quick_indicators) >= 3,
        any('ORACLE' in ind for ind in quick_indicators),
        any('XXE' in ind for ind in quick_indicators),
        any('Template' in ind for ind in quick_indicators),
        any('Wrapper' in ind for ind in quick_indicators)
    ]
    
    return any(complex_cases)

def analyze_with_gemini_efficient(url, quick_results):
    """Token-efficient Gemini analysis"""
    cached_result = get_cached_result(url)
    if cached_result:
        return cached_result
    
    try:
        model = genai.GenerativeModel(st.session_state.gemini_model)
        
        prompt = f"""URL security analysis:
URL: {url[:150]}
Patterns detected: {', '.join(quick_results) if quick_results else 'None'}

Respond in JSON:
{{
"malicious": true/false,
"attacks": ["type1"],
"confidence": 0-100,
"severity": "LOW/MEDIUM/HIGH/CRITICAL",
"explanation": "brief explanation",
"recommendations": ["rec1"]
}}"""

        response = model.generate_content(prompt)
        
        text = response.text
        text = re.sub(r'```json\n?', '', text)
        text = re.sub(r'```\n?', '', text)
        text = text.strip()
        
        result = json.loads(text)
        cache_result(url, result)
        st.session_state.performance_stats['ai_calls_made'] += 1
        
        return result
    
    except Exception as e:
        st.error(f"Gemini API Error: {str(e)}")
        return None

def calculate_confidence(quick_indicators, gemini_result):
    """Calculate overall confidence score"""
    if gemini_result and 'confidence' in gemini_result:
        return gemini_result['confidence']
    elif len(quick_indicators) > 0:
        return min(70 + (len(quick_indicators) * 5), 95)
    else:
        return 10

def determine_severity(attack_types):
    """Determine severity based on attack types"""
    critical_attacks = ['SQL Injection', 'Command Injection', 'XXE Injection', 'Web Shell Upload']
    high_attacks = ['XSS', 'SSRF', 'LFI/RFI', 'Path Traversal']
    
    for attack in attack_types:
        if any(critical in attack for critical in critical_attacks):
            return "CRITICAL"
    
    for attack in attack_types:
        if any(high in attack for high in high_attacks):
            return "HIGH"
    
    if len(attack_types) > 0:
        return "MEDIUM"
    
    return "LOW"

def enhanced_url_analysis(url, use_gemini=True, server_response=None, response_code=None, source_ip=None):
    """
    Complete enhanced analysis with success detection
    """
    start_time = time.time()
    
    # Step 1: Enhanced pattern detection
    attempted_attacks, quick_indicators = enhanced_quick_detection(url)
    pattern_time = time.time() - start_time
    
    # Step 2: Success analysis
    success_start = time.time()
    successful_attacks, success_evidence, attack_status = analyze_attack_success(
        url, attempted_attacks, server_response, response_code
    )
    success_time = time.time() - success_start
    
    # Step 3: Smart AI decision making
    gemini_result = None
    ai_time = 0
    
    if use_gemini and st.session_state.api_key:
        if should_use_gemini(attempted_attacks, quick_indicators):
            ai_start = time.time()
            gemini_result = analyze_with_gemini_efficient(url, attempted_attacks)
            ai_time = time.time() - ai_start
        else:
            st.session_state.performance_stats['ai_calls_saved'] += 1
    
    # Step 4: Combine results
    if gemini_result:
        final_attack_types = gemini_result.get('attacks', attempted_attacks)
        confidence = gemini_result.get('confidence', 0)
        severity = gemini_result.get('severity', determine_severity(final_attack_types))
        explanation = gemini_result.get('explanation', '')
        recommendations = gemini_result.get('recommendations', [])
        is_malicious = gemini_result.get('malicious', len(final_attack_types) > 0)
    else:
        final_attack_types = attempted_attacks
        confidence = calculate_confidence(quick_indicators, None)
        severity = determine_severity(final_attack_types)
        explanation = "Pattern-based detection" + (" (AI skipped for efficiency)" if use_gemini else "")
        recommendations = []
        is_malicious = len(final_attack_types) > 0
    
    # Update performance stats
    if attack_status == "success":
        st.session_state.performance_stats['successful_attacks'] += 1
    else:
        st.session_state.performance_stats['attempted_attacks'] += 1
    
    # Store analysis record
    analysis_record = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'url': url,
        'source_ip': source_ip,
        'attempted_attacks': attempted_attacks,
        'successful_attacks': successful_attacks,
        'success_evidence': success_evidence,
        'attack_status': attack_status,
        'final_attack_types': final_attack_types,
        'confidence': confidence,
        'severity': severity,
        'is_malicious': is_malicious,
        'indicators': quick_indicators,
        'explanation': explanation,
        'recommendations': recommendations,
        'response_code': response_code,
        'timing': {
            'pattern_detection': pattern_time,
            'success_analysis': success_time,
            'ai_analysis': ai_time,
            'total': pattern_time + success_time + ai_time
        }
    }
    
    st.session_state.analysis_history.append(analysis_record)
    st.session_state.performance_stats['total_analyses'] += 1
    
    if is_malicious:
        st.session_state.attacks_db.append(analysis_record)
    
    return analysis_record

# Enhanced PCAP Analysis
# Enhanced PCAP Analysis with Error Handling
def extract_urls_with_ips_from_pcap(pcap_file):
    """Extract URLs with source IPs from PCAP file with robust error handling"""
    urls_with_ips = []
    
    if not PCAP_SUPPORT:
        st.warning("⚠️ Scapy not available for PCAP parsing")
        return urls_with_ips
    
    try:
        # Save uploaded file to temporary location
        temp_path = f"/tmp/{pcap_file.name}"
        with open(temp_path, "wb") as f:
            f.write(pcap_file.getvalue())
        
        # Use different approach to read PCAP
        packets = []
        try:
            packets = rdpcap(temp_path)
        except Exception as e:
            st.warning(f"Scapy rdpcap failed: {str(e)}. Trying alternative method...")
            # Try reading with different parameters
            try:
                packets = rdpcap(temp_path, count=1000)  # Limit packets for large files
            except:
                st.error("Failed to parse PCAP file with Scapy")
                return urls_with_ips
        
        packet_count = 0
        for packet in packets:
            if packet_count >= 1000:  # Limit processing for large files
                break
                
            try:
                # Check for IP and TCP layers
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    ip_layer = packet[IP]
                    source_ip = ip_layer.src
                    
                    # Check for HTTP request
                    if packet.haslayer(HTTPRequest):
                        http_layer = packet[HTTPRequest]
                        host = http_layer.Host.decode() if http_layer.Host else ""
                        path = http_layer.Path.decode() if http_layer.Path else ""
                        
                        if host and path:
                            url = f"http://{host}{path}"
                            urls_with_ips.append({
                                'url': url,
                                'source_ip': source_ip,
                                'timestamp': datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
                            })
                            packet_count += 1
                    
                    # Also check raw TCP payload for HTTP requests
                    elif packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load
                            payload_str = payload.decode('utf-8', errors='ignore')
                            
                            # Look for HTTP methods in payload
                            if any(method in payload_str for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                                lines = payload_str.split('\r\n')
                                if lines and any(line.startswith(('GET', 'POST', 'PUT', 'DELETE')) for line in lines):
                                    request_line = lines[0]
                                    parts = request_line.split()
                                    if len(parts) >= 2:
                                        path = parts[1]
                                        host = ""
                                        for line in lines[1:]:
                                            if line.lower().startswith('host:'):
                                                host = line.split(':', 1)[1].strip()
                                                break
                                        
                                        if host and path:
                                            url = f"http://{host}{path}"
                                            urls_with_ips.append({
                                                'url': url,
                                                'source_ip': source_ip,
                                                'timestamp': datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
                                            })
                                            packet_count += 1
                        except:
                            continue
                            
            except Exception as e:
                continue  # Skip problematic packets
        
        # Clean up temp file
        try:
            os.remove(temp_path)
        except:
            pass
            
    except Exception as e:
        st.error(f"Error parsing PCAP: {str(e)}")
    
    return urls_with_ips

def parse_pcap_with_dpkt_enhanced(pcap_file):
    """Enhanced dpkt PCAP parsing as fallback"""
    urls_with_ips = []
    
    if not DPKT_SUPPORT:
        return urls_with_ips
    
    try:
        pcap_file.seek(0)
        pcap_data = pcap_file.getvalue()
        pcap = dpkt.pcap.Reader(io.BytesIO(pcap_data))
        
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                source_ip = dpkt.utils.inet_to_str(ip.src)
                
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                
                tcp = ip.data
                
                if len(tcp.data) > 0:
                    try:
                        # Try to parse as HTTP request
                        request = dpkt.http.Request(tcp.data)
                        host = request.headers.get('host', '')
                        uri = request.uri
                        
                        if host and uri:
                            url = f"http://{host}{uri}"
                            urls_with_ips.append({
                                'url': url,
                                'source_ip': source_ip,
                                'timestamp': datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                            })
                    except:
                        # Manual HTTP parsing
                        try:
                            payload = tcp.data.decode('utf-8', errors='ignore')
                            if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                                lines = payload.split('\r\n')
                                if lines:
                                    request_line = lines[0]
                                    parts = request_line.split()
                                    if len(parts) >= 2:
                                        path = parts[1]
                                        host = ""
                                        for line in lines[1:]:
                                            if line.lower().startswith('host:'):
                                                host = line.split(':', 1)[1].strip()
                                                break
                                        
                                        if host and path:
                                            url = f"http://{host}{path}"
                                            urls_with_ips.append({
                                                'url': url,
                                                'source_ip': source_ip,
                                                'timestamp': datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                                            })
                        except:
                            continue
            except:
                continue
                
    except Exception as e:
        st.error(f"Error parsing PCAP with dpkt: {str(e)}")
    
    return urls_with_ips

def enhanced_pcap_analysis(uploaded_file, use_gemini=True):
    """Robust PCAP analysis with multiple fallback methods"""
    urls_with_ips = []
    
    # Try Scapy first
    if PCAP_SUPPORT:
        with st.spinner("🔄 Parsing PCAP with Scapy..."):
            urls_with_ips = extract_urls_with_ips_from_pcap(uploaded_file)
    
    # Fallback to dpkt if Scapy fails or finds nothing
    if not urls_with_ips and DPKT_SUPPORT:
        with st.spinner("🔄 Trying dpkt PCAP parsing..."):
            urls_with_ips = parse_pcap_with_dpkt_enhanced(uploaded_file)
    
    # If still no results, try manual text extraction
    if not urls_with_ips:
        with st.spinner("🔄 Attempting manual PCAP analysis..."):
            urls_with_ips = manual_pcap_extraction(uploaded_file)
    
    if not urls_with_ips:
        st.warning("⚠️ No HTTP URLs extracted from PCAP file. The file may contain:")
        st.write("- Encrypted HTTPS traffic (cannot be parsed)")
        st.write("- Non-HTTP protocols")
        st.write("- Corrupted or incomplete PCAP data")
        st.write("- Very large file (processing limited to first 1000 packets)")
        return []
    
    st.success(f"✅ Extracted {len(urls_with_ips)} URLs from PCAP")
    
    # Analyze extracted URLs
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for idx, url_data in enumerate(urls_with_ips):
        status_text.text(f"Analyzing {idx + 1}/{len(urls_with_ips)}: {url_data['url'][:50]}...")
        
        result = enhanced_url_analysis(
            url=url_data['url'],
            use_gemini=use_gemini,
            source_ip=url_data['source_ip'],
            server_response=None,
            response_code=None
        )
        
        results.append(result)
        progress_bar.progress((idx + 1) / len(urls_with_ips))
    
    status_text.text("✅ PCAP analysis complete!")
    return results

def manual_pcap_extraction(uploaded_file):
    """Manual PCAP extraction as last resort"""
    urls_with_ips = []
    
    try:
        # Read file as binary and look for HTTP patterns
        content = uploaded_file.getvalue()
        content_str = content.decode('latin-1')  # Use latin-1 to handle binary data
        
        # Look for HTTP request patterns
        http_patterns = [
            r'GET\s+([^\s]+)\s+HTTP/1\.[01]',
            r'POST\s+([^\s]+)\s+HTTP/1\.[01]', 
            r'Host:\s*([^\r\n]+)'
        ]
        
        # Simple IP pattern (basic)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Extract potential URLs and IPs
        import re
        get_matches = re.findall(r'GET\s+([^\s]+)\s+HTTP/1\.[01]', content_str)
        host_matches = re.findall(r'Host:\s*([^\r\n]+)', content_str)
        ip_matches = re.findall(ip_pattern, content_str)
        
        # Create URL objects with dummy IPs
        for i, (path, host) in enumerate(zip(get_matches, host_matches)):
            if i < len(ip_matches):
                source_ip = ip_matches[i]
            else:
                source_ip = "192.168.1.100"  # Default IP
            
            url = f"http://{host.strip()}{path}"
            urls_with_ips.append({
                'url': url,
                'source_ip': source_ip,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
    except Exception as e:
        st.error(f"Manual extraction failed: {str(e)}")
    
    return urls_with_ips

def enhanced_pcap_analysis(uploaded_file, use_gemini=True):
    """Enhanced PCAP analysis with IP tracking"""
    urls_with_ips = extract_urls_with_ips_from_pcap(uploaded_file)
    
    if not urls_with_ips:
        st.warning("No HTTP traffic with IP information found in PCAP file")
        return []
    
    results = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for idx, url_data in enumerate(urls_with_ips):
        status_text.text(f"Analyzing {idx + 1}/{len(urls_with_ips)}: {url_data['url'][:50]}...")
        
        result = enhanced_url_analysis(
            url=url_data['url'],
            use_gemini=use_gemini,
            source_ip=url_data['source_ip'],
            server_response=None,  # Would need response packets for full analysis
            response_code=None
        )
        
        results.append(result)
        progress_bar.progress((idx + 1) / len(urls_with_ips))
    
    status_text.text("✅ PCAP analysis complete!")
    return results

# Application Pages
def show_enhanced_dashboard():
    """Enhanced dashboard with success/attempt differentiation"""
    st.markdown('<p class="main-header">🛡️ Advanced Cyber Attack Detection System</p>', unsafe_allow_html=True)
    st.markdown("### AI-Powered URL Analysis with Success Detection")
    
    # Enhanced Stats Cards
    col1, col2, col3, col4 = st.columns(4)
    
    total_analyzed = len(st.session_state.analysis_history)
    total_attacks = len(st.session_state.attacks_db)
    successful_attacks = st.session_state.performance_stats['successful_attacks']
    attempted_attacks = st.session_state.performance_stats['attempted_attacks']
    
    with col1:
        st.metric("📊 Total Analyzed", total_analyzed)
    
    with col2:
        st.metric("⚠️ Attack Attempts", attempted_attacks)
    
    with col3:
        st.metric("🔴 Successful Attacks", successful_attacks)
    
    with col4:
        success_rate = (successful_attacks / attempted_attacks * 100) if attempted_attacks > 0 else 0
        st.metric("🎯 Success Rate", f"{success_rate:.1f}%")
    
    st.markdown("---")
    
    # Enhanced Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Attack Success Distribution")
        if st.session_state.attacks_db:
            status_counts = Counter([a.get('attack_status', 'attempt') for a in st.session_state.attacks_db])
            
            fig = px.pie(
                values=list(status_counts.values()),
                names=list(status_counts.keys()),
                color=list(status_counts.keys()),
                color_discrete_map={'success': '#FF4444', 'attempt': '#FFA500'}
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks detected yet")
    
    with col2:
        st.subheader("🎯 Attack Type Distribution")
        if st.session_state.attacks_db:
            attack_types = []
            for attack in st.session_state.attacks_db:
                attack_types.extend(attack.get('final_attack_types', []))
            
            if attack_types:
                type_counts = Counter(attack_types)
                df = pd.DataFrame(list(type_counts.items()), columns=['Attack Type', 'Count'])
                fig = px.bar(df, x='Count', y='Attack Type', orientation='h',
                           color='Count', color_continuous_scale='Reds')
                fig.update_layout(height=350)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No attack types detected")
        else:
            st.info("No attacks detected yet")
    
    # Recent Attacks Table with Status
    st.subheader("🕐 Recent Detections")
    if st.session_state.attacks_db:
        recent = st.session_state.attacks_db[-10:][::-1]
        df = pd.DataFrame(recent)
        
        display_df = pd.DataFrame({
            'Timestamp': df['timestamp'],
            'Source IP': df.get('source_ip', 'N/A'),
            'URL Preview': df['url'].str[:40] + '...',
            'Attack Types': df['final_attack_types'].apply(lambda x: ', '.join(x)),
            'Status': df['attack_status'].apply(lambda x: f"🔴 {x.upper()}" if x == 'success' else f"🟡 {x.upper()}"),
            'Severity': df['severity'],
            'Confidence': df['confidence'].apply(lambda x: f"{x}%")
        })
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No detections yet. Start analyzing URLs to see results here!")

def show_enhanced_url_analysis():
    """Enhanced URL analysis page with success detection"""
    st.title("🔍 Enhanced URL Analysis")
    st.markdown("Analyze URLs for attack attempts and successful compromises")
    
    # Performance info
    st.info(f"📊 Performance: {st.session_state.performance_stats['total_analyses']} analyses | "
           f"Cache hits: {st.session_state.performance_stats['cache_hits']} | "
           f"AI calls saved: {st.session_state.performance_stats['ai_calls_saved']}")
    
    # Input section
    col1, col2 = st.columns([2, 1])
    
    with col1:
        url_input = st.text_area(
            "URL or HTTP Request",
            placeholder="http://example.com/page?id=1' UNION SELECT 1,2,3--\n\nExample successful attacks:\n- SQL: /page?id=1 UNION SELECT 1,2,3\n- XSS: /search?q=<script>alert(1)</script>\n- Path: /file?path=../../../etc/passwd",
            height=150
        )
    
    with col2:
        st.subheader("Analysis Options")
        use_gemini = st.checkbox("Use Gemini AI", value=True, disabled=not st.session_state.api_key)
        include_response = st.checkbox("Include Response Analysis", value=False,
                                     help="Analyze server responses for success detection")
        
        if include_response:
            response_input = st.text_area("Server Response (Optional)", height=100,
                                        placeholder="Paste server response here for success analysis...")
            response_code = st.number_input("HTTP Response Code", min_value=100, max_value=599, value=200)
        else:
            response_input = None
            response_code = None
        
        analyze_button = st.button("🔍 Analyze URL", type="primary", use_container_width=True)
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL with enhanced detection..."):
            result = enhanced_url_analysis(
                url=url_input,
                use_gemini=use_gemini,
                server_response=response_input,
                response_code=response_code
            )
            
            # Display Results
            st.markdown("---")
            st.subheader("📊 Enhanced Analysis Results")
            
            # Status-based display
            if result['attack_status'] == 'success':
                st.markdown(f'<div class="success-card">', unsafe_allow_html=True)
                st.error("🔴 **SUCCESSFUL ATTACK DETECTED!**")
                st.markdown('</div>', unsafe_allow_html=True)
            elif result['is_malicious']:
                st.markdown(f'<div class="attempt-card">', unsafe_allow_html=True)
                st.warning("🟡 **ATTACK ATTEMPT DETECTED**")
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="safe-card">', unsafe_allow_html=True)
                st.success("✅ **NO THREATS DETECTED**")
                st.markdown('</div>', unsafe_allow_html=True)
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Confidence", f"{result['confidence']}%")
            with col2:
                status_color = "🔴" if result['attack_status'] == 'success' else "🟡"
                st.metric("Status", f"{status_color} {result['attack_status'].upper()}")
            with col3:
                st.metric("Severity", result['severity'])
            with col4:
                st.metric("Analysis Time", f"{result['timing']['total']:.2f}s")
            
            # Attack Details
            if result['attempted_attacks']:
                st.subheader("🎯 Detected Attack Types")
                for attack in result['attempted_attacks']:
                    status_icon = "🔴" if attack in result['successful_attacks'] else "🟡"
                    st.markdown(f"- {status_icon} **{attack}**")
            
            # Success Evidence
            if result['success_evidence']:
                st.subheader("🔍 Success Evidence")
                for evidence in result['success_evidence']:
                    st.markdown(f"- ✅ {evidence}")
            
            # Technical Indicators
            if result['indicators']:
                st.subheader("🔧 Technical Indicators")
                for indicator in result['indicators']:
                    st.markdown(f"- {indicator}")
            
            # AI Explanation
            if result['explanation']:
                st.subheader("📝 Analysis Explanation")
                st.info(result['explanation'])
            
            # Recommendations
            if result['recommendations']:
                st.subheader("💡 Security Recommendations")
                for rec in result['recommendations']:
                    st.markdown(f"- {rec}")

def show_enhanced_bulk_analysis():
    """Enhanced bulk analysis with PCAP support"""
    st.title("📂 Enhanced Bulk Analysis")
    st.markdown("Upload files for comprehensive attack analysis with success detection")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a file for analysis",
        type=['pcap', 'pcapng', 'csv', 'json', 'txt'],
        help="PCAP files will extract URLs with source IPs for enhanced analysis"
    )
    
    # Analysis options
    with st.expander("⚙️ Enhanced Analysis Options", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            use_gemini = st.checkbox("Enable Gemini AI", value=True, disabled=not st.session_state.api_key)
            analysis_mode = st.selectbox(
                "Analysis Mode",
                ["Fast (Patterns Only)", "Standard (Patterns + Success)", "Comprehensive (AI Enhanced)"],
                index=1
            )
            
        with col2:
            max_urls = st.number_input("Maximum URLs to analyze", min_value=1, max_value=1000, value=100)
            ip_filter = st.text_input("Filter by IP Range (optional)", placeholder="192.168.1.0/24")
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: {uploaded_file.name} ({uploaded_file.size / 1024:.2f} KB)")
        
        if st.button("🚀 Start Enhanced Analysis", type="primary"):
            with st.spinner("Processing file with enhanced detection..."):
                try:
                    results = []
                    
                    if uploaded_file.name.endswith(('.pcap', '.pcapng')):
                        # Enhanced PCAP analysis
                        results = enhanced_pcap_analysis(uploaded_file, use_gemini)
                        
                    else:
                        # Standard file analysis
                        urls = []
                        if uploaded_file.name.endswith('.csv'):
                            df = pd.read_csv(uploaded_file)
                            if 'url' in df.columns:
                                urls = df['url'].tolist()[:max_urls]
                        
                        elif uploaded_file.name.endswith('.json'):
                            data = json.load(uploaded_file)
                            if isinstance(data, list):
                                urls = [item.get('url', '') for item in data if isinstance(item, dict)][:max_urls]
                        
                        elif uploaded_file.name.endswith('.txt'):
                            content = uploaded_file.read().decode('utf-8')
                            urls = [line.strip() for line in content.split('\n') if line.strip()][:max_urls]
                        
                        # Analyze URLs
                        progress_bar = st.progress(0)
                        for idx, url in enumerate(urls):
                            result = enhanced_url_analysis(url, use_gemini)
                            results.append(result)
                            progress_bar.progress((idx + 1) / len(urls))
                    
                    # Display results
                    if results:
                        successful = [r for r in results if r['attack_status'] == 'success']
                        attempts = [r for r in results if r['is_malicious'] and r['attack_status'] == 'attempt']
                        
                        st.success(f"🎯 Analysis Complete: {len(successful)} successful, {len(attempts)} attempts out of {len(results)} URLs")
                        
                        # Summary statistics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total URLs", len(results))
                        with col2:
                            st.metric("Successful Attacks", len(successful))
                        with col3:
                            st.metric("Attack Attempts", len(attempts))
                        
                        # Export results
                        if st.button("📥 Export Results (CSV)"):
                            df = pd.DataFrame(results)
                            csv = df.to_csv(index=False)
                            st.download_button(
                                label="Download CSV",
                                data=csv,
                                file_name=f"enhanced_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                    
                    else:
                        st.warning("No results generated from the analysis")
                        
                except Exception as e:
                    st.error(f"Error during analysis: {str(e)}")

def show_enhanced_attack_database():
    """Enhanced attack database with advanced filtering"""
    st.title("🗂️ Enhanced Attack Database")
    st.markdown("Query and analyze detected attacks with advanced filters")
    
    if not st.session_state.attacks_db:
        st.info("No attacks in database yet. Analyze some URLs to populate the database.")
        return
    
    # Enhanced Filters
    with st.expander("🔍 Advanced Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            all_attack_types = set()
            for attack in st.session_state.attacks_db:
                all_attack_types.update(attack.get('final_attack_types', []))
            selected_types = st.multiselect("Attack Type", sorted(list(all_attack_types)))
        
        with col2:
            selected_status = st.multiselect("Attack Status", ["success", "attempt"], default=["success", "attempt"])
            selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
        with col3:
            min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
            ip_filter = st.text_input("Source IP Filter", placeholder="192.168.1.100")
    
    # Apply filters
    filtered_attacks = st.session_state.attacks_db.copy()
    
    if selected_types:
        filtered_attacks = [a for a in filtered_attacks if any(t in a.get('final_attack_types', []) for t in selected_types)]
    
    if selected_status:
        filtered_attacks = [a for a in filtered_attacks if a.get('attack_status') in selected_status]
    
    if selected_severity:
        filtered_attacks = [a for a in filtered_attacks if a.get('severity') in selected_severity]
    
    if min_confidence > 0:
        filtered_attacks = [a for a in filtered_attacks if a.get('confidence', 0) >= min_confidence]
    
    if ip_filter:
        filtered_attacks = [a for a in filtered_attacks if ip_filter in a.get('source_ip', '')]
    
    st.markdown(f"### 📊 Showing {len(filtered_attacks)} of {len(st.session_state.attacks_db)} attacks")
    
    # Enhanced display
    if filtered_attacks:
        df = pd.DataFrame(filtered_attacks)
        
        # Create enhanced display dataframe
        display_df = pd.DataFrame({
            'Timestamp': df['timestamp'],
            'Source IP': df.get('source_ip', 'N/A'),
            'URL Preview': df['url'].str[:50] + '...',
            'Attempted Attacks': df['attempted_attacks'].apply(lambda x: ', '.join(x) if x else 'None'),
            'Successful Attacks': df['successful_attacks'].apply(lambda x: ', '.join(x) if x else 'None'),
            'Status': df['attack_status'].apply(lambda x: f"🔴 {x.upper()}" if x == 'success' else f"🟡 {x.upper()}"),
            'Severity': df['severity'],
            'Confidence': df['confidence'].apply(lambda x: f"{x}%")
        })
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Export functionality
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📥 Export Filtered Results (CSV)"):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"filtered_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📥 Export Filtered Results (JSON)"):
                json_data = df.to_json(orient='records', indent=2)
                st.download_button(
                    label="Download JSON", 
                    data=json_data,
                    file_name=f"filtered_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

def show_visualizations():
    """Enhanced visualizations page"""
    st.title("📊 Advanced Analytics & Visualizations")
    
    if not st.session_state.attacks_db:
        st.info("No data available for visualization. Analyze some URLs first.")
        return
    
    df = pd.DataFrame(st.session_state.attacks_db)
    
    # Enhanced timeline with success tracking
    st.subheader("📈 Attack Timeline with Success Tracking")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    timeline_df = df.groupby([df['timestamp'].dt.date, 'attack_status']).size().reset_index(name='count')
    timeline_df.columns = ['Date', 'Status', 'Attacks']
    
    fig = px.line(timeline_df, x='Date', y='Attacks', color='Status', 
                  color_discrete_map={'success': 'red', 'attempt': 'orange'},
                  markers=True)
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # Attack type distribution with success rate
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Attack Type Success Rate")
        attack_success = []
        for attack in st.session_state.attacks_db:
            for attack_type in attack.get('final_attack_types', []):
                attack_success.append({
                    'type': attack_type,
                    'success': attack.get('attack_status') == 'success'
                })
        
        if attack_success:
            success_df = pd.DataFrame(attack_success)
            success_rates = success_df.groupby('type')['success'].mean().reset_index()
            success_rates['success_rate'] = (success_rates['success'] * 100).round(1)
            
            fig = px.bar(success_rates, x='success_rate', y='type', orientation='h',
                        color='success_rate', color_continuous_scale='RdYlGn_r')
            fig.update_layout(height=400, xaxis_title="Success Rate (%)", yaxis_title="Attack Type")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ Severity vs Success Rate")
        severity_success = df.groupby('severity')['attack_status'].apply(
            lambda x: (x == 'success').mean() * 100
        ).reset_index(name='success_rate')
        
        fig = px.bar(severity_success, x='severity', y='success_rate',
                    color='success_rate', color_continuous_scale='Reds')
        fig.update_layout(height=400, yaxis_title="Success Rate (%)")
        st.plotly_chart(fig, use_container_width=True)
    
    # Source IP analysis
    st.subheader("🌐 Top Source IPs with Attacks")
    if 'source_ip' in df.columns:
        ip_counts = df['source_ip'].value_counts().head(10)
        ip_df = pd.DataFrame({'IP': ip_counts.index, 'Attacks': ip_counts.values})
        st.dataframe(ip_df, use_container_width=True, hide_index=True)

# Main Application
def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/clouds/200/security-checked.png", width=150)
        st.title("🛡️ Advanced Cyber Detector")
        st.markdown("---")
        
        # API Key Input
        api_key = st.text_input("🔑 Google Gemini API Key", type="password", value=st.session_state.api_key)
        
        # Model Selection
        selected_model = st.selectbox(
            "🤖 Gemini Model",
            options=GEMINI_MODELS,
            index=GEMINI_MODELS.index(st.session_state.gemini_model) if st.session_state.gemini_model in GEMINI_MODELS else 0
        )
        
        if api_key != st.session_state.api_key or selected_model != st.session_state.gemini_model:
            st.session_state.api_key = api_key
            if api_key:
                if configure_gemini(api_key, selected_model):
                    st.success(f"✅ API configured with {selected_model}!")
        
        st.markdown("---")
        
        # Navigation
        page = st.radio("Navigation", [
            "🏠 Enhanced Dashboard",
            "🔍 URL Analysis", 
            "📂 Bulk Analysis",
            "🗂️ Attack Database",
            "📊 Visualizations"
        ])
        
        st.markdown("---")
        
        # Performance Stats
        st.subheader("📈 Performance Stats")
        st.metric("Total Analyses", st.session_state.performance_stats['total_analyses'])
        st.metric("Successful Attacks", st.session_state.performance_stats['successful_attacks'])
        st.metric("AI Calls Saved", st.session_state.performance_stats['ai_calls_saved'])
        st.metric("Cache Hits", st.session_state.performance_stats['cache_hits'])
        
        st.markdown("---")
        st.info("💡 **Tip**: Use response analysis for accurate success detection!")
    
    # Main Content Routing
    if "Enhanced Dashboard" in page:
        show_enhanced_dashboard()
    elif "URL Analysis" in page:
        show_enhanced_url_analysis()
    elif "Bulk Analysis" in page:
        show_enhanced_bulk_analysis()
    elif "Attack Database" in page:
        show_enhanced_attack_database()
    elif "Visualizations" in page:
        show_visualizations()

if __name__ == "__main__":
    main()
