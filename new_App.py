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
from pymongo import MongoClient
import pymongo
import ipaddress
import csv
import struct

# Try to import PCAP libraries
try:
    from scapy.all import rdpcap, TCP, Raw, IP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.utils import RawPcapReader
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
    page_title="Cyber Attack Detection System",
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
    .attack-card {
        border-left: 4px solid #FF4444;
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
    .model-info {
        background-color: #f0f8ff;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.25rem 0;
        font-size: 0.85rem;
    }
    .success-attack {
        border-left: 4px solid #FF0000;
        background-color: #ffe6e6;
    }
    .attempt-attack {
        border-left: 4px solid #FFA500;
        background-color: #fff0e6;
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
if 'mongodb_connection' not in st.session_state:
    st.session_state.mongodb_connection = ""
if 'mongo_db' not in st.session_state:
    st.session_state.mongo_db = None
if 'attack_patterns_cache' not in st.session_state:
    st.session_state.attack_patterns_cache = None
if 'patterns_loaded' not in st.session_state:
    st.session_state.patterns_loaded = False
if 'secrets_configured' not in st.session_state:
    st.session_state.secrets_configured = False
if 'selected_model' not in st.session_state:
    st.session_state.selected_model = "gemini-2.0-flash"

# Define available Gemini models with their specifications
GEMINI_MODELS = {
    "gemini-2.0-flash": {
        "name": "Gemini 2.0 Flash",
        "rate_limit": 15,
        "context_window": 1000000,
        "daily_limit": 200,
        "description": "Fast and reliable model"
    },
    "gemini-1.5-flash": {
        "name": "Gemini 1.5 Flash",
        "rate_limit": 15,
        "context_window": 1000000,
        "daily_limit": 1500,
        "description": "Widely available and reliable"
    },
    "gemini-1.5-pro": {
        "name": "Gemini 1.5 Pro",
        "rate_limit": 2,
        "context_window": 2000000,
        "daily_limit": 50,
        "description": "High-quality reasoning with large context"
    }
}

# MongoDB Functions
@st.cache_resource
def connect_to_mongodb(connection_string):
    """Connect to MongoDB Atlas"""
    try:
        client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        db = client['cyber_attack_detection']
        return db
    except Exception as e:
        st.error(f"MongoDB Connection Error: {str(e)}")
        return None

def load_attack_patterns_from_db(db):
    """Load attack patterns from MongoDB"""
    try:
        collection = db['attack_patterns']
        patterns = {}
        
        for doc in collection.find({'active': True}):
            attack_id = doc.get('attack_id')
            patterns[attack_id] = {
                'category': doc.get('category'),
                'severity': doc.get('severity'),
                'patterns': doc.get('patterns', []),
                'mitigation': doc.get('mitigation', []),
                'success_indicators': doc.get('success_indicators', [])
            }
        
        return patterns
    except Exception as e:
        st.error(f"Error loading patterns from MongoDB: {str(e)}")
        return None

def save_detection_to_db(db, detection_record):
    """Save detection result to MongoDB"""
    try:
        collection = db['detection_results']
        detection_record['saved_at'] = datetime.now()
        collection.insert_one(detection_record)
        return True
    except Exception as e:
        st.error(f"Error saving to MongoDB: {str(e)}")
        return False

def get_detection_history_from_db(db, limit=1000):
    """Get detection history from MongoDB"""
    try:
        collection = db['detection_results']
        results = list(collection.find().sort('timestamp', pymongo.DESCENDING).limit(limit))
        
        # Convert ObjectId to string for JSON serialization
        for result in results:
            result['_id'] = str(result['_id'])
        
        return results
    except Exception as e:
        st.error(f"Error fetching history: {str(e)}")
        return []

# Gemini API Configuration
def configure_gemini(api_key):
    """Configure Google Gemini API"""
    try:
        genai.configure(api_key=api_key)
        return True
    except Exception as e:
        st.error(f"Error configuring Gemini API: {str(e)}")
        return False

# Initialize from secrets
def initialize_from_secrets():
    """Initialize MongoDB and Gemini from Streamlit secrets"""
    try:
        # Initialize MongoDB
        if 'mongodb_connection' in st.secrets:
            st.session_state.mongodb_connection = st.secrets.mongodb_connection
            with st.spinner("🔗 Connecting to MongoDB..."):
                db = connect_to_mongodb(st.session_state.mongodb_connection)
                if db is not None:
                    st.session_state.mongo_db = db
                    patterns = load_attack_patterns_from_db(db)
                    if patterns:
                        st.session_state.attack_patterns_cache = patterns
                        st.session_state.patterns_loaded = True
                        st.success(f"✅ Loaded {len(patterns)} attack patterns from MongoDB!")
                    else:
                        st.error("❌ Failed to load attack patterns from MongoDB")
                else:
                    st.error("❌ Failed to connect to MongoDB")
        
        # Initialize Gemini API
        if 'gemini_api_key' in st.secrets:
            st.session_state.api_key = st.secrets.gemini_api_key
            if st.session_state.api_key:
                if configure_gemini(st.session_state.api_key):
                    st.success("✅ Gemini API configured from secrets!")
                else:
                    st.error("❌ Failed to configure Gemini API")
        
        st.session_state.secrets_configured = True
        
    except Exception as e:
        st.error(f"Error initializing from secrets: {str(e)}")

# IP Address Functions
def extract_ip_from_url(url):
    """Extract IP addresses from URL"""
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, url)
    return ips[0] if ips else None

def is_ip_in_range(ip, ip_range):
    """Check if IP is within specified range"""
    try:
        if '/' in ip_range:
            # CIDR notation
            network = ipaddress.ip_network(ip_range, strict=False)
            return ipaddress.ip_address(ip) in network
        elif '-' in ip_range:
            # IP range like 192.168.1.1-192.168.1.100
            start_ip, end_ip = ip_range.split('-')
            return ipaddress.ip_address(start_ip.strip()) <= ipaddress.ip_address(ip) <= ipaddress.ip_address(end_ip.strip())
        else:
            # Single IP
            return ip == ip_range
    except:
        return False

def get_ip_info(ip):
    """Get basic IP information"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return {
            'ip': ip,
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_global': ip_obj.is_global,
            'is_multicast': ip_obj.is_multicast
        }
    except:
        return {'ip': ip, 'version': 'unknown'}

# Attack Detection Functions
def detect_attack_with_patterns(url, attack_id, patterns_data):
    """Generic attack detection using MongoDB patterns"""
    indicators = []
    
    if not patterns_data or attack_id not in patterns_data:
        return False, []
    
    attack_patterns = patterns_data[attack_id]['patterns']
    
    for pattern_obj in attack_patterns:
        pattern = pattern_obj.get('regex', '')
        description = pattern_obj.get('description', '')
        
        try:
            if re.search(pattern, url, re.IGNORECASE):
                indicators.append(description)
        except re.error:
            continue
    
    return len(indicators) > 0, indicators

def detect_attack_success(url, response_content, attack_types, patterns_data):
    """Determine if attack was successful based on response patterns"""
    success_indicators = []
    is_successful = False
    
    for attack_type in attack_types:
        for attack_id, info in patterns_data.items():
            if info['category'] == attack_type and 'success_indicators' in info:
                for indicator in info['success_indicators']:
                    pattern = indicator.get('regex', '')
                    description = indicator.get('description', '')
                    try:
                        if response_content and re.search(pattern, response_content, re.IGNORECASE):
                            success_indicators.append(description)
                            is_successful = True
                    except re.error:
                        continue
    
    return is_successful, success_indicators

def quick_detection(url, patterns_data):
    """Quick pattern-based detection using MongoDB patterns"""
    if not patterns_data:
        st.warning("⚠️ Attack patterns not loaded. Please check MongoDB connection in secrets.")
        return [], []
    
    results = {}
    detected_attacks = []
    all_indicators = []
    
    for attack_id, attack_info in patterns_data.items():
        detected, indicators = detect_attack_with_patterns(url, attack_id, patterns_data)
        if detected:
            category = attack_info['category']
            detected_attacks.append(category)
            all_indicators.extend(indicators)
    
    return detected_attacks, all_indicators

def analyze_with_gemini(url, quick_results, response_content=None):
    """Analyze URL with Google Gemini API"""
    if not st.session_state.api_key:
        return None
    
    try:
        # Use the selected model
        model = genai.GenerativeModel(st.session_state.selected_model)
        
        response_info = f"Response content: {response_content[:500]}..." if response_content else "No response content available"
        
        prompt = f"""As a cybersecurity expert, analyze this URL for potential attacks:

URL: {url}

Pre-detected patterns: {', '.join(quick_results) if quick_results else 'None'}
{response_info}

Determine if the attack was successful and provide response in this exact JSON format:
{{
    "is_malicious": true/false,
    "attack_types": ["type1", "type2"],
    "confidence": 0-100,
    "severity": "LOW/MEDIUM/HIGH/CRITICAL",
    "is_successful": true/false,
    "explanation": "brief technical explanation",
    "recommendations": ["recommendation1", "recommendation2"]
}}

Important: Return ONLY the JSON object, no additional text."""

        response = model.generate_content(prompt)
        
        # Extract JSON from response
        text = response.text
        text = re.sub(r'```json\n?', '', text)
        text = re.sub(r'```\n?', '', text)
        text = text.strip()
        
        # Try to find JSON in the response
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            result = json.loads(json_match.group())
            return result
        else:
            # If no JSON found, try to parse the entire response
            result = json.loads(text)
            return result
    
    except json.JSONDecodeError as e:
        st.error(f"Gemini API Response Parsing Error: {str(e)}")
        return None
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
    high_attacks = ['XSS', 'Cross-Site Scripting', 'SSRF', 'LFI/RFI', 'Path Traversal', 'Local/Remote File Inclusion']
    
    for attack in attack_types:
        if any(critical in attack for critical in critical_attacks):
            return "CRITICAL"
    
    for attack in attack_types:
        if any(high in attack for high in high_attacks):
            return "HIGH"
    
    if len(attack_types) > 0:
        return "MEDIUM"
    
    return "LOW"

# Enhanced PCAP Parsing Functions - FIXED VERSION
def parse_pcap_simple_scapy(pcap_file):
    """Simple PCAP parsing using Scapy - handles various file formats"""
    urls = []
    try:
        # Save uploaded file temporarily
        temp_path = f"/tmp/{pcap_file.name}"
        with open(temp_path, "wb") as f:
            f.write(pcap_file.getvalue())
        
        # Use RawPcapReader for better format handling
        packets = rdpcap(temp_path)
        
        for packet in packets:
            try:
                # Check for IP and TCP layers
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    # Look for HTTP traffic on common ports
                    if packet[TCP].dport in [80, 443, 8080, 8000] or packet[TCP].sport in [80, 443, 8080, 8000]:
                        if packet.haslayer(Raw):
                            payload = packet[Raw].load
                            try:
                                payload_str = payload.decode('utf-8', errors='ignore')
                                
                                # Look for HTTP requests
                                if payload_str.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                                    lines = payload_str.split('\r\n')
                                    if lines:
                                        request_line = lines[0]
                                        parts = request_line.split()
                                        if len(parts) >= 2:
                                            method = parts[0]
                                            path = parts[1]
                                            
                                            # Extract host from headers
                                            host = ""
                                            for line in lines[1:]:
                                                if line.lower().startswith('host:'):
                                                    host = line.split(':', 1)[1].strip()
                                                    break
                                            
                                            if host:
                                                # Determine protocol
                                                protocol = "https" if packet[TCP].dport == 443 or packet[TCP].sport == 443 else "http"
                                                url = f"{protocol}://{host}{path}"
                                                
                                                url_info = {
                                                    'url': url,
                                                    'method': method,
                                                    'src_ip': packet[IP].src,
                                                    'dst_ip': packet[IP].dst,
                                                    'src_port': packet[TCP].sport,
                                                    'dst_port': packet[TCP].dport,
                                                    'timestamp': datetime.fromtimestamp(float(packet.time)),
                                                    'raw_payload': payload_str[:1000]  # Store first 1000 chars
                                                }
                                                urls.append(url_info)
                            except Exception as e:
                                continue
            except Exception as e:
                continue
                
        return urls
    except Exception as e:
        st.error(f"Error parsing PCAP with Scapy: {str(e)}")
        return []

def parse_pcap_simple_dpkt(pcap_file):
    """Simple PCAP parsing using dpkt - handles various file formats"""
    urls = []
    try:
        pcap_file.seek(0)
        pcap_data = pcap_file.read()
        
        # Try different pcap formats
        try:
            pcap = dpkt.pcap.Reader(io.BytesIO(pcap_data))
        except ValueError:
            # Try pcapng format
            try:
                pcap = dpkt.pcapng.Reader(io.BytesIO(pcap_data))
            except ValueError as e:
                st.error(f"Unsupported PCAP format: {e}")
                return urls
        
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                
                tcp = ip.data
                
                # Check for HTTP on common ports
                if tcp.dport in [80, 443, 8080, 8000] or tcp.sport in [80, 443, 8080, 8000]:
                    if len(tcp.data) > 0:
                        try:
                            payload = tcp.data.decode('utf-8', errors='ignore')
                            
                            # Look for HTTP requests
                            if payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                                lines = payload.split('\r\n')
                                if lines:
                                    request_line = lines[0]
                                    parts = request_line.split()
                                    if len(parts) >= 2:
                                        method = parts[0]
                                        path = parts[1]
                                        
                                        # Extract host from headers
                                        host = ""
                                        for line in lines[1:]:
                                            if line.lower().startswith('host:'):
                                                host = line.split(':', 1)[1].strip()
                                                break
                                        
                                        if host:
                                            # Determine protocol
                                            protocol = "https" if tcp.dport == 443 or tcp.sport == 443 else "http"
                                            url = f"{protocol}://{host}{path}"
                                            
                                            url_info = {
                                                'url': url,
                                                'method': method,
                                                'src_ip': dpkt.utils.inet_to_str(ip.src),
                                                'dst_ip': dpkt.utils.inet_to_str(ip.dst),
                                                'src_port': tcp.sport,
                                                'dst_port': tcp.dport,
                                                'timestamp': datetime.fromtimestamp(timestamp),
                                                'raw_payload': payload[:1000]  # Store first 1000 chars
                                            }
                                            urls.append(url_info)
                        except Exception as e:
                            continue
            except Exception as e:
                continue
                
        return urls
    except Exception as e:
        st.error(f"Error parsing PCAP with dpkt: {str(e)}")
        return []

def parse_pcap_manual(uploaded_file):
    """Manual PCAP parsing as last resort"""
    urls = []
    try:
        uploaded_file.seek(0)
        data = uploaded_file.read()
        
        # Look for HTTP patterns in raw data
        http_patterns = [
            rb'GET /[^\s]* HTTP/1\.[01]',
            rb'POST /[^\s]* HTTP/1\.[01]', 
            rb'PUT /[^\s]* HTTP/1\.[01]',
            rb'DELETE /[^\s]* HTTP/1\.[01]',
            rb'HEAD /[^\s]* HTTP/1\.[01]'
        ]
        
        for pattern in http_patterns:
            matches = re.findall(pattern, data)
            for match in matches:
                try:
                    match_str = match.decode('utf-8', errors='ignore')
                    parts = match_str.split()
                    if len(parts) >= 2:
                        method = parts[0]
                        path = parts[1]
                        
                        # Look for host in nearby data
                        host_match = re.search(rb'Host: ([^\r\n]+)', data[data.find(match):data.find(match)+1000])
                        if host_match:
                            host = host_match.group(1).decode('utf-8', errors='ignore').strip()
                            url = f"http://{host}{path}"
                            
                            url_info = {
                                'url': url,
                                'method': method,
                                'src_ip': 'Unknown',
                                'dst_ip': 'Unknown', 
                                'src_port': 0,
                                'dst_port': 0,
                                'timestamp': datetime.now(),
                                'raw_payload': match_str
                            }
                            urls.append(url_info)
                except:
                    continue
        
        if urls:
            st.info(f"🔍 Manual extraction found {len(urls)} URLs")
        
    except Exception as e:
        st.error(f"Manual PCAP parsing failed: {str(e)}")
    
    return urls

def parse_pcap_file_robust(uploaded_file):
    """Robust PCAP parsing that handles various formats and errors"""
    urls = []
    
    st.info("🔄 Attempting to parse PCAP file...")
    
    # Try Scapy first
    if PCAP_SUPPORT:
        with st.spinner("Trying Scapy parser..."):
            try:
                urls = parse_pcap_simple_scapy(uploaded_file)
                if urls:
                    st.success(f"✅ Scapy extracted {len(urls)} URLs")
                    return urls
            except Exception as e:
                st.warning(f"Scapy parser failed: {str(e)}")
    
    # Try dpkt if Scapy fails
    if not urls and DPKT_SUPPORT:
        with st.spinner("Trying dpkt parser..."):
            try:
                urls = parse_pcap_simple_dpkt(uploaded_file)
                if urls:
                    st.success(f"✅ dpkt extracted {len(urls)} URLs")
                    return urls
            except Exception as e:
                st.warning(f"dpkt parser failed: {str(e)}")
    
    # If both fail, try manual parsing as last resort
    if not urls:
        urls = parse_pcap_manual(uploaded_file)
    
    if not urls:
        st.warning("❌ No HTTP URLs found in PCAP file. The file might be:")
        st.warning("- Encrypted traffic (HTTPS)")
        st.warning("- Non-HTTP protocol")
        st.warning("- Corrupted or invalid PCAP format")
        st.warning("- Empty or very small file")
    
    return urls

# Export Functions
def export_to_csv(data, filename):
    """Export data to CSV format"""
    if not data:
        return None
    
    output = io.StringIO()
    
    if isinstance(data, pd.DataFrame):
        data.to_csv(output, index=False)
    else:
        # Convert list of dictionaries to CSV
        if data and isinstance(data[0], dict):
            fieldnames = data[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        else:
            return None
    
    return output.getvalue()

def export_to_json(data, filename):
    """Export data to JSON format"""
    if isinstance(data, pd.DataFrame):
        return data.to_json(orient='records', indent=2)
    else:
        return json.dumps(data, indent=2, default=str)

# Main Application
def main():
    # Initialize from secrets on first run
    if not st.session_state.secrets_configured:
        initialize_from_secrets()
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/clouds/200/security-checked.png", width=150)
        st.title("🛡️ Cyber Attack Detector")
        st.markdown("---")
        
        # Configuration Status
        st.subheader("⚙️ Configuration Status")
        
        if st.session_state.patterns_loaded:
            st.success("✅ MongoDB Connected")
            st.info(f"📊 {len(st.session_state.attack_patterns_cache)} attack patterns loaded")
        else:
            st.error("❌ MongoDB Not Configured")
            st.info("💡 Add MongoDB connection string to Streamlit secrets")
        
        if st.session_state.api_key:
            st.success("✅ Gemini API Configured")
        else:
            st.warning("⚠️ Gemini API Not Configured")
            st.info("💡 Add Gemini API key to Streamlit secrets")
        
        st.markdown("---")
        
        # Gemini Model Selection
        st.subheader("🤖 Gemini Model Selection")
        
        # Model selection with detailed info
        model_options = list(GEMINI_MODELS.keys())
        model_display_names = [f"{GEMINI_MODELS[model]['name']} ({model})" for model in model_options]
        
        selected_model_display = st.selectbox(
            "Select Model",
            options=model_display_names,
            index=model_display_names.index(f"{GEMINI_MODELS[st.session_state.selected_model]['name']} ({st.session_state.selected_model})")
        )
        
        # Extract model ID from display name
        selected_model_id = model_options[model_display_names.index(selected_model_display)]
        
        if selected_model_id != st.session_state.selected_model:
            st.session_state.selected_model = selected_model_id
            st.rerun()
        
        # Display model specifications
        model_info = GEMINI_MODELS[st.session_state.selected_model]
        st.markdown(f"""
        <div class="model-info">
        <strong>📊 Model Specifications:</strong><br>
        • Rate Limit: {model_info['rate_limit']} RPM<br>
        • Context: {model_info['context_window']:,} tokens<br>
        • Daily Limit: {model_info['daily_limit']} requests<br>
        • Description: {model_info['description']}
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Navigation
        page = st.radio("Navigation", [
            "🏠 Dashboard",
            "🔍 URL Analysis", 
            "📂 Bulk Analysis",
            "🗂️ Attack Database",
            "📊 Visualizations"
        ])
        
        st.markdown("---")
        
        # Stats
        if st.session_state.attacks_db:
            total_attacks = len(st.session_state.attacks_db)
            successful_attacks = len([a for a in st.session_state.attacks_db if a.get('is_successful')])
            critical_count = len([a for a in st.session_state.attacks_db if a.get('severity') == 'CRITICAL'])
            
            st.metric("Total Attacks", total_attacks)
            st.metric("Successful Attacks", successful_attacks)
            st.metric("Critical Threats", critical_count)
    
    # Main Content
    if "Dashboard" in page:
        show_dashboard()
    elif "URL Analysis" in page:
        show_url_analysis()
    elif "Bulk Analysis" in page:
        show_bulk_analysis()
    elif "Attack Database" in page:
        show_attack_database()
    elif "Visualizations" in page:
        show_visualizations()

def show_dashboard():
    """Dashboard page"""
    st.markdown('<p class="main-header">🛡️ Cyber Attack Detection System</p>', unsafe_allow_html=True)
    st.markdown("### AI-Powered URL Analysis with MongoDB & Gemini")
    
    # Check MongoDB connection
    if not st.session_state.patterns_loaded:
        st.error("❌ MongoDB not configured. Please add MongoDB connection string to Streamlit secrets.")
        st.info("""
        **To configure Streamlit secrets:**
        
        1. Create a `.streamlit/secrets.toml` file in your project directory
        2. Add the following configuration:
        ```
        mongodb_connection = "your_mongodb_connection_string"
        gemini_api_key = "your_gemini_api_key"
        ```
        3. Restart the application
        """)
        return
    
    # Display current model info
    current_model = GEMINI_MODELS[st.session_state.selected_model]
    st.info(f"🤖 **Current Model**: {current_model['name']} | 📊 **Context**: {current_model['context_window']:,} tokens | ⚡ **Rate Limit**: {current_model['rate_limit']} RPM")
    
    # Stats Cards
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_analyzed = len(st.session_state.analysis_history)
    total_attacks = len(st.session_state.attacks_db)
    successful_attacks = len([a for a in st.session_state.attacks_db if a.get('is_successful')])
    attempted_attacks = total_attacks - successful_attacks
    critical_count = len([a for a in st.session_state.attacks_db if a.get('severity') == 'CRITICAL'])
    
    with col1:
        st.metric("📊 Total Analyzed", total_analyzed)
    
    with col2:
        st.metric("⚠️ Attacks Detected", total_attacks)
    
    with col3:
        st.metric("✅ Successful", successful_attacks)
    
    with col4:
        st.metric("🔄 Attempted", attempted_attacks)
    
    with col5:
        st.metric("🔴 Critical", critical_count)
    
    st.markdown("---")
    
    # Recent Activity
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Attack Distribution")
        if st.session_state.attacks_db:
            attack_types = []
            for attack in st.session_state.attacks_db:
                attack_types.extend(attack.get('attack_types', []))
            
            if attack_types:
                type_counts = Counter(attack_types)
                df = pd.DataFrame(list(type_counts.items()), columns=['Attack Type', 'Count'])
                fig = px.pie(df, values='Count', names='Attack Type', hole=0.4)
                fig.update_layout(height=350)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No attacks detected yet")
        else:
            st.info("No attacks detected yet")
    
    with col2:
        st.subheader("🎯 Success vs Attempt")
        if st.session_state.attacks_db:
            success_data = {
                'Status': ['Successful', 'Attempted'],
                'Count': [successful_attacks, attempted_attacks]
            }
            df = pd.DataFrame(success_data)
            colors = ['#FF4444', '#FFA500']
            fig = px.pie(df, values='Count', names='Status', color='Status',
                        color_discrete_map={'Successful': '#FF4444', 'Attempted': '#FFA500'})
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack data available")
    
    # Recent Attacks Table
    st.subheader("🕐 Recent Detections")
    if st.session_state.attacks_db:
        recent = st.session_state.attacks_db[-10:][::-1]
        
        df = pd.DataFrame(recent)
        if not df.empty:
            display_df = pd.DataFrame({
                'Timestamp': df['timestamp'],
                'URL (Preview)': df['url'].str[:50] + '...',
                'Attack Types': df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x),
                'Severity': df['severity'],
                'Status': df['is_successful'].apply(lambda x: '✅ Success' if x else '🔄 Attempt'),
                'Confidence': df['confidence'].apply(lambda x: f"{x}%"),
                'Source IP': df.get('src_ip', 'N/A')
            })
            st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No detections yet. Start analyzing URLs!")
    
    # Display loaded attack patterns info
    if st.session_state.attack_patterns_cache:
        st.markdown("---")
        st.subheader("🔍 Loaded Attack Patterns")
        patterns_info = []
        for attack_id, info in st.session_state.attack_patterns_cache.items():
            patterns_info.append({
                'Category': info['category'],
                'Severity': info['severity'],
                'Patterns Count': len(info['patterns']),
                'Success Indicators': len(info.get('success_indicators', []))
            })
        
        patterns_df = pd.DataFrame(patterns_info)
        st.dataframe(patterns_df, use_container_width=True, hide_index=True)

def show_url_analysis():
    """URL Analysis page"""
    st.title("🔍 Single URL Analysis")
    st.markdown("Enter a URL or HTTP request to analyze for potential cyber attacks")
    
    if not st.session_state.patterns_loaded:
        st.error("❌ MongoDB not configured. Please add MongoDB connection string to Streamlit secrets.")
        return
    
    # Display current model info
    current_model = GEMINI_MODELS[st.session_state.selected_model]
    st.info(f"🤖 **Current Model**: {current_model['name']} | 📊 **Context**: {current_model['context_window']:,} tokens")
    
    # Input
    col1, col2 = st.columns(2)
    
    with col1:
        url_input = st.text_area(
            "URL or HTTP Request",
            placeholder="http://example.com/page?id=1' OR '1'='1\n\nExample attacks:\n- SQL: /page?id=1' UNION SELECT * FROM users--\n- XSS: /search?q=<script>alert(1)</script>\n- Path Traversal: /file?path=../../etc/passwd",
            height=150
        )
    
    with col2:
        response_input = st.text_area(
            "HTTP Response (Optional)",
            placeholder="Paste HTTP response content to determine attack success...",
            height=150,
            help="Provide response content to analyze if the attack was successful"
        )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)
    with col2:
        use_gemini = st.checkbox("Use Gemini AI for deep analysis", value=True, disabled=not st.session_state.api_key)
        if not st.session_state.api_key:
            st.info("💡 Configure Gemini API key in Streamlit secrets for AI-powered analysis")
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL..."):
            # Extract IP information
            src_ip = extract_ip_from_url(url_input)
            ip_info = get_ip_info(src_ip) if src_ip else {}
            
            # Quick detection using MongoDB patterns
            quick_attacks, quick_indicators = quick_detection(url_input, st.session_state.attack_patterns_cache)
            
            # Determine success based on response content
            is_successful = False
            success_indicators = []
            if response_input and quick_attacks:
                is_successful, success_indicators = detect_attack_success(
                    url_input, response_input, quick_attacks, st.session_state.attack_patterns_cache
                )
            
            # Gemini analysis
            gemini_result = None
            if use_gemini and st.session_state.api_key:
                with st.spinner(f"🤖 Running {current_model['name']} analysis..."):
                    gemini_result = analyze_with_gemini(url_input, quick_attacks, response_input)
            
            # Combine results
            if gemini_result:
                attack_types = gemini_result.get('attack_types', quick_attacks)
                confidence = gemini_result.get('confidence', 0)
                severity = gemini_result.get('severity', determine_severity(attack_types))
                explanation = gemini_result.get('explanation', '')
                recommendations = gemini_result.get('recommendations', [])
                is_malicious = gemini_result.get('is_malicious', len(attack_types) > 0)
                gemini_success = gemini_result.get('is_successful', is_successful)
                
                # Use Gemini's success determination if available, otherwise use pattern-based
                final_success = gemini_success if 'is_successful' in gemini_result else is_successful
            else:
                attack_types = quick_attacks
                confidence = calculate_confidence(quick_indicators, None)
                severity = determine_severity(attack_types)
                explanation = "Pattern-based detection using MongoDB patterns"
                recommendations = []
                is_malicious = len(attack_types) > 0
                final_success = is_successful
            
            # Get mitigation recommendations from MongoDB
            if is_malicious and attack_types:
                for attack_type in attack_types:
                    for attack_id, info in st.session_state.attack_patterns_cache.items():
                        if info['category'] == attack_type:
                            recommendations.extend(info.get('mitigation', []))
                            break
            
            # Store in history
            analysis_record = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'url': url_input,
                'attack_types': attack_types,
                'confidence': confidence,
                'severity': severity,
                'is_malicious': is_malicious,
                'is_successful': final_success,
                'indicators': quick_indicators,
                'success_indicators': success_indicators,
                'explanation': explanation,
                'recommendations': list(set(recommendations)),  # Remove duplicates
                'model_used': st.session_state.selected_model if use_gemini and st.session_state.api_key else "pattern_only",
                'src_ip': src_ip,
                'ip_info': ip_info,
                'has_response': bool(response_input)
            }
            
            st.session_state.analysis_history.append(analysis_record)
            
            if is_malicious:
                st.session_state.attacks_db.append(analysis_record)
                
                # Save to MongoDB
                if st.session_state.mongo_db is not None:
                    save_detection_to_db(st.session_state.mongo_db, analysis_record.copy())
            
            # Display Results
            st.markdown("---")
            st.subheader("📊 Analysis Results")
            
            if is_malicious:
                card_class = "success-attack" if final_success else "attempt-attack"
                status_text = "SUCCESSFUL" if final_success else "ATTEMPTED"
                status_icon = "✅" if final_success else "🔄"
                
                st.markdown(f'<div class="attack-card {card_class}">', unsafe_allow_html=True)
                st.error(f"⚠️ **{status_icon} {status_text} ATTACK DETECTED!**")
                st.markdown('</div>', unsafe_allow_html=True)
                
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Confidence Score", f"{confidence}%")
                with col2:
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(severity, '⚪')
                    st.metric("Severity", f"{severity_color} {severity}")
                with col3:
                    st.metric("Attack Types", len(attack_types))
                with col4:
                    st.metric("Status", f"{status_icon} {status_text}")
                
                # IP Information
                if src_ip:
                    st.subheader("🌐 IP Information")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.info(f"**Source IP**: {src_ip}")
                    with col2:
                        st.info(f"**IP Version**: IPv{ip_info.get('version', 'N/A')}")
                    with col3:
                        st.info(f"**Type**: {'Private' if ip_info.get('is_private') else 'Public'}")
                
                # Attack Types
                st.subheader("🎯 Detected Attack Types")
                for attack in attack_types:
                    st.markdown(f"- **{attack}**")
                
                # Indicators
                if quick_indicators:
                    st.subheader("🔍 Technical Indicators")
                    for indicator in quick_indicators:
                        st.markdown(f"- {indicator}")
                
                # Success Indicators
                if final_success and success_indicators:
                    st.subheader("✅ Success Indicators")
                    for indicator in success_indicators:
                        st.markdown(f"- 🎯 {indicator}")
                
                # Explanation
                if explanation:
                    st.subheader("📝 Detailed Analysis")
                    st.info(explanation)
                
                # Recommendations
                if recommendations:
                    st.subheader("💡 Security Recommendations")
                    for rec in recommendations[:5]:  # Show top 5
                        st.markdown(f"- {rec}")
                
            else:
                st.markdown(f'<div class="safe-card">', unsafe_allow_html=True)
                st.success("✅ **NO THREATS DETECTED**")
                st.markdown('</div>', unsafe_allow_html=True)
                
                st.info("The URL appears to be safe based on pattern analysis.")

def show_bulk_analysis():
    """Bulk Analysis page"""
    st.title("📂 Bulk Traffic Analysis")
    st.markdown("Upload PCAP, CSV, JSON, or TXT files for batch analysis")
    
    if not st.session_state.patterns_loaded:
        st.error("❌ MongoDB not configured. Please add MongoDB connection string to Streamlit secrets.")
        return
    
    # Display current model info
    current_model = GEMINI_MODELS[st.session_state.selected_model]
    st.info(f"🤖 **Current Model**: {current_model['name']} | ⚡ **Rate Limit**: {current_model['rate_limit']} RPM")
    
    # Show PCAP support status
    if PCAP_SUPPORT or DPKT_SUPPORT:
        pcap_libs = []
        if PCAP_SUPPORT:
            pcap_libs.append("Scapy")
        if DPKT_SUPPORT:
            pcap_libs.append("dpkt")
        st.success(f"✅ PCAP support enabled ({', '.join(pcap_libs)})")
    else:
        st.warning("⚠️ PCAP support disabled. Install scapy or dpkt for PCAP analysis.")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=['pcap', 'pcapng', 'csv', 'json', 'txt'],
        help="Supported formats: PCAP, PCAPNG, CSV, JSON, TXT"
    )
    
    # Analysis options
    with st.expander("⚙️ Analysis Options", expanded=True):
        use_ai = st.checkbox("Enable Gemini AI Analysis", value=False, disabled=not st.session_state.api_key)
        if not st.session_state.api_key:
            st.info("💡 AI analysis disabled without API key in secrets (pattern-based detection will still work)")
        
        if use_ai and st.session_state.api_key:
            st.warning(f"⚠️ Using {current_model['name']} with rate limit of {current_model['rate_limit']} RPM. Large files may take time.")
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: {uploaded_file.name} ({uploaded_file.size / 1024:.2f} KB)")
        
        if st.button("🚀 Start Analysis", type="primary"):
            with st.spinner("Processing file..."):
                try:
                    url_data = []
                    
                    # Read file based on type
                    if uploaded_file.name.endswith(('.pcap', '.pcapng')):
                        if PCAP_SUPPORT or DPKT_SUPPORT:
                            url_data = parse_pcap_file_robust(uploaded_file)
                            if url_data:
                                st.success(f"📊 Successfully extracted {len(url_data)} URLs from PCAP")
                            else:
                                st.error("❌ Failed to extract URLs from PCAP file")
                                return
                        else:
                            st.error("PCAP parsing requires scapy or dpkt.")
                            return
                    
                    elif uploaded_file.name.endswith('.csv'):
                        df = pd.read_csv(uploaded_file)
                        st.info(f"📊 Loaded {len(df)} rows from CSV")
                        
                        url_columns = [col for col in df.columns if 'url' in col.lower()]
                        if url_columns:
                            # Convert to list of dictionaries for consistent processing
                            urls = df[url_columns[0]].dropna().tolist()
                            url_data = [{'url': url} for url in urls]
                        else:
                            st.error("CSV must contain a URL column")
                            return
                    
                    elif uploaded_file.name.endswith('.json'):
                        data = json.load(uploaded_file)
                        if isinstance(data, list):
                            # Try to find URL fields
                            url_data = []
                            for item in data:
                                if isinstance(item, dict):
                                    for key, value in item.items():
                                        if 'url' in key.lower() and isinstance(value, str):
                                            url_data.append({'url': value})
                                            break
                        else:
                            url = data.get('url', '')
                            url_data = [{'url': url}] if url else []
                        st.info(f"📊 Loaded {len(url_data)} URLs from JSON")
                    
                    elif uploaded_file.name.endswith('.txt'):
                        content = uploaded_file.read().decode('utf-8')
                        urls = [line.strip() for line in content.split('\n') if line.strip() and line.startswith('http')]
                        url_data = [{'url': url} for url in urls]
                        st.info(f"📊 Loaded {len(url_data)} URLs from text file")
                    
                    if not url_data:
                        st.warning("No URLs found in file")
                        return
                    
                    # Remove duplicate URLs (extract URL strings for deduplication)
                    unique_urls = {}
                    for item in url_data:
                        url = item['url']
                        if url not in unique_urls:
                            unique_urls[url] = item
                    
                    url_data = list(unique_urls.values())
                    st.info(f"🔍 Analyzing {len(url_data)} unique URLs...")
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    results = []
                    
                    for idx, item in enumerate(url_data):
                        url = item['url']
                        status_text.text(f"Analyzing {idx + 1}/{len(url_data)}: {url[:50]}...")
                        
                        # Extract IP information
                        src_ip = extract_ip_from_url(url)
                        ip_info = get_ip_info(src_ip) if src_ip else {}
                        
                        quick_attacks, quick_indicators = quick_detection(url, st.session_state.attack_patterns_cache)
                        
                        if use_ai and st.session_state.api_key and quick_attacks:
                            gemini_result = analyze_with_gemini(url, quick_attacks)
                            if gemini_result:
                                attack_types = gemini_result.get('attack_types', quick_attacks)
                                confidence = gemini_result.get('confidence', 0)
                                severity = gemini_result.get('severity', determine_severity(attack_types))
                                gemini_success = gemini_result.get('is_successful', False)
                                final_success = gemini_success if 'is_successful' in gemini_result else False
                            else:
                                attack_types = quick_attacks
                                confidence = calculate_confidence(quick_indicators, None)
                                severity = determine_severity(attack_types)
                                final_success = False
                        else:
                            attack_types = quick_attacks
                            confidence = calculate_confidence(quick_indicators, None)
                            severity = determine_severity(attack_types)
                            final_success = False
                        
                        if attack_types:
                            result = {
                                'url': url,
                                'attack_types': attack_types,
                                'confidence': confidence,
                                'severity': severity,
                                'is_successful': final_success,
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'model_used': st.session_state.selected_model if use_ai and st.session_state.api_key else "pattern_only",
                                'src_ip': src_ip,
                                'ip_info': ip_info
                            }
                            
                            # Add additional PCAP data if available
                            if 'src_ip' in item and item['src_ip'] != 'Unknown':
                                result.update({
                                    'src_ip': item.get('src_ip'),
                                    'dst_ip': item.get('dst_ip'),
                                    'method': item.get('method'),
                                    'src_port': item.get('src_port'),
                                    'dst_port': item.get('dst_port')
                                })
                            
                            results.append(result)
                            st.session_state.attacks_db.append(result)
                            
                            # Save to MongoDB
                            if st.session_state.mongo_db is not None:
                                save_detection_to_db(st.session_state.mongo_db, result.copy())
                        
                        progress_bar.progress((idx + 1) / len(url_data))
                    
                    status_text.text("✅ Analysis complete!")
                    
                    # Display results
                    if results:
                        st.success(f"🎯 Found {len(results)} potential attacks out of {len(url_data)} URLs")
                        
                        # Summary statistics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total Threats", len(results))
                        with col2:
                            successful = len([r for r in results if r['is_successful']])
                            st.metric("Successful", successful)
                        with col3:
                            critical = len([r for r in results if r['severity'] == 'CRITICAL'])
                            st.metric("Critical", critical)
                        with col4:
                            avg_conf = sum(r['confidence'] for r in results) / len(results)
                            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
                        
                        # Results table
                        results_df = pd.DataFrame(results)
                        results_df['attack_types'] = results_df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
                        results_df['status'] = results_df['is_successful'].apply(lambda x: '✅ Success' if x else '🔄 Attempt')
                        
                        display_df = results_df.copy()
                        display_columns = ['timestamp', 'url', 'attack_types', 'severity', 'status', 'confidence']
                        if 'src_ip' in results_df.columns:
                            display_columns.append('src_ip')
                        
                        display_df = display_df[display_columns]
                        display_df['url'] = display_df['url'].str[:80] + '...'
                        display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x}%")
                        
                        st.dataframe(display_df, use_container_width=True)
                        
                        # Export options
                        st.subheader("📤 Export Results")
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            # CSV Export
                            csv_data = export_to_csv(results_df, "attack_results.csv")
                            st.download_button(
                                label="📥 Download Results (CSV)",
                                data=csv_data,
                                file_name=f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                        
                        with col2:
                            # JSON Export
                            json_data = export_to_json(results_df, "attack_results.json")
                            st.download_button(
                                label="📥 Download Results (JSON)",
                                data=json_data,
                                file_name=f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                mime="application/json"
                            )
                    else:
                        st.success("✅ No attacks detected. All URLs appear safe!")
                
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())

# ... (The show_attack_database and show_visualizations functions remain the same as in the previous code)

def show_attack_database():
    """Attack Database page"""
    st.title("🗂️ Attack Database")
    st.markdown("Query and filter detected attacks with advanced filtering options")
    
    # Option to load from MongoDB or session
    col1, col2 = st.columns([3, 1])
    with col1:
        data_source = st.radio("Data Source", ["Session Data", "MongoDB History"], horizontal=True)
    with col2:
        if st.button("🔄 Refresh"):
            st.rerun()
    
    # Load data based on source
    if data_source == "MongoDB History" and st.session_state.mongo_db is not None:
        with st.spinner("Loading from MongoDB..."):
            attacks_data = get_detection_history_from_db(st.session_state.mongo_db, limit=1000)
            if not attacks_data:
                st.info("No attacks in MongoDB database yet.")
                return
    else:
        attacks_data = st.session_state.attacks_db
        if not attacks_data:
            st.info("No attacks in session database yet. Analyze some URLs to populate.")
            return
    
    # Advanced Filters
    with st.expander("🔍 Advanced Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            # Attack Type Filter
            all_attack_types = set()
            for attack in attacks_data:
                all_attack_types.update(attack.get('attack_types', []))
            
            selected_types = st.multiselect("Attack Type", sorted(list(all_attack_types)))
        
        with col2:
            # Severity Filter
            selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
        with col3:
            # Status Filter
            status_options = ["All", "Successful", "Attempted"]
            selected_status = st.selectbox("Attack Status", status_options)
        
        with col4:
            # Confidence Filter
            min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
        
        # IP Range Filter
        col1, col2 = st.columns(2)
        with col1:
            ip_filter = st.text_input("IP Address/Range Filter", 
                                    placeholder="192.168.1.1 or 192.168.1.0/24 or 192.168.1.1-192.168.1.100")
        
        with col2:
            ip_filter_type = st.selectbox("IP Filter Type", ["Source IP", "Destination IP", "Any IP"])
    
    # Apply filters
    filtered_attacks = attacks_data.copy()
    
    if selected_types:
        filtered_attacks = [a for a in filtered_attacks if any(t in a.get('attack_types', []) for t in selected_types)]
    
    if selected_severity:
        filtered_attacks = [a for a in filtered_attacks if a.get('severity') in selected_severity]
    
    if selected_status != "All":
        target_status = selected_status == "Successful"
        filtered_attacks = [a for a in filtered_attacks if a.get('is_successful') == target_status]
    
    if min_confidence > 0:
        filtered_attacks = [a for a in filtered_attacks if a.get('confidence', 0) >= min_confidence]
    
    # IP Filtering
    if ip_filter:
        ip_filtered = []
        for attack in filtered_attacks:
            if ip_filter_type == "Source IP" and attack.get('src_ip'):
                if is_ip_in_range(attack['src_ip'], ip_filter):
                    ip_filtered.append(attack)
            elif ip_filter_type == "Destination IP" and attack.get('dst_ip'):
                if is_ip_in_range(attack['dst_ip'], ip_filter):
                    ip_filtered.append(attack)
            elif ip_filter_type == "Any IP":
                src_match = attack.get('src_ip') and is_ip_in_range(attack['src_ip'], ip_filter)
                dst_match = attack.get('dst_ip') and is_ip_in_range(attack['dst_ip'], ip_filter)
                if src_match or dst_match:
                    ip_filtered.append(attack)
        filtered_attacks = ip_filtered
    
    st.markdown(f"### 📊 Showing {len(filtered_attacks)} of {len(attacks_data)} attacks")
    
    # Display as dataframe
    if filtered_attacks:
        df = pd.DataFrame(filtered_attacks)
        
        # Handle MongoDB _id field
        if '_id' in df.columns:
            df = df.drop('_id', axis=1)
        
        df['attack_types'] = df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
        df['status'] = df['is_successful'].apply(lambda x: '✅ Success' if x else '🔄 Attempt')
        
        # Select columns to display
        display_columns = ['timestamp', 'url', 'attack_types', 'severity', 'status', 'confidence']
        if 'src_ip' in df.columns:
            display_columns.append('src_ip')
        if 'dst_ip' in df.columns:
            display_columns.append('dst_ip')
        if 'model_used' in df.columns:
            display_columns.append('model_used')
        
        available_columns = [col for col in display_columns if col in df.columns]
        
        display_df = df[available_columns].copy()
        display_df['url'] = display_df['url'].str[:60] + '...'
        display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x}%")
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Export filtered results
        st.subheader("📤 Export Filtered Results")
        col1, col2 = st.columns(2)
        
        with col1:
            csv_data = export_to_csv(df, "filtered_attacks.csv")
            st.download_button(
                label="📥 Export as CSV",
                data=csv_data,
                file_name=f"filtered_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        
        with col2:
            json_data = export_to_json(df, "filtered_attacks.json")
            st.download_button(
                label="📥 Export as JSON",
                data=json_data,
                file_name=f"filtered_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    else:
        st.info("No attacks match the selected filters.")

def show_visualizations():
    """Visualizations page"""
    st.title("📊 Advanced Analytics & Visualizations")
    
    if not st.session_state.attacks_db:
        st.info("No data available for visualization. Analyze some URLs first.")
        return
    
    df = pd.DataFrame(st.session_state.attacks_db)
    
    # Main metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total_attacks = len(df)
        st.metric("Total Attacks", total_attacks)
    with col2:
        successful_attacks = len(df[df['is_successful'] == True])
        st.metric("Successful Attacks", successful_attacks)
    with col3:
        attempted_attacks = total_attacks - successful_attacks
        st.metric("Attempted Attacks", attempted_attacks)
    with col4:
        critical_attacks = len(df[df['severity'] == 'CRITICAL'])
        st.metric("Critical Attacks", critical_attacks)
    
    # Timeline
    st.subheader("📈 Attack Timeline")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    timeline_df = df.groupby(df['timestamp'].dt.date).size().reset_index(name='count')
    timeline_df.columns = ['Date', 'Attacks']
    
    fig = px.line(timeline_df, x='Date', y='Attacks', markers=True, title="Attack Timeline")
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # Attack analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Attack Type Distribution")
        attack_types = []
        for attacks in df['attack_types']:
            if isinstance(attacks, list):
                attack_types.extend(attacks)
        
        type_counts = Counter(attack_types)
        type_df = pd.DataFrame(list(type_counts.items()), columns=['Attack Type', 'Count'])
        type_df = type_df.sort_values('Count', ascending=False)
        
        fig = px.bar(type_df, x='Count', y='Attack Type', orientation='h',
                     color='Count', color_continuous_scale='Reds')
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ Severity Distribution")
        severity_counts = df['severity'].value_counts()
        
        colors = {'CRITICAL': '#FF4444', 'HIGH': '#FF8844', 'MEDIUM': '#FFBB44', 'LOW': '#44FF44'}
        fig = go.Figure(data=[go.Pie(
            labels=severity_counts.index,
            values=severity_counts.values,
            marker=dict(colors=[colors.get(s, '#CCCCCC') for s in severity_counts.index]),
            hole=0.4
        )])
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Success analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("✅ Success vs Attempt Distribution")
        success_data = df['is_successful'].value_counts()
        success_labels = {True: 'Successful', False: 'Attempted'}
        success_data.index = [success_labels[x] for x in success_data.index]
        
        colors = ['#FF4444', '#FFA500']
        fig = px.pie(values=success_data.values, names=success_data.index, 
                     color=success_data.index, color_discrete_map={'Successful': '#FF4444', 'Attempted': '#FFA500'})
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("📊 Confidence Score Distribution")
        fig = px.histogram(df, x='confidence', nbins=20, 
                           labels={'confidence': 'Confidence Score', 'count': 'Number of Attacks'})
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # IP Analysis (if available)
    if 'src_ip' in df.columns and df['src_ip'].notna().any():
        st.subheader("🌐 Source IP Analysis")
        ip_counts = df['src_ip'].value_counts().head(10)
        ip_df = pd.DataFrame({'IP Address': ip_counts.index, 'Attack Count': ip_counts.values})
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(ip_df, x='Attack Count', y='IP Address', orientation='h',
                         title="Top 10 Attacking IPs")
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # IP Type Analysis
            private_ips = len(df[df['src_ip'].apply(lambda x: x and ipaddress.ip_address(x).is_private)])
            public_ips = len(df) - private_ips
            ip_type_data = {'Type': ['Private IPs', 'Public IPs'], 'Count': [private_ips, public_ips]}
            ip_type_df = pd.DataFrame(ip_type_data)
            
            fig = px.pie(ip_type_df, values='Count', names='Type', 
                         title="Private vs Public IP Attacks")
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    # Model usage distribution (if available)
    if 'model_used' in df.columns:
        st.subheader("🤖 Model Usage Distribution")
        model_counts = df['model_used'].value_counts()
        fig = px.pie(values=model_counts.values, names=model_counts.index, 
                     title="Analysis Methods Used")
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Top attacked patterns
    st.subheader("🔝 Most Common Attack Patterns")
    url_patterns = df['url'].str[:50].value_counts().head(10)
    pattern_df = pd.DataFrame({'URL Pattern': url_patterns.index, 'Frequency': url_patterns.values})
    st.dataframe(pattern_df, use_container_width=True, hide_index=True)
    
    # Attack patterns from MongoDB
    if st.session_state.attack_patterns_cache:
        st.markdown("---")
        st.subheader("🔍 Attack Pattern Coverage")
        
        detected_types = set()
        for attacks in df['attack_types']:
            if isinstance(attacks, list):
                detected_types.update(attacks)
        
        coverage_data = []
        for attack_id, info in st.session_state.attack_patterns_cache.items():
            category = info['category']
            detected = category in detected_types
            coverage_data.append({
                'Attack Type': category,
                'Status': '✅ Detected' if detected else '⚪ Not Detected',
                'Pattern Count': len(info['patterns']),
                'Success Indicators': len(info.get('success_indicators', [])),
                'Severity': info['severity']
            })
        
        coverage_df = pd.DataFrame(coverage_data)
        st.dataframe(coverage_df, use_container_width=True, hide_index=True)

if __name__ == "__main__":
    main()
