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

# Try to import PCAP libraries
try:
    from scapy.all import rdpcap, TCP, Raw
    from scapy.layers.http import HTTPRequest
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

# MongoDB Functions
@st.cache_resource
def connect_to_mongodb(connection_string):
    """Connect to MongoDB Atlas"""
    try:
        connection_string="mongodb+srv://adhilbinmujeeb:NVYM5d67PHpkE7LA@cluster0.uz62z.mongodb.net/"
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
                'mitigation': doc.get('mitigation', [])
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

def get_detection_history_from_db(db, limit=100):
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

# Attack Detection Functions using MongoDB patterns
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

def quick_detection(url, patterns_data):
    """Quick pattern-based detection using MongoDB patterns"""
    if not patterns_data:
        st.warning("⚠️ Attack patterns not loaded. Please configure MongoDB connection.")
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

def analyze_with_gemini(url, quick_results):
    """Analyze URL with Google Gemini API"""
    if not st.session_state.api_key:
        return None
    
    try:
        model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        prompt = f"""As a cybersecurity expert, analyze this URL for potential attacks:

URL: {url}

Pre-detected patterns: {', '.join(quick_results) if quick_results else 'None'}

Identify attack type(s) and provide response in this exact JSON format:
{{
    "is_malicious": true/false,
    "attack_types": ["type1", "type2"],
    "confidence": 0-100,
    "severity": "LOW/MEDIUM/HIGH/CRITICAL",
    "explanation": "brief technical explanation",
    "recommendations": ["recommendation1", "recommendation2"]
}}"""

        response = model.generate_content(prompt)
        
        # Extract JSON from response
        text = response.text
        text = re.sub(r'```json\n?', '', text)
        text = re.sub(r'```\n?', '', text)
        text = text.strip()
        
        result = json.loads(text)
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

# PCAP Parsing Functions
def parse_pcap_with_scapy(pcap_file):
    """Parse PCAP file using Scapy"""
    urls = []
    try:
        packets = rdpcap(pcap_file)
        
        for packet in packets:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if http_layer.Host else ""
                path = http_layer.Path.decode() if http_layer.Path else ""
                
                if host and path:
                    url = f"http://{host}{path}"
                    urls.append(url)
            
            elif packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    if payload_str.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                        lines = payload_str.split('\r\n')
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
                                    urls.append(url)
                except:
                    continue
        
        return urls
    except Exception as e:
        st.error(f"Error parsing PCAP with Scapy: {str(e)}")
        return []

def parse_pcap_with_dpkt(pcap_file):
    """Parse PCAP file using dpkt"""
    urls = []
    try:
        pcap_file.seek(0)
        pcap = dpkt.pcap.Reader(pcap_file)
        
        for timestamp, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                
                ip = eth.data
                
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                
                tcp = ip.data
                
                if len(tcp.data) > 0:
                    try:
                        request = dpkt.http.Request(tcp.data)
                        host = request.headers.get('host', '')
                        uri = request.uri
                        
                        if host and uri:
                            url = f"http://{host}{uri}"
                            urls.append(url)
                    except:
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
                                        urls.append(url)
            except:
                continue
        
        return urls
    except Exception as e:
        st.error(f"Error parsing PCAP with dpkt: {str(e)}")
        return []

def parse_pcap_file(uploaded_file):
    """Parse PCAP file and extract URLs"""
    urls = []
    
    if PCAP_SUPPORT:
        with st.spinner("Parsing PCAP with Scapy..."):
            temp_path = f"/tmp/{uploaded_file.name}"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getvalue())
            
            urls = parse_pcap_with_scapy(temp_path)
    
    if not urls and DPKT_SUPPORT:
        with st.spinner("Parsing PCAP with dpkt..."):
            uploaded_file.seek(0)
            urls = parse_pcap_with_dpkt(uploaded_file)
    
    if not urls:
        if not PCAP_SUPPORT and not DPKT_SUPPORT:
            st.error("PCAP parsing requires scapy or dpkt libraries.")
        else:
            st.warning("No HTTP URLs found in PCAP file.")
    
    return urls

# Main Application
def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/clouds/200/security-checked.png", width=150)
        st.title("🛡️ Cyber Attack Detector")
        st.markdown("---")
        
        # MongoDB Connection
        st.subheader("🗄️ MongoDB Configuration")
        mongodb_conn = st.text_input(
            "MongoDB Connection String", 
            type="password", 
            value=st.session_state.mongodb_connection,
            placeholder="mongodb+srv://..."
        )
        
        if mongodb_conn != st.session_state.mongodb_connection:
            st.session_state.mongodb_connection = mongodb_conn
            st.session_state.patterns_loaded = False
            
            if mongodb_conn:
                with st.spinner("Connecting to MongoDB..."):
                    db = connect_to_mongodb(mongodb_conn)
                    if db is not None:
                        st.session_state.mongo_db = db
                        patterns = load_attack_patterns_from_db(db)
                        if patterns:
                            st.session_state.attack_patterns_cache = patterns
                            st.session_state.patterns_loaded = True
                            st.success(f"✅ Loaded {len(patterns)} attack patterns!")
        
        # API Key Input
        st.markdown("---")
        st.subheader("🔑 Gemini API Key")
        api_key = st.text_input("API Key", type="password", value=st.session_state.api_key)
        if api_key != st.session_state.api_key:
            st.session_state.api_key = api_key
            if api_key:
                if configure_gemini(api_key):
                    st.success("✅ Gemini API configured!")
        
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
        
        # Connection Status
        if st.session_state.patterns_loaded:
            st.success("✅ MongoDB Connected")
        else:
            st.warning("⚠️ Configure MongoDB")
        
        # Stats
        if st.session_state.attacks_db:
            st.metric("Total Attacks", len(st.session_state.attacks_db))
            critical_count = len([a for a in st.session_state.attacks_db if a.get('severity') == 'CRITICAL'])
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
        st.warning("⚠️ Please configure MongoDB connection in the sidebar to load attack patterns.")
        return
    
    # Stats Cards
    col1, col2, col3, col4 = st.columns(4)
    
    total_analyzed = len(st.session_state.analysis_history)
    total_attacks = len(st.session_state.attacks_db)
    
    with col1:
        st.metric("📊 Total Analyzed", total_analyzed)
    
    with col2:
        st.metric("⚠️ Attacks Detected", total_attacks)
    
    with col3:
        if total_analyzed > 0:
            rate = (total_attacks / total_analyzed) * 100
            st.metric("🎯 Detection Rate", f"{rate:.1f}%")
        else:
            st.metric("🎯 Detection Rate", "0%")
    
    with col4:
        critical = len([a for a in st.session_state.attacks_db if a.get('severity') == 'CRITICAL'])
        st.metric("🔴 Critical Threats", critical)
    
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
        st.subheader("🎯 Severity Distribution")
        if st.session_state.attacks_db:
            severities = [a.get('severity', 'UNKNOWN') for a in st.session_state.attacks_db]
            severity_counts = Counter(severities)
            
            df = pd.DataFrame(list(severity_counts.items()), columns=['Severity', 'Count'])
            colors = {'CRITICAL': '#FF4444', 'HIGH': '#FF8844', 'MEDIUM': '#FFBB44', 'LOW': '#44FF44'}
            fig = px.bar(df, x='Severity', y='Count', color='Severity',
                        color_discrete_map=colors)
            fig.update_layout(height=350, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No severity data available")
    
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
                'Confidence': df['confidence'].apply(lambda x: f"{x}%")
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
                'Patterns Count': len(info['patterns'])
            })
        
        patterns_df = pd.DataFrame(patterns_info)
        st.dataframe(patterns_df, use_container_width=True, hide_index=True)

def show_url_analysis():
    """URL Analysis page"""
    st.title("🔍 Single URL Analysis")
    st.markdown("Enter a URL or HTTP request to analyze for potential cyber attacks")
    
    if not st.session_state.patterns_loaded:
        st.warning("⚠️ Please configure MongoDB connection in the sidebar to load attack patterns.")
        return
    
    # Input
    url_input = st.text_area(
        "URL or HTTP Request",
        placeholder="http://example.com/page?id=1' OR '1'='1\n\nExample attacks:\n- SQL: /page?id=1' UNION SELECT * FROM users--\n- XSS: /search?q=<script>alert(1)</script>\n- Path Traversal: /file?path=../../etc/passwd",
        height=150
    )
    
    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)
    with col2:
        use_gemini = st.checkbox("Use Gemini AI for deep analysis", value=True, disabled=not st.session_state.api_key)
        if not st.session_state.api_key:
            st.info("💡 Configure Gemini API key for AI-powered analysis")
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL..."):
            # Quick detection using MongoDB patterns
            quick_attacks, quick_indicators = quick_detection(url_input, st.session_state.attack_patterns_cache)
            
            # Gemini analysis
            gemini_result = None
            if use_gemini and st.session_state.api_key:
                with st.spinner("🤖 Running Gemini AI analysis..."):
                    gemini_result = analyze_with_gemini(url_input, quick_attacks)
            
            # Combine results
            if gemini_result:
                attack_types = gemini_result.get('attack_types', quick_attacks)
                confidence = gemini_result.get('confidence', 0)
                severity = gemini_result.get('severity', determine_severity(attack_types))
                explanation = gemini_result.get('explanation', '')
                recommendations = gemini_result.get('recommendations', [])
                is_malicious = gemini_result.get('is_malicious', len(attack_types) > 0)
            else:
                attack_types = quick_attacks
                confidence = calculate_confidence(quick_indicators, None)
                severity = determine_severity(attack_types)
                explanation = "Pattern-based detection using MongoDB patterns"
                recommendations = []
                is_malicious = len(attack_types) > 0
            
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
                'indicators': quick_indicators,
                'explanation': explanation,
                'recommendations': list(set(recommendations))  # Remove duplicates
            }
            
            st.session_state.analysis_history.append(analysis_record)
            
            if is_malicious:
                st.session_state.attacks_db.append(analysis_record)
                
                # Save to MongoDB
                if st.session_state.mongo_db:
                    save_detection_to_db(st.session_state.mongo_db, analysis_record.copy())
            
            # Display Results
            st.markdown("---")
            st.subheader("📊 Analysis Results")
            
            if is_malicious:
                st.markdown(f'<div class="attack-card">', unsafe_allow_html=True)
                st.error("⚠️ **THREAT DETECTED!**")
                st.markdown('</div>', unsafe_allow_html=True)
                
                col1, col2, col3 = st.columns(3)
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
                
                # Attack Types
                st.subheader("🎯 Detected Attack Types")
                for attack in attack_types:
                    st.markdown(f"- **{attack}**")
                
                # Indicators
                if quick_indicators:
                    st.subheader("🔍 Technical Indicators")
                    for indicator in quick_indicators:
                        st.markdown(f"- {indicator}")
                
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
        st.warning("⚠️ Please configure MongoDB connection in the sidebar.")
        return
    
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
            st.info("💡 AI analysis disabled without API key (pattern-based detection will still work)")
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: {uploaded_file.name} ({uploaded_file.size / 1024:.2f} KB)")
        
        if st.button("🚀 Start Analysis", type="primary"):
            with st.spinner("Processing file..."):
                try:
                    urls = []
                    
                    # Read file based on type
                    if uploaded_file.name.endswith(('.pcap', '.pcapng')):
                        if PCAP_SUPPORT or DPKT_SUPPORT:
                            urls = parse_pcap_file(uploaded_file)
                            if urls:
                                st.info(f"📊 Extracted {len(urls)} URLs from PCAP")
                        else:
                            st.error("PCAP parsing requires scapy or dpkt.")
                            return
                    
                    elif uploaded_file.name.endswith('.csv'):
                        df = pd.read_csv(uploaded_file)
                        st.info(f"📊 Loaded {len(df)} rows from CSV")
                        
                        if 'url' in df.columns:
                            urls = df['url'].tolist()
                        else:
                            st.error("CSV must contain a 'url' column")
                            return
                    
                    elif uploaded_file.name.endswith('.json'):
                        data = json.load(uploaded_file)
                        if isinstance(data, list):
                            urls = [item.get('url', '') for item in data if isinstance(item, dict)]
                        else:
                            urls = [data.get('url', '')] if isinstance(data, dict) else []
                        st.info(f"📊 Loaded {len(urls)} URLs from JSON")
                    
                    elif uploaded_file.name.endswith('.txt'):
                        content = uploaded_file.read().decode('utf-8')
                        urls = [line.strip() for line in content.split('\n') if line.strip()]
                        st.info(f"📊 Loaded {len(urls)} URLs from text file")
                    
                    if not urls:
                        st.warning("No URLs found in file")
                        return
                    
                    # Remove duplicates
                    urls = list(set(urls))
                    st.info(f"🔍 Analyzing {len(urls)} unique URLs...")
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    results = []
                    for idx, url in enumerate(urls):
                        if url:
                            status_text.text(f"Analyzing {idx + 1}/{len(urls)}: {url[:50]}...")
                            
                            quick_attacks, quick_indicators = quick_detection(url, st.session_state.attack_patterns_cache)
                            
                            if use_ai and st.session_state.api_key and quick_attacks:
                                gemini_result = analyze_with_gemini(url, quick_attacks)
                                if gemini_result:
                                    attack_types = gemini_result.get('attack_types', quick_attacks)
                                    confidence = gemini_result.get('confidence', 0)
                                    severity = gemini_result.get('severity', determine_severity(attack_types))
                                else:
                                    attack_types = quick_attacks
                                    confidence = calculate_confidence(quick_indicators, None)
                                    severity = determine_severity(attack_types)
                            else:
                                attack_types = quick_attacks
                                confidence = calculate_confidence(quick_indicators, None)
                                severity = determine_severity(attack_types)
                            
                            if attack_types:
                                result = {
                                    'url': url,
                                    'attack_types': attack_types,
                                    'confidence': confidence,
                                    'severity': severity,
                                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                }
                                results.append(result)
                                st.session_state.attacks_db.append(result)
                                
                                # Save to MongoDB
                                if st.session_state.mongo_db:
                                    save_detection_to_db(st.session_state.mongo_db, result.copy())
                        
                        progress_bar.progress((idx + 1) / len(urls))
                    
                    status_text.text("✅ Analysis complete!")
                    
                    # Display results
                    if results:
                        st.success(f"🎯 Found {len(results)} potential attacks out of {len(urls)} URLs")
                        
                        # Summary statistics
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total Threats", len(results))
                        with col2:
                            critical = len([r for r in results if r['severity'] == 'CRITICAL'])
                            st.metric("Critical", critical)
                        with col3:
                            avg_conf = sum(r['confidence'] for r in results) / len(results)
                            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
                        
                        # Results table
                        results_df = pd.DataFrame(results)
                        results_df['attack_types'] = results_df['attack_types'].apply(lambda x: ', '.join(x))
                        
                        display_df = results_df.copy()
                        display_df['url'] = display_df['url'].str[:80] + '...'
                        st.dataframe(display_df, use_container_width=True)
                        
                        # Download results
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Results (CSV)",
                            data=csv,
                            file_name=f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.success("✅ No attacks detected. All URLs appear safe!")
                
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())

def show_attack_database():
    """Attack Database page"""
    st.title("🗂️ Attack Database")
    st.markdown("Query and filter detected attacks")
    
    # Option to load from MongoDB or session
    col1, col2 = st.columns([3, 1])
    with col1:
        data_source = st.radio("Data Source", ["Session Data", "MongoDB History"], horizontal=True)
    with col2:
        if st.button("🔄 Refresh"):
            st.rerun()
    
    # Load data based on source
    if data_source == "MongoDB History" and st.session_state.mongo_db:
        with st.spinner("Loading from MongoDB..."):
            attacks_data = get_detection_history_from_db(st.session_state.mongo_db, limit=500)
            if not attacks_data:
                st.info("No attacks in MongoDB database yet.")
                return
    else:
        attacks_data = st.session_state.attacks_db
        if not attacks_data:
            st.info("No attacks in session database yet. Analyze some URLs to populate.")
            return
    
    # Filters
    with st.expander("🔍 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            all_attack_types = set()
            for attack in attacks_data:
                all_attack_types.update(attack.get('attack_types', []))
            
            selected_types = st.multiselect("Attack Type", sorted(list(all_attack_types)))
        
        with col2:
            selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
        with col3:
            min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
    
    # Apply filters
    filtered_attacks = attacks_data.copy()
    
    if selected_types:
        filtered_attacks = [a for a in filtered_attacks if any(t in a.get('attack_types', []) for t in selected_types)]
    
    if selected_severity:
        filtered_attacks = [a for a in filtered_attacks if a.get('severity') in selected_severity]
    
    if min_confidence > 0:
        filtered_attacks = [a for a in filtered_attacks if a.get('confidence', 0) >= min_confidence]
    
    st.markdown(f"### 📊 Showing {len(filtered_attacks)} of {len(attacks_data)} attacks")
    
    # Display as dataframe
    if filtered_attacks:
        df = pd.DataFrame(filtered_attacks)
        
        # Handle MongoDB _id field
        if '_id' in df.columns:
            df = df.drop('_id', axis=1)
        
        df['attack_types'] = df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
        
        # Select columns to display
        display_columns = ['timestamp', 'url', 'attack_types', 'severity', 'confidence']
        available_columns = [col for col in display_columns if col in df.columns]
        
        display_df = df[available_columns].copy()
        display_df['url'] = display_df['url'].str[:60] + '...'
        display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x}%")
        
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # Export filtered results
        csv = df.to_csv(index=False)
        st.download_button(
            label="📥 Export Filtered Results (CSV)",
            data=csv,
            file_name=f"filtered_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
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
    
    # Timeline
    st.subheader("📈 Attack Timeline")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    timeline_df = df.groupby(df['timestamp'].dt.date).size().reset_index(name='count')
    timeline_df.columns = ['Date', 'Attacks']
    
    fig = px.line(timeline_df, x='Date', y='Attacks', markers=True)
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)
    
    # Attack type distribution
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
    
    # Confidence distribution
    st.subheader("📊 Confidence Score Distribution")
    fig = px.histogram(df, x='confidence', nbins=20, 
                       labels={'confidence': 'Confidence Score', 'count': 'Number of Attacks'})
    fig.update_layout(height=350)
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
                'Severity': info['severity']
            })
        
        coverage_df = pd.DataFrame(coverage_data)
        st.dataframe(coverage_df, use_container_width=True, hide_index=True)

if __name__ == "__main__":
    main()
