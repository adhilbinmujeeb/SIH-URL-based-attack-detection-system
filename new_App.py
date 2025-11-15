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
import pymongo
from pymongo import MongoClient

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
    .safe-card {
        border-left: 4px solid #44FF44;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
    .pattern-info {
        background-color: #e7f3ff;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.25rem 0;
        font-size: 0.9rem;
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
if 'mongodb_connected' not in st.session_state:
    st.session_state.mongodb_connected = False
if 'mongodb_client' not in st.session_state:
    st.session_state.mongodb_client = None
if 'mongodb_db' not in st.session_state:
    st.session_state.mongodb_db = None
if 'attack_patterns' not in st.session_state:
    st.session_state.attack_patterns = {}
if 'mongodb_connection_string' not in st.session_state:
    st.session_state.mongodb_connection_string = ""

# MongoDB Connection Functions
def connect_to_mongodb(connection_string):
    """Connect to MongoDB Atlas"""
    try:
        client = MongoClient(connection_string, serverSelectionTimeoutMS=10000)
        client.admin.command('ping')
        db = client['cyber_attack_detection']
        return client, db
    except Exception as e:
        st.error(f"❌ MongoDB connection failed: {str(e)}")
        return None, None

def load_attack_patterns(db):
    """Load attack patterns from MongoDB"""
    try:
        collection = db['attack_patterns']
        patterns = {}
        
        for doc in collection.find({'active': True}):
            attack_id = doc.get('attack_id')
            patterns[attack_id] = {
                'category': doc.get('category'),
                'description': doc.get('description'),
                'severity': doc.get('severity'),
                'patterns': doc.get('patterns', []),
                'mitigation': doc.get('mitigation', [])
            }
        
        return patterns
    except Exception as e:
        st.error(f"Error loading patterns: {str(e)}")
        return {}

def get_detection_config(db):
    """Get detection configuration from MongoDB"""
    try:
        config_collection = db['detection_config']
        config = config_collection.find_one({'config_id': 'comprehensive_v2'})
        return config if config else {}
    except Exception as e:
        st.error(f"Error loading config: {str(e)}")
        return {}

def save_detection_to_mongodb(db, detection_record):
    """Save detection results to MongoDB"""
    try:
        detections_collection = db['detections']
        detections_collection.insert_one(detection_record)
        
        # Update statistics
        stats_collection = db['attack_statistics']
        stats = stats_collection.find_one({'stat_id': 'initial'})
        
        if stats:
            # Update statistics
            stats['total_detections'] += 1
            
            # Update by category
            for attack_type in detection_record.get('attack_types', []):
                if attack_type in stats['detections_by_category']:
                    stats['detections_by_category'][attack_type] += 1
                else:
                    stats['detections_by_category'][attack_type] = 1
            
            # Update by severity
            severity = detection_record.get('severity', 'LOW')
            if severity in stats['detections_by_severity']:
                stats['detections_by_severity'][severity] += 1
            
            stats['last_updated'] = datetime.now()
            
            stats_collection.update_one(
                {'stat_id': 'initial'},
                {'$set': stats}
            )
        
        return True
    except Exception as e:
        st.error(f"Error saving to MongoDB: {str(e)}")
        return False

# Gemini API Configuration
def configure_gemini(api_key):
    """Configure Google Gemini API"""
    try:
        genai.configure(api_key=api_key)
        return True
    except Exception as e:
        st.error(f"Error configuring Gemini API: {str(e)}")
        return False

# MongoDB-based Attack Detection
def detect_attacks_from_mongodb(url, attack_patterns):
    """Detect attacks using patterns from MongoDB"""
    detected_attacks = {}
    all_matched_patterns = []
    
    for attack_id, pattern_data in attack_patterns.items():
        category = pattern_data['category']
        severity = pattern_data['severity']
        patterns = pattern_data['patterns']
        
        matched_patterns = []
        
        for pattern in patterns:
            regex = pattern.get('regex', '')
            description = pattern.get('description', '')
            
            try:
                if re.search(regex, url, re.IGNORECASE):
                    matched_patterns.append({
                        'description': description,
                        'example': pattern.get('example', ''),
                        'regex': regex
                    })
            except re.error:
                continue
        
        if matched_patterns:
            detected_attacks[attack_id] = {
                'category': category,
                'severity': severity,
                'matched_patterns': matched_patterns,
                'pattern_count': len(matched_patterns),
                'mitigation': pattern_data.get('mitigation', [])
            }
            all_matched_patterns.extend(matched_patterns)
    
    return detected_attacks, all_matched_patterns

def calculate_confidence_score(detected_attacks, all_matched_patterns):
    """Calculate confidence score based on detections"""
    if not detected_attacks:
        return 0
    
    # Base score on number of patterns matched
    pattern_score = min(len(all_matched_patterns) * 15, 60)
    
    # Severity multiplier
    severity_weights = {'CRITICAL': 1.5, 'HIGH': 1.3, 'MEDIUM': 1.1, 'LOW': 1.0}
    max_severity_weight = max([severity_weights.get(data['severity'], 1.0) 
                               for data in detected_attacks.values()])
    
    # Category diversity bonus
    category_bonus = min(len(detected_attacks) * 5, 20)
    
    confidence = min((pattern_score * max_severity_weight) + category_bonus, 99)
    
    return int(confidence)

def determine_overall_severity(detected_attacks):
    """Determine overall severity from detected attacks"""
    if not detected_attacks:
        return "LOW"
    
    severity_priority = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    
    for severity in severity_priority:
        for attack_data in detected_attacks.values():
            if attack_data['severity'] == severity:
                return severity
    
    return "LOW"

def analyze_with_gemini(url, detected_attacks):
    """Analyze URL with Google Gemini API"""
    if not st.session_state.api_key:
        return None
    
    try:
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        attack_categories = [data['category'] for data in detected_attacks.values()]
        
        prompt = f"""As a cybersecurity expert, analyze this URL for potential attacks:

URL: {url}

Pre-detected attack categories: {', '.join(attack_categories) if attack_categories else 'None'}

Provide a detailed security analysis including:
1. Confirmation or refinement of detected attack types
2. Additional attack vectors not initially detected
3. Technical explanation of the attack mechanism
4. Risk assessment and potential impact
5. Specific mitigation recommendations

Response format (JSON):
{{
    "is_malicious": true/false,
    "attack_types": ["type1", "type2"],
    "confidence": 0-100,
    "severity": "LOW/MEDIUM/HIGH/CRITICAL",
    "explanation": "detailed technical explanation",
    "attack_mechanism": "how the attack works",
    "potential_impact": "what could happen",
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
        mongodb_string = st.text_input(
            "MongoDB Connection String",
            type="password",
            value=st.session_state.mongodb_connection_string,
            placeholder="mongodb+srv://..."
        )
        
        if mongodb_string != st.session_state.mongodb_connection_string:
            st.session_state.mongodb_connection_string = mongodb_string
        
        if st.button("Connect to MongoDB", type="primary"):
            with st.spinner("Connecting to MongoDB..."):
                client, db = connect_to_mongodb(mongodb_string)
                if client and db:
                    st.session_state.mongodb_client = client
                    st.session_state.mongodb_db = db
                    st.session_state.mongodb_connected = True
                    
                    # Load attack patterns
                    patterns = load_attack_patterns(db)
                    st.session_state.attack_patterns = patterns
                    
                    st.success(f"✅ Connected! Loaded {len(patterns)} attack categories")
                else:
                    st.session_state.mongodb_connected = False
        
        if st.session_state.mongodb_connected:
            st.success(f"🟢 MongoDB Connected")
            st.info(f"📊 {len(st.session_state.attack_patterns)} attack patterns loaded")
        else:
            st.warning("🔴 MongoDB Not Connected")
        
        st.markdown("---")
        
        # API Key Input
        st.subheader("🤖 Gemini AI Configuration")
        api_key = st.text_input("Google Gemini API Key", type="password", value=st.session_state.api_key)
        if api_key != st.session_state.api_key:
            st.session_state.api_key = api_key
            if api_key:
                if configure_gemini(api_key):
                    st.success("✅ API Key configured!")
        
        st.markdown("---")
        
        # Navigation
        page = st.radio("Navigation", [
            "🏠 Dashboard",
            "🔍 URL Analysis", 
            "📂 Bulk Analysis",
            "🗂️ Attack Database",
            "📊 Visualizations",
            "⚙️ Pattern Management",
            "📥 Export & Reports"
        ])
        
        st.markdown("---")
        
        # Stats
        if st.session_state.attacks_db:
            st.metric("Total Attacks Detected", len(st.session_state.attacks_db))
            critical_count = len([a for a in st.session_state.attacks_db if a.get('severity') == 'CRITICAL'])
            st.metric("Critical Threats", critical_count)
    
    # Main Content
    if not st.session_state.mongodb_connected:
        st.warning("⚠️ Please connect to MongoDB to use the application")
        st.info("Enter your MongoDB Atlas connection string in the sidebar and click 'Connect to MongoDB'")
        return
    
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
    elif "Pattern Management" in page:
        show_pattern_management()
    elif "Export" in page:
        show_export()

def show_dashboard():
    """Dashboard page"""
    st.markdown('<p class="main-header">🛡️ Cyber Attack Detection System</p>', unsafe_allow_html=True)
    st.markdown("### MongoDB-Powered AI Detection with Google Gemini")
    
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
    
    # System Status
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔧 System Status")
        st.write(f"✅ MongoDB: Connected")
        st.write(f"📊 Attack Patterns: {len(st.session_state.attack_patterns)}")
        st.write(f"🤖 Gemini AI: {'Enabled' if st.session_state.api_key else 'Disabled'}")
        
        # Pattern categories
        if st.session_state.attack_patterns:
            st.write("**Loaded Categories:**")
            for pattern_id, pattern_data in list(st.session_state.attack_patterns.items())[:5]:
                st.write(f"  • {pattern_data['category']} ({pattern_data['severity']})")
    
    with col2:
        st.subheader("📈 Attack Distribution")
        if st.session_state.attacks_db:
            attack_types = []
            for attack in st.session_state.attacks_db:
                attack_types.extend(attack.get('attack_types', []))
            
            if attack_types:
                type_counts = Counter(attack_types)
                df = pd.DataFrame(list(type_counts.items()), columns=['Attack Type', 'Count'])
                fig = px.pie(df, values='Count', names='Attack Type', hole=0.4)
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No attacks detected yet")
        else:
            st.info("No attacks detected yet")
    
    # Recent Detections
    st.subheader("🕐 Recent Detections")
    if st.session_state.attacks_db:
        recent = st.session_state.attacks_db[-10:][::-1]
        
        df = pd.DataFrame(recent)
        if not df.empty:
            display_df = pd.DataFrame({
                'Timestamp': df['timestamp'],
                'URL (Preview)': df['url'].str[:50] + '...',
                'Attack Types': df['attack_types'].apply(lambda x: ', '.join(x[:3]) if isinstance(x, list) else x),
                'Severity': df['severity'],
                'Confidence': df['confidence'].apply(lambda x: f"{x}%")
            })
            st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No detections yet. Start analyzing URLs!")

def show_url_analysis():
    """URL Analysis page"""
    st.title("🔍 Single URL Analysis")
    st.markdown("MongoDB-powered attack detection with comprehensive pattern matching")
    
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
            st.warning("⚠️ Configure Gemini API key for AI analysis")
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL with MongoDB patterns..."):
            # Detect using MongoDB patterns
            detected_attacks, all_matched_patterns = detect_attacks_from_mongodb(
                url_input, 
                st.session_state.attack_patterns
            )
            
            # Calculate confidence and severity
            confidence = calculate_confidence_score(detected_attacks, all_matched_patterns)
            severity = determine_overall_severity(detected_attacks)
            
            # Gemini analysis
            gemini_result = None
            if use_gemini and st.session_state.api_key and detected_attacks:
                with st.spinner("🤖 Running Gemini AI analysis..."):
                    gemini_result = analyze_with_gemini(url_input, detected_attacks)
            
            # Combine results
            if gemini_result:
                confidence = gemini_result.get('confidence', confidence)
                severity = gemini_result.get('severity', severity)
                explanation = gemini_result.get('explanation', '')
                attack_mechanism = gemini_result.get('attack_mechanism', '')
                potential_impact = gemini_result.get('potential_impact', '')
                recommendations = gemini_result.get('recommendations', [])
            else:
                explanation = "Pattern-based detection using MongoDB attack signatures"
                attack_mechanism = ""
                potential_impact = ""
                recommendations = []
            
            is_malicious = len(detected_attacks) > 0
            
            # Prepare attack types list
            attack_types = [data['category'] for data in detected_attacks.values()]
            
            # Store in history
            analysis_record = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'url': url_input,
                'attack_types': attack_types,
                'confidence': confidence,
                'severity': severity,
                'is_malicious': is_malicious,
                'detected_attacks': detected_attacks,
                'matched_patterns_count': len(all_matched_patterns),
                'explanation': explanation,
                'recommendations': recommendations
            }
            
            st.session_state.analysis_history.append(analysis_record)
            
            if is_malicious:
                st.session_state.attacks_db.append(analysis_record)
                
                # Save to MongoDB
                if st.session_state.mongodb_db:
                    save_detection_to_mongodb(st.session_state.mongodb_db, analysis_record)
            
            # Display Results
            st.markdown("---")
            st.subheader("📊 Analysis Results")
            
            if is_malicious:
                st.markdown(f'<div class="attack-card">', unsafe_allow_html=True)
                st.error("⚠️ **THREAT DETECTED!**")
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
                    st.metric("Attack Categories", len(detected_attacks))
                with col4:
                    st.metric("Patterns Matched", len(all_matched_patterns))
                
                # Detailed Attack Information
                st.subheader("🎯 Detected Attack Types")
                
                for attack_id, attack_data in detected_attacks.items():
                    with st.expander(f"🔴 {attack_data['category']} - {attack_data['severity']}", expanded=True):
                        st.write(f"**Patterns Matched:** {attack_data['pattern_count']}")
                        
                        st.write("**Matched Indicators:**")
                        for pattern in attack_data['matched_patterns'][:5]:  # Show first 5
                            st.markdown(f'<div class="pattern-info">• {pattern["description"]}</div>', unsafe_allow_html=True)
                            if pattern.get('example'):
                                st.code(f"Example: {pattern['example']}", language="text")
                        
                        if attack_data.get('mitigation'):
                            st.write("**Mitigation Strategies:**")
                            for mitigation in attack_data['mitigation'][:3]:
                                st.markdown(f"- {mitigation}")
                
                # AI Analysis
                if gemini_result:
                    st.subheader("🤖 AI-Powered Analysis")
                    
                    if explanation:
                        st.info(f"**Analysis:** {explanation}")
                    
                    if attack_mechanism:
                        st.warning(f"**Attack Mechanism:** {attack_mechanism}")
                    
                    if potential_impact:
                        st.error(f"**Potential Impact:** {potential_impact}")
                    
                    if recommendations:
                        st.write("**AI Recommendations:**")
                        for rec in recommendations:
                            st.markdown(f"- {rec}")
                
            else:
                st.markdown(f'<div class="safe-card">', unsafe_allow_html=True)
                st.success("✅ **NO THREATS DETECTED**")
                st.markdown('</div>', unsafe_allow_html=True)
                
                st.info("The URL appears to be safe based on MongoDB pattern analysis.")

def show_bulk_analysis():
    """Bulk Analysis page"""
    st.title("📂 Bulk Traffic Analysis")
    st.markdown("Upload files for batch analysis using MongoDB patterns")
    
    if PCAP_SUPPORT or DPKT_SUPPORT:
        pcap_libs = []
        if PCAP_SUPPORT:
            pcap_libs.append("Scapy")
        if DPKT_SUPPORT:
            pcap_libs.append("dpkt")
        st.success(f"✅ PCAP support enabled ({', '.join(pcap_libs)})")
    else:
        st.warning("⚠️ PCAP support disabled. Install scapy or dpkt for PCAP analysis.")
    
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=['pcap', 'pcapng', 'csv', 'json', 'txt'],
        help="Supported formats: PCAP, PCAPNG, CSV, JSON, TXT"
    )
    
    with st.expander("⚙️ Analysis Options", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            use_ai = st.checkbox("Enable Gemini AI Analysis", value=False, disabled=not st.session_state.api_key)
            save_to_db = st.checkbox("Save results to MongoDB", value=True)
        with col2:
            max_urls = st.number_input("Max URLs to analyze", min_value=10, max_value=1000, value=100)
    
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
                    
                    # Remove duplicates and limit
                    urls = list(set(urls))[:max_urls]
                    st.info(f"🔍 Analyzing {len(urls)} unique URLs...")
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    results = []
                    for idx, url in enumerate(urls):
                        if url:
                            status_text.text(f"Analyzing {idx + 1}/{len(urls)}: {url[:50]}...")
                            
                            # MongoDB pattern detection
                            detected_attacks, all_matched_patterns = detect_attacks_from_mongodb(
                                url, 
                                st.session_state.attack_patterns
                            )
                            
                            if detected_attacks:
                                confidence = calculate_confidence_score(detected_attacks, all_matched_patterns)
                                severity = determine_overall_severity(detected_attacks)
                                attack_types = [data['category'] for data in detected_attacks.values()]
                                
                                # Optional Gemini analysis
                                if use_ai and st.session_state.api_key:
                                    gemini_result = analyze_with_gemini(url, detected_attacks)
                                    if gemini_result:
                                        confidence = gemini_result.get('confidence', confidence)
                                        severity = gemini_result.get('severity', severity)
                                
                                result = {
                                    'url': url,
                                    'attack_types': attack_types,
                                    'confidence': confidence,
                                    'severity': severity,
                                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    'pattern_matches': len(all_matched_patterns)
                                }
                                
                                results.append(result)
                                st.session_state.attacks_db.append(result)
                                
                                # Save to MongoDB
                                if save_to_db and st.session_state.mongodb_db:
                                    save_detection_to_mongodb(st.session_state.mongodb_db, result)
                        
                        progress_bar.progress((idx + 1) / len(urls))
                    
                    status_text.text("✅ Analysis complete!")
                    
                    # Display results
                    if results:
                        st.success(f"🎯 Found {len(results)} potential attacks out of {len(urls)} URLs")
                        
                        # Summary statistics
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total Threats", len(results))
                        with col2:
                            critical = len([r for r in results if r['severity'] == 'CRITICAL'])
                            st.metric("Critical", critical)
                        with col3:
                            avg_conf = sum(r['confidence'] for r in results) / len(results)
                            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
                        with col4:
                            total_patterns = sum(r.get('pattern_matches', 0) for r in results)
                            st.metric("Total Patterns", total_patterns)
                        
                        # Results table
                        results_df = pd.DataFrame(results)
                        results_df['attack_types'] = results_df['attack_types'].apply(lambda x: ', '.join(x[:2]) if isinstance(x, list) else x)
                        
                        display_df = results_df.copy()
                        display_df['url'] = display_df['url'].str[:60] + '...'
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
    
    if not st.session_state.attacks_db:
        st.info("No attacks in database yet. Analyze some URLs to populate the database.")
        return
    
    # Filters
    with st.expander("🔍 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            all_attack_types = set()
            for attack in st.session_state.attacks_db:
                all_attack_types.update(attack.get('attack_types', []))
            
            selected_types = st.multiselect("Attack Type", sorted(list(all_attack_types)))
        
        with col2:
            selected_severity = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        
        with col3:
            min_confidence = st.slider("Minimum Confidence", 0, 100, 0)
    
    # Apply filters
    filtered_attacks = st.session_state.attacks_db.copy()
    
    if selected_types:
        filtered_attacks = [a for a in filtered_attacks if any(t in a.get('attack_types', []) for t in selected_types)]
    
    if selected_severity:
        filtered_attacks = [a for a in filtered_attacks if a.get('severity') in selected_severity]
    
    if min_confidence > 0:
        filtered_attacks = [a for a in filtered_attacks if a.get('confidence', 0) >= min_confidence]
    
    st.markdown(f"### 📊 Showing {len(filtered_attacks)} of {len(st.session_state.attacks_db)} attacks")
    
    # Display as dataframe
    if filtered_attacks:
        df = pd.DataFrame(filtered_attacks)
        df['attack_types'] = df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
        
        display_columns = ['timestamp', 'url', 'attack_types', 'severity', 'confidence']
        display_df = df[display_columns].copy()
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

def show_pattern_management():
    """Pattern Management page"""
    st.title("⚙️ Attack Pattern Management")
    st.markdown("View and manage MongoDB attack patterns")
    
    if not st.session_state.attack_patterns:
        st.warning("No attack patterns loaded from MongoDB")
        return
    
    # Statistics
    col1, col2, col3, col4 = st.columns(4)
    
    total_patterns = sum(len(p['patterns']) for p in st.session_state.attack_patterns.values())
    critical_cats = len([p for p in st.session_state.attack_patterns.values() if p['severity'] == 'CRITICAL'])
    high_cats = len([p for p in st.session_state.attack_patterns.values() if p['severity'] == 'HIGH'])
    
    with col1:
        st.metric("Total Categories", len(st.session_state.attack_patterns))
    with col2:
        st.metric("Total Patterns", total_patterns)
    with col3:
        st.metric("Critical Categories", critical_cats)
    with col4:
        st.metric("High Categories", high_cats)
    
    st.markdown("---")
    
    # Pattern browser
    st.subheader("📋 Pattern Categories")
    
    for attack_id, pattern_data in st.session_state.attack_patterns.items():
        with st.expander(f"{pattern_data['category']} - {pattern_data['severity']} ({len(pattern_data['patterns'])} patterns)"):
            st.write(f"**Description:** {pattern_data['description']}")
            st.write(f"**Severity:** {pattern_data['severity']}")
            st.write(f"**Pattern Count:** {len(pattern_data['patterns'])}")
            
            st.write("**Sample Patterns:**")
            for i, pattern in enumerate(pattern_data['patterns'][:5]):
                st.markdown(f"**{i+1}. {pattern['description']}**")
                st.code(f"Regex: {pattern['regex'][:100]}...", language="regex")
                if pattern.get('example'):
                    st.code(f"Example: {pattern['example']}", language="text")
                st.markdown("---")
            
            if pattern_data.get('mitigation'):
                st.write("**Mitigation Strategies:**")
                for mitigation in pattern_data['mitigation'][:5]:
                    st.markdown(f"- {mitigation}")
    
    # Refresh patterns button
    st.markdown("---")
    if st.button("🔄 Refresh Patterns from MongoDB", type="primary"):
        with st.spinner("Reloading patterns..."):
            patterns = load_attack_patterns(st.session_state.mongodb_db)
            st.session_state.attack_patterns = patterns
            st.success(f"✅ Reloaded {len(patterns)} attack categories")
            st.rerun()

def show_export():
    """Export & Reports page"""
    st.title("📥 Export & Report Generation")
    
    if not st.session_state.attacks_db:
        st.info("No data available for export. Analyze some URLs first.")
        return
    
    st.markdown("### Export Options")
    
    # Export format selection
    export_format = st.radio(
        "Select Export Format",
        ["CSV", "JSON", "PDF Report (Summary)", "Excel"],
        horizontal=True
    )
    
    # Data selection
    st.markdown("### Data Selection")
    col1, col2 = st.columns(2)
    
    with col1:
        include_url = st.checkbox("Include full URLs", value=True)
        include_patterns = st.checkbox("Include pattern matches", value=True)
    
    with col2:
        include_timestamp = st.checkbox("Include timestamps", value=True)
        include_confidence = st.checkbox("Include confidence scores", value=True)
    
    # Date range filter
    st.markdown("### Filter by Date Range")
    df = pd.DataFrame(st.session_state.attacks_db)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    
    date_range = st.date_input(
        "Select date range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    if len(date_range) == 2:
        start_date, end_date = date_range
        filtered_df = df[(df['timestamp'].dt.date >= start_date) & (df['timestamp'].dt.date <= end_date)]
    else:
        filtered_df = df
    
    st.info(f"📊 {len(filtered_df)} attacks in selected date range")
    
    # Generate export
    if st.button("🚀 Generate Export", type="primary"):
        with st.spinner("Generating export..."):
            export_data = filtered_df.copy()
            
            if export_format == "CSV":
                csv = export_data.to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"cyber_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
                st.success("✅ CSV export ready!")
            
            elif export_format == "JSON":
                json_data = export_data.to_json(orient='records', date_format='iso')
                st.download_button(
                    label="📥 Download JSON",
                    data=json_data,
                    file_name=f"cyber_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
                st.success("✅ JSON export ready!")
            
            elif export_format == "PDF Report (Summary)":
                report = generate_summary_report(filtered_df)
                st.download_button(
                    label="📥 Download Report",
                    data=report,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
                st.success("✅ Report generated!")
            
            elif export_format == "Excel":
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    export_data.to_excel(writer, sheet_name='Attacks', index=False)
                
                st.download_button(
                    label="📥 Download Excel",
                    data=output.getvalue(),
                    file_name=f"cyber_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
                st.success("✅ Excel export ready!")
    
    # MongoDB Statistics
    st.markdown("---")
    st.markdown("### 📊 MongoDB Statistics")
    
    if st.button("📈 Load Statistics from MongoDB"):
        try:
            stats_collection = st.session_state.mongodb_db['attack_statistics']
            stats = stats_collection.find_one({'stat_id': 'initial'})
            
            if stats:
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("Total Detections", stats.get('total_detections', 0))
                    st.write("**Detections by Severity:**")
                    for severity, count in stats.get('detections_by_severity', {}).items():
                        st.write(f"  • {severity}: {count}")
                
                with col2:
                    st.write("**Top Attack Categories:**")
                    categories = stats.get('detections_by_category', {})
                    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]
                    for cat, count in sorted_cats:
                        st.write(f"  • {cat}: {count}")
            else:
                st.info("No statistics available in MongoDB")
        
        except Exception as e:
            st.error(f"Error loading statistics: {str(e)}")

def generate_summary_report(df):
    """Generate a text-based summary report"""
    report = f"""
CYBER ATTACK DETECTION SYSTEM
MongoDB-Powered Security Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'='*60}
EXECUTIVE SUMMARY
{'='*60}

Total Attacks Detected: {len(df)}
Date Range: {df['timestamp'].min()} to {df['timestamp'].max()}

Severity Breakdown:
{df['severity'].value_counts().to_string()}

Top Attack Types:
"""
    
    attack_types = []
    for attacks in df['attack_types']:
        if isinstance(attacks, list):
            attack_types.extend(attacks)
    
    type_counts = Counter(attack_types)
    for attack_type, count in type_counts.most_common(5):
        report += f"\n  - {attack_type}: {count}"
    
    report += f"""

Average Confidence Score: {df['confidence'].mean():.1f}%

{'='*60}
RECOMMENDATIONS
{'='*60}

1. Review and block IPs associated with critical threats
2. Update WAF rules based on detected attack patterns
3. Conduct security awareness training
4. Implement rate limiting for suspicious endpoints
5. Enable detailed logging for forensic analysis

{'='*60}
MongoDB Attack Patterns Used
Total Pattern Categories: {len(st.session_state.attack_patterns)}
Total Detection Patterns: {sum(len(p['patterns']) for p in st.session_state.attack_patterns.values())}

End of Report
"""
    
    return report

if __name__ == "__main__":
    main()
