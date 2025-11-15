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
import base64

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
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'attacks_db' not in st.session_state:
    st.session_state.attacks_db = []
if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []
if 'api_key' not in st.session_state:
    st.session_state.api_key = ""

# Gemini API Configuration
def configure_gemini(api_key):
    """Configure Google Gemini API"""
    try:
        genai.configure(api_key=api_key)
        return True
    except Exception as e:
        st.error(f"Error configuring Gemini API: {str(e)}")
        return False

# Attack Detection Functions
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
        r"(admin|root|user)'?\s*(--|#|/\*)": "Authentication bypass attempt"
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
        r"document\.(write|cookie|location)": "DOM manipulation"
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
        r"\.\.%252f": "Double encoded traversal"
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
        r"\b(cat|ls|whoami|ping|curl|wget)\b": "System command",
        r"[|&]{2}": "Command chaining",
        r">\s*[/\\]": "Output redirection"
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
        r"(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)" : "Internal IP address",
        r"169\.254\.169\.254": "Cloud metadata endpoint",
        r"file://|gopher://|dict://": "Suspicious protocol",
        r"@.*\.(local|internal)": "Internal domain"
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
        r"http[s]?://.*\.(txt|php|asp)": "Remote file URL"
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
        r"file://": "File protocol in XML"
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
        r"(cmd|shell|backdoor|webshell)\.": "Suspicious filename",
        r"upload.*\.(php|asp|jsp)": "Upload with executable extension"
    }
    
    for pattern, description in patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            indicators.append(description)
    
    return len(indicators) > 0, indicators

def quick_detection(url):
    """Quick pattern-based detection before Gemini API"""
    results = {
        "SQL Injection": detect_sql_injection(url),
        "Cross-Site Scripting (XSS)": detect_xss(url),
        "Path Traversal": detect_path_traversal(url),
        "Command Injection": detect_command_injection(url),
        "SSRF": detect_ssrf(url),
        "LFI/RFI": detect_lfi_rfi(url),
        "XXE Injection": detect_xxe(url),
        "Web Shell Upload": detect_web_shell(url)
    }
    
    detected_attacks = []
    all_indicators = []
    
    for attack_type, (detected, indicators) in results.items():
        if detected:
            detected_attacks.append(attack_type)
            all_indicators.extend(indicators)
    
    return detected_attacks, all_indicators

def analyze_with_gemini(url, quick_results):
    """Analyze URL with Google Gemini API"""
    if not st.session_state.api_key:
        return None
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""As a cybersecurity expert, analyze this URL for potential attacks:

URL: {url}

Pre-detected patterns: {', '.join(quick_results) if quick_results else 'None'}

Identify attack type(s) from:
- SQL Injection (specify type: union-based, boolean-based, time-based, error-based)
- XSS (specify: reflected, stored, DOM-based)
- Directory/Path Traversal
- Command Injection
- SSRF (Server-Side Request Forgery)
- Typosquatting/URL Spoofing
- LFI/RFI (Local/Remote File Inclusion)
- Credential Stuffing/Brute Force
- HTTP Parameter Pollution
- XXE Injection
- Web Shell Upload

Provide response in this exact JSON format:
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
        # Remove markdown code blocks if present
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
        # Base confidence on number of indicators
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

# Main Application
def main():
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/clouds/200/security-checked.png", width=150)
        st.title("🛡️ Cyber Attack Detector")
        st.markdown("---")
        
        # API Key Input
        api_key = st.text_input("🔑 Google Gemini API Key", type="password", value=st.session_state.api_key)
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
            "📥 Export & Reports"
        ])
        
        st.markdown("---")
        st.info("💡 **Tip**: Configure your Gemini API key for enhanced AI-powered detection!")
        
        # Stats
        if st.session_state.attacks_db:
            st.metric("Total Attacks Detected", len(st.session_state.attacks_db))
            
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
    elif "Export" in page:
        show_export()

def show_dashboard():
    """Dashboard page"""
    st.markdown('<p class="main-header">🛡️ Cyber Attack Detection System</p>', unsafe_allow_html=True)
    st.markdown("### AI-Powered URL Analysis with Google Gemini")
    
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
            # Format the dataframe
            display_df = pd.DataFrame({
                'Timestamp': df['timestamp'],
                'URL (Preview)': df['url'].str[:50] + '...',
                'Attack Types': df['attack_types'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x),
                'Severity': df['severity'],
                'Confidence': df['confidence'].apply(lambda x: f"{x}%")
            })
            st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.info("No detections yet. Start analyzing URLs to see results here!")

def show_url_analysis():
    """URL Analysis page"""
    st.title("🔍 Single URL Analysis")
    st.markdown("Enter a URL or HTTP request to analyze for potential cyber attacks")
    
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
            st.warning("⚠️ Configure Gemini API key in sidebar for AI analysis")
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL..."):
            # Quick detection
            quick_attacks, quick_indicators = quick_detection(url_input)
            
            # Gemini analysis
            gemini_result = None
            if use_gemini and st.session_state.api_key:
                with st.spinner("🤖 Running Gemini AI analysis..."):
                    time.sleep(1)  # Simulate processing
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
                explanation = "Pattern-based detection only (Gemini AI not used)"
                recommendations = []
                is_malicious = len(attack_types) > 0
            
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
                'recommendations': recommendations
            }
            
            st.session_state.analysis_history.append(analysis_record)
            
            if is_malicious:
                st.session_state.attacks_db.append(analysis_record)
            
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
                    st.subheader("💡 Recommendations")
                    for rec in recommendations:
                        st.markdown(f"- {rec}")
                
            else:
                st.markdown(f'<div class="safe-card">', unsafe_allow_html=True)
                st.success("✅ **NO THREATS DETECTED**")
                st.markdown('</div>', unsafe_allow_html=True)
                
                st.info("The URL appears to be safe based on pattern analysis.")
                if explanation:
                    st.markdown(f"**Analysis**: {explanation}")

def show_bulk_analysis():
    """Bulk Analysis page"""
    st.title("📂 Bulk Traffic Analysis")
    st.markdown("Upload PCAP, CSV, or JSON files for batch analysis")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=['pcap', 'pcapng', 'csv', 'json', 'txt'],
        help="Supported formats: PCAP, CSV, JSON, TXT"
    )
    
    # Analysis options
    with st.expander("⚙️ Analysis Options", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            use_ai = st.checkbox("Enable Gemini AI Analysis", value=True, disabled=not st.session_state.api_key)
            deep_inspect = st.checkbox("Deep Packet Inspection", value=True)
        with col2:
            filter_ip = st.text_input("Filter by IP Range (optional)", placeholder="10.0.0.0/24")
            attack_filter = st.multiselect(
                "Filter Attack Types",
                ["SQL Injection", "XSS", "Path Traversal", "Command Injection", "SSRF"],
                default=[]
            )
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: {uploaded_file.name}")
        
        if st.button("🚀 Start Analysis", type="primary"):
            with st.spinner("Processing file..."):
                try:
                    # Read file based on type
                    if uploaded_file.name.endswith('.csv'):
                        df = pd.read_csv(uploaded_file)
                        st.info(f"📊 Loaded {len(df)} rows from CSV")
                        
                        # Assume CSV has 'url' column
                        if 'url' in df.columns:
                            urls = df['url'].tolist()
                        else:
                            st.error("CSV must contain a 'url' column")
                            return
                    
                    elif uploaded_file.name.endswith('.json'):
                        data = json.load(uploaded_file)
                        if isinstance(data, list):
                            urls = [item.get('url', '') for item in data]
                        else:
                            urls = [data.get('url', '')]
                        st.info(f"📊 Loaded {len(urls)} URLs from JSON")
                    
                    elif uploaded_file.name.endswith('.txt'):
                        content = uploaded_file.read().decode('utf-8')
                        urls = [line.strip() for line in content.split('\n') if line.strip()]
                        st.info(f"📊 Loaded {len(urls)} URLs from text file")
                    
                    else:
                        st.error("PCAP parsing requires additional libraries (scapy/dpkt). Please use CSV, JSON, or TXT format.")
                        return
                    
                    # Progress bar
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results_container = st.empty()
                    
                    results = []
                    for idx, url in enumerate(urls):
                        if url:
                            status_text.text(f"Analyzing {idx + 1}/{len(urls)}: {url[:50]}...")
                            
                            quick_attacks, quick_indicators = quick_detection(url)
                            
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
                        
                        progress_bar.progress((idx + 1) / len(urls))
                    
                    status_text.text("✅ Analysis complete!")
                    
                    # Display results
                    st.success(f"🎯 Found {len(results)} potential attacks out of {len(urls)} URLs")
                    
                    if results:
                        results_df = pd.DataFrame(results)
                        results_df['attack_types'] = results_df['attack_types'].apply(lambda x: ', '.join(x))
                        st.dataframe(results_df, use_container_width=True)
                        
                        # Download results
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Results (CSV)",
                            data=csv,
                            file_name=f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")

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
        
        # Select columns to display
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
    
    # Top attacked patterns
    st.subheader("🔝 Most Common Attack Patterns")
    url_patterns = df['url'].str[:50].value_counts().head(10)
    pattern_df = pd.DataFrame({'URL Pattern': url_patterns.index, 'Frequency': url_patterns.values})
    st.dataframe(pattern_df, use_container_width=True, hide_index=True)

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
        include_indicators = st.checkbox("Include technical indicators", value=True)
        include_recommendations = st.checkbox("Include recommendations", value=False)
    
    with col2:
        include_timestamp = st.checkbox("Include timestamps", value=True)
        include_confidence = st.checkbox("Include confidence scores", value=True)
        include_severity = st.checkbox("Include severity levels", value=True)
    
    # Date range filter
    st.markdown("### Filter by Date Range")
    if st.session_state.attacks_db:
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
            time.sleep(1)  # Simulate processing
            
            # Prepare data
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
                # Generate summary report
                report = generate_summary_report(filtered_df)
                st.download_button(
                    label="📥 Download PDF Report",
                    data=report,
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )
                st.success("✅ Report generated! (Note: PDF generation requires additional libraries)")
            
            elif export_format == "Excel":
                # Create Excel file in memory
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
    
    # Report templates
    st.markdown("---")
    st.markdown("### 📋 Report Templates")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Executive Summary", use_container_width=True):
            st.info("Executive summary focuses on high-level statistics and critical threats")
            show_executive_summary(filtered_df)
    
    with col2:
        if st.button("🔬 Technical Deep Dive", use_container_width=True):
            st.info("Technical report includes detailed attack patterns and indicators")
            show_technical_report(filtered_df)

def generate_summary_report(df):
    """Generate a text-based summary report"""
    report = f"""
CYBER ATTACK DETECTION SYSTEM
Security Analysis Report
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
    
    # Get attack types
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
3. Conduct security awareness training for development teams
4. Implement rate limiting for suspicious endpoints
5. Enable detailed logging for forensic analysis

{'='*60}
End of Report
"""
    
    return report

def show_executive_summary(df):
    """Show executive summary"""
    st.markdown("### 📊 Executive Summary")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Threats", len(df))
        st.metric("Critical", len(df[df['severity'] == 'CRITICAL']))
    
    with col2:
        st.metric("High Severity", len(df[df['severity'] == 'HIGH']))
        st.metric("Avg Confidence", f"{df['confidence'].mean():.1f}%")
    
    with col3:
        unique_types = set()
        for attacks in df['attack_types']:
            if isinstance(attacks, list):
                unique_types.update(attacks)
        st.metric("Attack Types", len(unique_types))
        st.metric("Medium/Low", len(df[df['severity'].isin(['MEDIUM', 'LOW'])]))
    
    st.markdown("### 🎯 Key Findings")
    st.write(f"- Analysis period: {df['timestamp'].min()} to {df['timestamp'].max()}")
    st.write(f"- Most common attack: {Counter([item for sublist in df['attack_types'] for item in (sublist if isinstance(sublist, list) else [])]).most_common(1)[0][0] if len(df) > 0 else 'N/A'}")
    st.write(f"- Peak threat severity: {df['severity'].mode()[0] if len(df) > 0 else 'N/A'}")

def show_technical_report(df):
    """Show technical report"""
    st.markdown("### 🔬 Technical Analysis")
    
    st.markdown("#### Attack Patterns")
    attack_types = []
    for attacks in df['attack_types']:
        if isinstance(attacks, list):
            attack_types.extend(attacks)
    
    type_counts = Counter(attack_types)
    for attack_type, count in type_counts.most_common():
        percentage = (count / len(df)) * 100
        st.write(f"**{attack_type}**: {count} occurrences ({percentage:.1f}%)")
    
    st.markdown("#### Confidence Distribution")
    st.write(f"- Mean: {df['confidence'].mean():.1f}%")
    st.write(f"- Median: {df['confidence'].median():.1f}%")
    st.write(f"- Std Dev: {df['confidence'].std():.1f}%")
    
    st.markdown("#### Sample Attacks")
    sample = df.head(5)[['timestamp', 'url', 'attack_types', 'severity']]
    sample['url'] = sample['url'].str[:60] + '...'
    st.dataframe(sample, hide_index=True)

if __name__ == "__main__":
    main()
