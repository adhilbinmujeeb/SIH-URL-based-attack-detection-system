import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
from urllib.parse import unquote, urlparse
import tempfile
import os
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import json

# PCAP parsing libraries
try:
    from scapy.all import rdpcap, TCP, IP, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Page configuration
st.set_page_config(
    page_title="HTTP Attack Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .attack-alert {
        background-color: #ffebee;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #f44336;
    }
    .success-box {
        background-color: #e8f5e9;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #4caf50;
    }
</style>
""", unsafe_allow_html=True)

# Attack pattern definitions
ATTACK_PATTERNS = {
    'sql_injection': [
        r"(\bunion\b.*\bselect\b)", r"(\bselect\b.*\bfrom\b)", 
        r"(\binsert\b.*\binto\b)", r"(\bdelete\b.*\bfrom\b)",
        r"(\bdrop\b.*\btable\b)", r"(\bupdate\b.*\bset\b)",
        r"'.*--", r"'.*or.*'.*=.*'", r"\bor\b.*\b1\b.*=.*\b1\b",
        r"%27", r"0x[0-9a-f]+", r"\bunion\b", r"\bexec\b",
        r"char\(", r"concat\(", r"information_schema"
    ],
    'xss': [
        r"<script[^>]*>.*?</script>", r"javascript:", r"onerror\s*=",
        r"onload\s*=", r"<img[^>]+src", r"<iframe", r"alert\(",
        r"document\.cookie", r"<svg", r"onmouseover\s*=",
        r"%3Cscript", r"expression\(", r"vbscript:"
    ],
    'directory_traversal': [
        r"\.\./", r"\.\.", r"%2e%2e", r"\.\.\\",
        r"/etc/passwd", r"/windows/system32", r"c:\\", r"d:\\",
        r"%2e%2e%2f", r"..%2f", r"..%5c"
    ],
    'command_injection': [
        r";\s*\w+", r"\|\s*\w+", r"&&\s*\w+", r"`.*`",
        r"\$\(.*\)", r">\s*/", r"<\s*/", r"\bwget\b",
        r"\bcurl\b", r"\bcat\b", r"\bls\b", r"\brm\b",
        r"\bchmod\b", r"\bchown\b", r"%0a", r"%0d"
    ],
    'ssrf': [
        r"(http|https)://localhost", r"(http|https)://127\.0\.0\.1",
        r"(http|https)://192\.168\.", r"(http|https)://10\.",
        r"(http|https)://172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"file://", r"dict://", r"gopher://", r"@localhost"
    ],
    'lfi_rfi': [
        r"(include|require).*\.(php|asp|jsp)", r"\.\./(.*\.php)",
        r"php://", r"data://", r"expect://", r"zip://",
        r"\?page=http", r"\?file=http", r"php://filter",
        r"php://input"
    ],
    'xxe_injection': [
        r"<!ENTITY", r"<!DOCTYPE", r"SYSTEM\s+['\"]",
        r"file:///", r"php://filter", r"<\?xml"
    ],
    'parameter_pollution': [
        r"&\w+=.*&\1=", r"\?\w+=.*&\1=", r"&{2,}",
        r"={2,}", r"%26%26", r"%3D%3D"
    ],
    'brute_force': [
        r"(login|signin|auth).*password", r"(admin|root|test)",
        r"(passwd|pwd|pass)=", r"user(name)?="
    ],
    'web_shell': [
        r"cmd\.jsp", r"backdoor\.(php|asp|jsp)", r"shell\.(php|asp|jsp)",
        r"c99\.php", r"r57\.php", r"webshell", r"eval\(base64_decode"
    ],
    'typosquatting': [
        r"g00gle", r"faceb00k", r"yah00", r"micros0ft",
        r"paypa1", r"amazon[^\.com]", r"\d+[a-z]+\d+"
    ]
}

class HTTPAttackDetector:
    """Main class for HTTP attack detection"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        
    def extract_url_features(self, url):
        """Extract features from URL for ML model"""
        if pd.isna(url) or url == '':
            url = ''
        
        url_decoded = unquote(str(url))
        
        features = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_slashes': url.count('/'),
            'num_questionmarks': url.count('?'),
            'num_ampersands': url.count('&'),
            'num_equals': url.count('='),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_percent': url.count('%'),
            'num_special_chars': sum([url.count(c) for c in ['<', '>', '"', "'", ';', '(', ')', '{', '}', '[', ']']]),
            'has_script_tag': int('<script' in url_decoded.lower()),
            'has_sql_keywords': int(bool(re.search(r'\b(select|union|insert|update|delete|drop|exec|execute)\b', url_decoded.lower()))),
            'has_traversal': int(bool(re.search(r'\.\.|%2e%2e', url_decoded.lower()))),
            'has_command_chars': int(bool(re.search(r'[|;&`$]', url))),
            'entropy': self._calculate_entropy(url),
            'digit_ratio': sum(c.isdigit() for c in url) / max(len(url), 1),
            'uppercase_ratio': sum(c.isupper() for c in url) / max(len(url), 1),
        }
        
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        entropy = 0
        for x in set(text):
            p_x = text.count(x) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def detect_attack_type(self, url):
        """Detect specific attack type using pattern matching"""
        if pd.isna(url) or url == '':
            return 'benign'
        
        url_decoded = unquote(str(url).lower())
        detected_attacks = []
        
        for attack_type, patterns in ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_decoded, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        if detected_attacks:
            return detected_attacks[0]  # Return first detected attack
        return 'benign'
    
    def train_model(self, df, url_column, label_column):
        """Train the ML model"""
        st.info("Training model... This may take a few minutes.")
        
        # Extract features
        features_list = []
        progress_bar = st.progress(0)
        
        for idx, row in df.iterrows():
            features = self.extract_url_features(row[url_column])
            features_list.append(features)
            if idx % 1000 == 0:
                progress_bar.progress(min(idx / len(df), 1.0))
        
        progress_bar.progress(1.0)
        
        X = pd.DataFrame(features_list)
        self.feature_names = X.columns.tolist()
        
        # Encode labels
        y = self.label_encoder.fit_transform(df[label_column])
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        return accuracy, X_test, y_test, y_pred
    
    def predict(self, url):
        """Predict attack type for a single URL"""
        if self.model is None:
            return "benign", 0.0, "benign"
        
        features = self.extract_url_features(url)
        X = pd.DataFrame([features])
        
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = max(probabilities)
        
        label = self.label_encoder.inverse_transform([prediction])[0]
        
        # Also use pattern matching
        pattern_detection = self.detect_attack_type(url)
        
        return label, confidence, pattern_detection


def parse_pcap_with_scapy(pcap_file):
    """Parse PCAP file using Scapy"""
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        tmp.write(pcap_file.read())
        tmp_path = tmp.name
    
    try:
        packets = rdpcap(tmp_path)
        
        http_requests = []
        packet_count = 0
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, packet in enumerate(packets):
            if i % 100 == 0:
                progress_bar.progress(min(i / len(packets), 1.0))
                status_text.text(f"Processing packet {i}/{len(packets)}")
            
            # Check if packet has HTTP layer
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = packet[Raw].load
                
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    # Check for HTTP request
                    if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                        lines = payload_str.split('\r\n')
                        if lines:
                            request_line = lines[0]
                            parts = request_line.split(' ')
                            
                            if len(parts) >= 2:
                                method = parts[0]
                                uri = parts[1]
                                
                                # Extract headers
                                headers = {}
                                for line in lines[1:]:
                                    if ':' in line:
                                        key, value = line.split(':', 1)
                                        headers[key.strip().lower()] = value.strip()
                                
                                # Get source and destination
                                src_ip = packet[IP].src if packet.haslayer(IP) else ''
                                dst_ip = packet[IP].dst if packet.haslayer(IP) else ''
                                src_port = packet[TCP].sport if packet.haslayer(TCP) else 0
                                dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
                                
                                # Get timestamp
                                timestamp = packet.time
                                
                                http_requests.append({
                                    'packet_number': packet_count,
                                    'timestamp': pd.Timestamp(timestamp, unit='s'),
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'src_port': src_port,
                                    'dst_port': dst_port,
                                    'method': method,
                                    'uri': uri,
                                    'host': headers.get('host', ''),
                                    'user_agent': headers.get('user-agent', ''),
                                    'referer': headers.get('referer', ''),
                                    'full_url': f"http://{headers.get('host', '')}{uri}" if headers.get('host') else uri
                                })
                                
                                packet_count += 1
                
                except Exception as e:
                    continue
        
        progress_bar.progress(1.0)
        status_text.text(f"Completed! Found {len(http_requests)} HTTP requests")
        
        if http_requests:
            df = pd.DataFrame(http_requests)
            return df
        else:
            return None
            
    except Exception as e:
        st.error(f"Error parsing PCAP: {str(e)}")
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except:
            pass


def main():
    st.markdown('<h1 class="main-header">🛡️ HTTP Attack Detection System</h1>', unsafe_allow_html=True)
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        st.error("⚠️ Scapy library not found! Please install it using: `pip install scapy`")
        st.stop()
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=100)
        st.title("Navigation")
        page = st.radio("Choose a page:", 
                       ["📊 Train Model", "🔍 Analyze PCAP", "📈 Dashboard"])
        
        st.markdown("---")
        st.markdown("### About")
        st.info("""
        This system detects HTTP URL-based attacks including:
        - SQL Injection
        - XSS (Cross-Site Scripting)
        - Directory Traversal
        - Command Injection
        - SSRF
        - LFI/RFI
        - XXE Injection
        - Parameter Pollution
        - Brute Force
        - Web Shell Uploads
        - Typosquatting
        """)
        
        st.markdown("---")
        st.markdown("### System Status")
        st.success("✅ Scapy Available")
    
    # Initialize session state
    if 'detector' not in st.session_state:
        st.session_state.detector = HTTPAttackDetector()
    if 'model_trained' not in st.session_state:
        st.session_state.model_trained = False
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None
    
    # Page routing
    if page == "📊 Train Model":
        train_model_page()
    elif page == "🔍 Analyze PCAP":
        analyze_pcap_page()
    elif page == "📈 Dashboard":
        dashboard_page()


def train_model_page():
    st.header("📊 Train Attack Detection Model")
    
    st.markdown("""
    Upload your training dataset (CSV format) to train the machine learning model.
    The dataset should contain URL data and corresponding labels (benign/anomalous/attack types).
    
    **Supported Datasets:**
    - CSIC 2010 HTTP Dataset
    - Attack Simulation Dataset
    - Custom labeled datasets
    """)
    
    uploaded_file = st.file_uploader("Upload Training Dataset (CSV)", type=['csv'])
    
    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)
            
            st.subheader("Dataset Preview")
            st.dataframe(df.head(100), use_container_width=True)
            
            st.subheader("Dataset Information")
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Rows", f"{len(df):,}")
            with col2:
                st.metric("Total Columns", len(df.columns))
            with col3:
                st.metric("Memory Usage", f"{df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            # Column selection
            st.subheader("Select Columns")
            col1, col2 = st.columns(2)
            
            with col1:
                url_column = st.selectbox("URL Column", df.columns, 
                                         help="Select the column containing URLs or request URIs")
            with col2:
                label_column = st.selectbox("Label Column", df.columns,
                                           help="Select the column containing labels (benign/anomalous)")
            
            # Show label distribution
            if label_column:
                st.subheader("Label Distribution")
                label_counts = df[label_column].value_counts()
                
                col1, col2 = st.columns([2, 1])
                with col1:
                    fig = px.bar(x=label_counts.index, y=label_counts.values,
                                labels={'x': 'Class', 'y': 'Count'},
                                title="Class Distribution",
                                color=label_counts.values,
                                color_continuous_scale='blues')
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.markdown("#### Class Statistics")
                    for label, count in label_counts.items():
                        percentage = (count / len(df)) * 100
                        st.metric(label, f"{count:,}", f"{percentage:.1f}%")
            
            # Train button
            if st.button("🚀 Train Model", type="primary", use_container_width=True):
                with st.spinner("Training model..."):
                    accuracy, X_test, y_test, y_pred = st.session_state.detector.train_model(
                        df, url_column, label_column
                    )
                    st.session_state.model_trained = True
                    
                    st.success(f"✅ Model trained successfully! Test Accuracy: {accuracy:.2%}")
                    
                    # Show confusion matrix
                    st.subheader("Confusion Matrix")
                    cm = confusion_matrix(y_test, y_pred)
                    classes = st.session_state.detector.label_encoder.classes_
                    
                    fig = go.Figure(data=go.Heatmap(
                        z=cm,
                        x=classes,
                        y=classes,
                        colorscale='Blues',
                        text=cm,
                        texttemplate='%{text}',
                        textfont={"size": 16}
                    ))
                    fig.update_layout(
                        title="Confusion Matrix",
                        xaxis_title="Predicted",
                        yaxis_title="Actual",
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Classification report
                    st.subheader("Classification Report")
                    report = classification_report(y_test, y_pred, 
                                                   target_names=classes,
                                                   output_dict=True)
                    report_df = pd.DataFrame(report).transpose()
                    st.dataframe(report_df.style.format("{:.2f}"), use_container_width=True)
                    
                    # Feature importance
                    st.subheader("Feature Importance")
                    feature_importance = pd.DataFrame({
                        'feature': st.session_state.detector.feature_names,
                        'importance': st.session_state.detector.model.feature_importances_
                    }).sort_values('importance', ascending=False)
                    
                    fig = px.bar(feature_importance.head(10), x='importance', y='feature',
                               orientation='h', title="Top 10 Important Features",
                               color='importance', color_continuous_scale='viridis')
                    st.plotly_chart(fig, use_container_width=True)
                    
        except Exception as e:
            st.error(f"Error loading dataset: {str(e)}")


def analyze_pcap_page():
    st.header("🔍 Analyze PCAP/PCAPNG Files")
    
    if not st.session_state.model_trained:
        st.warning("⚠️ Please train the model first in the 'Train Model' page.")
        st.info("💡 You can still upload a PCAP file and use pattern-based detection!")
        use_ml = False
    else:
        use_ml = True
        st.success("✅ Model is trained and ready!")
    
    st.markdown("""
    Upload a PCAP or PCAPNG file to analyze HTTP traffic and detect potential attacks.
    
    **Supported Formats:**
    - `.pcap` - Standard PCAP format
    - `.pcapng` - Next Generation PCAP format
    - `.cap` - Capture files
    """)
    
    uploaded_pcap = st.file_uploader("Upload PCAP/PCAPNG File", 
                                     type=['pcap', 'pcapng', 'cap'])
    
    if uploaded_pcap:
        st.info(f"📁 File: {uploaded_pcap.name} ({uploaded_pcap.size / 1024:.2f} KB)")
        
        with st.spinner("Parsing PCAP file... This may take a while for large files."):
            df = parse_pcap_with_scapy(uploaded_pcap)
        
        if df is not None and len(df) > 0:
            st.success(f"✅ Successfully parsed {len(df)} HTTP requests")
            
            # Show sample requests
            with st.expander("📋 View Sample Requests"):
                st.dataframe(df.head(20), use_container_width=True)
            
            # Analyze traffic
            with st.spinner("Analyzing traffic for attacks..."):
                results = []
                
                progress_bar = st.progress(0)
                
                for idx, row in df.iterrows():
                    if idx % 10 == 0:
                        progress_bar.progress(min(idx / len(df), 1.0))
                    
                    url = row.get('uri', '') or row.get('full_url', '')
                    
                    if url:
                        if use_ml:
                            ml_prediction, confidence, pattern_detection = st.session_state.detector.predict(url)
                        else:
                            ml_prediction = 'unknown'
                            confidence = 0.0
                            pattern_detection = st.session_state.detector.detect_attack_type(url)
                        
                        results.append({
                            'packet_number': row.get('packet_number', idx),
                            'timestamp': row.get('timestamp', ''),
                            'src_ip': row.get('src_ip', ''),
                            'dst_ip': row.get('dst_ip', ''),
                            'src_port': row.get('src_port', ''),
                            'dst_port': row.get('dst_port', ''),
                            'method': row.get('method', ''),
                            'url': url,
                            'host': row.get('host', ''),
                            'user_agent': row.get('user_agent', ''),
                            'ml_prediction': ml_prediction,
                            'confidence': confidence,
                            'pattern_detection': pattern_detection,
                            'final_verdict': pattern_detection if pattern_detection != 'benign' else ml_prediction
                        })
                
                progress_bar.progress(1.0)
                results_df = pd.DataFrame(results)
                st.session_state.analysis_results = results_df
            
            # Display results
            st.subheader("📊 Analysis Results")
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            total_requests = len(results_df)
            attacks_detected = len(results_df[results_df['final_verdict'] != 'benign'])
            benign_requests = total_requests - attacks_detected
            attack_rate = (attacks_detected / total_requests * 100) if total_requests > 0 else 0
            
            with col1:
                st.metric("Total Requests", f"{total_requests:,}")
            with col2:
                st.metric("🚨 Attacks Detected", f"{attacks_detected:,}", 
                         delta=f"{attack_rate:.1f}%", delta_color="inverse")
            with col3:
                st.metric("✅ Benign Requests", f"{benign_requests:,}")
            with col4:
                if use_ml:
                    avg_confidence = results_df['confidence'].mean()
                    st.metric("Avg Confidence", f"{avg_confidence:.2%}")
                else:
                    st.metric("Detection Mode", "Pattern-based")
            
            # Attack distribution
            if attacks_detected > 0:
                st.subheader("🎯 Attack Type Distribution")
                attack_types = results_df[results_df['final_verdict'] != 'benign']['final_verdict'].value_counts()
                
                col1, col2 = st.columns([2, 1])
                with col1:
                    fig = px.pie(values=attack_types.values, names=attack_types.index,
                               title="Detected Attack Types",
                               hole=0.4)
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    st.markdown("#### Attack Summary")
                    for attack_type, count in attack_types.items():
                        st.markdown(f"**{attack_type.upper()}**: {count}")
            
            # Detailed results
            st.subheader("📋 Detailed Results")
            
            # Filter options
            col1, col2, col3 = st.columns(3)
            with col1:
                filter_type = st.multiselect("Filter by Attack Type",
                                            options=sorted(results_df['final_verdict'].unique()),
                                            default=sorted(results_df['final_verdict'].unique()))
            with col2:
                if use_ml:
                    min_confidence = st.slider("Minimum Confidence", 0.0, 1.0, 0.0)
                else:
                    min_confidence = 0.0
            with col3:
                show_benign = st.checkbox("Show Benign Traffic", value=True)
            
            # Apply filters
            filtered_df = results_df[results_df['final_verdict'].isin(filter_type)]
            if use_ml:
                filtered_df = filtered_df[filtered_df['confidence'] >= min_confidence]
            if not show_benign:
                filtered_df = filtered_df[filtered_df['final_verdict'] != 'benign']
            
            # Highlight attacks
            def highlight_attacks(row):
                if row['final_verdict'] != 'benign':
                    return ['background-color: #ffebee'] * len(row)
                return [''] * len(row)
            
            st.dataframe(
                filtered_df[['packet_number', 'timestamp', 'src_ip', 'dst_ip', 
                           'method', 'host', 'url', 'final_verdict', 'confidence']]
                .style.apply(highlight_attacks, axis=1),
                use_container_width=True, 
                height=400
            )
            
            # Export options
            st.subheader("💾 Export Results")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                csv = results_df.to_csv(index=False)
                st.download_button("📥 Download Full Results (CSV)", 
                                 csv, 
                                 "attack_analysis_full.csv", 
                                 "text/csv",
                                 use_container_width=True)
            
            with col2:
                attacks_only = results_df[results_df['final_verdict'] != 'benign']
                csv_attacks = attacks_only.to_csv(index=False)
                st.download_button("📥 Download Attacks Only (CSV)", 
                                 csv_attacks, 
                                 "attack_analysis_attacks.csv", 
                                 "text/csv",
                                 use_container_width=True)
            
            with col3:
                json_data = results_df.to_json(orient='records', indent=2)
                st.download_button("📥 Download JSON", 
                                 json_data, 
                                 "attack_analysis.json", 
                                 "application/json",
                                 use_container_width=True)
        
        else:
            st.error("❌ No HTTP traffic found in the PCAP file. Please ensure the file contains HTTP requests.")


def dashboard_page():
    st.header("📈 Analysis Dashboard")
    
    if st.session_state.analysis_results is None:
        st.info("ℹ️ No analysis results available. Please analyze a PCAP file first.")
        return
    
    results_df = st.session_state.analysis_results
    
    # Overview metrics
    st.subheader("📊 Overview Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    total = len(results_df)
    attacks = len(results_df[results_df['final_verdict'] != 'benign'])
    benign = total - attacks
    unique_ips = results_df['src_ip'].nunique()
    
    with col1:
        st.metric("Total Requests", f"{total:,}")
    with col2:
        st.metric("Attacks Detected", f"{attacks:,}", delta=f"{(attacks/total*100):.1f}%")
    with col3:
        st.metric("Benign Traffic", f"{benign:,}")
    with col4:
        st.metric("Unique Source IPs", unique_ips)
    
    # Time series analysis
    if 'timestamp' in results_df.columns and results_df['timestamp'].notna().any():
        st.subheader("📈 Attack Timeline")
        
        # Ensure timestamps are datetime
        results_df['timestamp_parsed'] = pd.to_datetime(results_df['timestamp'], errors='coerce')
        
        # Group by time intervals
        time_freq = st.selectbox("Time Resolution", 
                                ['1min', '5min', '10min', '30min', '1H'],
                                index=2)
        
        timeline_df = results_df.groupby([
            pd.Grouper(key='timestamp_parsed', freq=time_freq), 
            'final_verdict'
        ]).size().reset_index(name='count')
        
        fig = px.line(timeline_df, x='timestamp_parsed', y='count', 
                     color='final_verdict',
                     title=f"Traffic Over Time (grouped by {time_freq})",
                     labels={'timestamp_parsed': 'Time', 'count': 'Number of Requests'},
                     markers=True)
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Attack type distribution
    st.subheader("🎯 Attack Type Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        attack_counts = results_df['final_verdict'].value_counts()
        fig = px.bar(x=attack_counts.index, y=attack_counts.values,
                    title="Overall Traffic Classification",
                    labels={'x': 'Classification', 'y': 'Count'},
                    color=attack_counts.values,
                    color_continuous_scale='reds')
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Only attacks
        attacks_only = results_df[results_df['final_verdict'] != 'benign']
        if len(attacks_only) > 0:
            attack_types = attacks_only['final_verdict'].value_counts()
            fig = px.pie(values=attack_types.values, 
                        names=attack_types.index,
                        title="Attack Type Distribution",
                        hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks detected in the analyzed traffic.")
    
    # Geographic analysis (IP-based)
    st.subheader("🌍 Source IP Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Top Source IPs (All Traffic)")
        top_ips_all = results_df['src_ip'].value_counts().head(10)
        fig = px.bar(x=top_ips_all.values, y=top_ips_all.index,
                    orientation='h',
                    labels={'x': 'Request Count', 'y': 'Source IP'},
                    title="Top 10 Most Active IPs")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### Top Attacking IPs")
        if attacks > 0:
            top_attackers = results_df[results_df['final_verdict'] != 'benign']['src_ip'].value_counts().head(10)
            fig = px.bar(x=top_attackers.values, y=top_attackers.index,
                        orientation='h',
                        labels={'x': 'Attack Count', 'y': 'Source IP'},
                        title="Top 10 Attacking IPs",
                        color=top_attackers.values,
                        color_continuous_scale='reds')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacking IPs found.")
    
    # Target analysis
    st.subheader("🎯 Target Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Most Targeted Destinations")
        top_targets = results_df['dst_ip'].value_counts().head(10)
        fig = px.bar(x=top_targets.values, y=top_targets.index,
                    orientation='h',
                    labels={'x': 'Request Count', 'y': 'Destination IP'})
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### Most Targeted Hosts")
        top_hosts = results_df[results_df['host'] != '']['host'].value_counts().head(10)
        if len(top_hosts) > 0:
            fig = px.bar(x=top_hosts.values, y=top_hosts.index,
                        orientation='h',
                        labels={'x': 'Request Count', 'y': 'Host'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No host information available.")
    
    # Method analysis
    st.subheader("🔧 HTTP Method Distribution")
    col1, col2 = st.columns(2)
    
    with col1:
        method_counts = results_df['method'].value_counts()
        fig = px.pie(values=method_counts.values, 
                    names=method_counts.index,
                    title="HTTP Methods Used")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Methods used in attacks
        if attacks > 0:
            attack_methods = results_df[results_df['final_verdict'] != 'benign']['method'].value_counts()
            fig = px.pie(values=attack_methods.values, 
                        names=attack_methods.index,
                        title="HTTP Methods in Attacks")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attacks to analyze methods.")
    
    # Confidence distribution (if ML model used)
    if 'confidence' in results_df.columns and results_df['confidence'].max() > 0:
        st.subheader("📊 Prediction Confidence Distribution")
        fig = px.histogram(results_df[results_df['confidence'] > 0], 
                          x='confidence', 
                          nbins=30,
                          title="ML Model Confidence Distribution",
                          labels={'confidence': 'Confidence Score', 'count': 'Frequency'},
                          color_discrete_sequence=['#1f77b4'])
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    
    # Detailed attack examples
    st.subheader("🔍 Sample Detected Attacks")
    
    attacks_df = results_df[results_df['final_verdict'] != 'benign'].head(20)
    
    if len(attacks_df) > 0:
        for idx, row in attacks_df.iterrows():
            attack_type = row['final_verdict']
            
            with st.expander(f"🚨 {attack_type.upper().replace('_', ' ')} - Packet #{row['packet_number']}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Timestamp:** {row['timestamp']}")
                    st.markdown(f"**Source IP:** `{row['src_ip']}:{row['src_port']}`")
                    st.markdown(f"**Destination IP:** `{row['dst_ip']}:{row['dst_port']}`")
                    st.markdown(f"**Method:** {row['method']}")
                    st.markdown(f"**Host:** {row['host']}")
                
                with col2:
                    st.markdown(f"**Attack Type:** `{attack_type}`")
                    st.markdown(f"**ML Prediction:** `{row['ml_prediction']}`")
                    st.markdown(f"**Pattern Detection:** `{row['pattern_detection']}`")
                    if row['confidence'] > 0:
                        st.markdown(f"**Confidence:** {row['confidence']:.2%}")
                    if row['user_agent']:
                        st.markdown(f"**User Agent:** {row['user_agent'][:50]}...")
                
                st.markdown("**Request URL:**")
                st.code(row['url'], language='text')
    else:
        st.info("No attacks detected in the analyzed traffic.")
    
    # Statistics table
    st.subheader("📋 Detailed Statistics")
    
    stats_data = {
        'Metric': [
            'Total Packets Analyzed',
            'Total Attacks Detected',
            'Total Benign Traffic',
            'Attack Rate',
            'Unique Source IPs',
            'Unique Destination IPs',
            'Unique Hosts',
            'HTTP Methods Used',
            'Most Common Attack Type',
            'Most Active Source IP',
            'Most Targeted Destination'
        ],
        'Value': [
            f"{total:,}",
            f"{attacks:,}",
            f"{benign:,}",
            f"{(attacks/total*100):.2f}%",
            f"{results_df['src_ip'].nunique()}",
            f"{results_df['dst_ip'].nunique()}",
            f"{results_df['host'].nunique()}",
            f"{results_df['method'].nunique()}",
            results_df[results_df['final_verdict'] != 'benign']['final_verdict'].mode()[0] if attacks > 0 else 'N/A',
            results_df['src_ip'].mode()[0] if len(results_df) > 0 else 'N/A',
            results_df['dst_ip'].mode()[0] if len(results_df) > 0 else 'N/A'
        ]
    }
    
    stats_df = pd.DataFrame(stats_data)
    st.dataframe(stats_df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
