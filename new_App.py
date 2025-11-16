import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
from urllib.parse import unquote
import subprocess
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
        for idx, row in df.iterrows():
            features = self.extract_url_features(row[url_column])
            features_list.append(features)
        
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
            return "benign", 0.0
        
        features = self.extract_url_features(url)
        X = pd.DataFrame([features])
        
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        confidence = max(probabilities)
        
        label = self.label_encoder.inverse_transform([prediction])[0]
        
        # Also use pattern matching
        pattern_detection = self.detect_attack_type(url)
        
        return label, confidence, pattern_detection


def parse_pcap_to_dataframe(pcap_file):
    """Parse PCAP file using tshark and return DataFrame"""
    
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        tmp.write(pcap_file.read())
        tmp_path = tmp.name
    
    try:
        # Check if tshark is available
        tshark_fields = [
            'frame.number', 'frame.time', 'frame.len',
            'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
            'http.request.method', 'http.request.uri', 
            'http.request.full_uri', 'http.host',
            'http.user_agent', 'http.response.code'
        ]
        
        cmd = ['tshark', '-r', tmp_path, '-T', 'fields']
        for field in tshark_fields:
            cmd.extend(['-e', field])
        cmd.extend(['-E', 'header=y', '-E', 'separator=,'])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            st.error("TShark not found. Please install Wireshark/TShark.")
            return None
        
        # Parse output
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            st.warning("No HTTP traffic found in PCAP file.")
            return None
        
        # Create DataFrame
        from io import StringIO
        df = pd.read_csv(StringIO(result.stdout))
        
        # Filter only HTTP requests
        df = df[df['http.request.uri'].notna()].reset_index(drop=True)
        
        return df
        
    except Exception as e:
        st.error(f"Error parsing PCAP: {str(e)}")
        return None
    finally:
        os.unlink(tmp_path)


def main():
    st.markdown('<h1 class="main-header">🛡️ HTTP Attack Detection System</h1>', unsafe_allow_html=True)
    
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
        - And more...
        """)
    
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
    The dataset should contain URL data and corresponding labels (benign/anomalous).
    """)
    
    uploaded_file = st.file_uploader("Upload Training Dataset (CSV)", type=['csv'])
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        
        st.subheader("Dataset Preview")
        st.dataframe(df.head(100), use_container_width=True)
        
        st.subheader("Dataset Information")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Rows", len(df))
        with col2:
            st.metric("Total Columns", len(df.columns))
        with col3:
            st.metric("Memory Usage", f"{df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        
        # Column selection
        st.subheader("Select Columns")
        col1, col2 = st.columns(2)
        
        with col1:
            url_column = st.selectbox("URL Column", df.columns)
        with col2:
            label_column = st.selectbox("Label Column", df.columns)
        
        # Show label distribution
        if label_column:
            st.subheader("Label Distribution")
            label_counts = df[label_column].value_counts()
            fig = px.bar(x=label_counts.index, y=label_counts.values,
                        labels={'x': 'Class', 'y': 'Count'},
                        title="Class Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        # Train button
        if st.button("🚀 Train Model", type="primary"):
            with st.spinner("Training model..."):
                accuracy, X_test, y_test, y_pred = st.session_state.detector.train_model(
                    df, url_column, label_column
                )
                st.session_state.model_trained = True
                
                st.success(f"✅ Model trained successfully! Accuracy: {accuracy:.2%}")
                
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
                    yaxis_title="Actual"
                )
                st.plotly_chart(fig, use_container_width=True)
                
                # Feature importance
                st.subheader("Feature Importance")
                feature_importance = pd.DataFrame({
                    'feature': st.session_state.detector.feature_names,
                    'importance': st.session_state.detector.model.feature_importances_
                }).sort_values('importance', ascending=False)
                
                fig = px.bar(feature_importance.head(10), x='importance', y='feature',
                           orientation='h', title="Top 10 Important Features")
                st.plotly_chart(fig, use_container_width=True)


def analyze_pcap_page():
    st.header("🔍 Analyze PCAP/PCAPNG Files")
    
    if not st.session_state.model_trained:
        st.warning("⚠️ Please train the model first in the 'Train Model' page.")
        return
    
    st.markdown("""
    Upload a PCAP or PCAPNG file to analyze HTTP traffic and detect potential attacks.
    
    **Requirements:** TShark must be installed on your system.
    - Linux: `sudo apt-get install tshark`
    - macOS: `brew install wireshark` (includes tshark)
    - Windows: Install Wireshark (includes tshark)
    """)
    
    uploaded_pcap = st.file_uploader("Upload PCAP/PCAPNG File", 
                                     type=['pcap', 'pcapng', 'cap'])
    
    if uploaded_pcap:
        with st.spinner("Parsing PCAP file..."):
            df = parse_pcap_to_dataframe(uploaded_pcap)
        
        if df is not None and len(df) > 0:
            st.success(f"✅ Successfully parsed {len(df)} HTTP requests")
            
            # Analyze traffic
            with st.spinner("Analyzing traffic for attacks..."):
                results = []
                
                for idx, row in df.iterrows():
                    url = row.get('http.request.uri', '') or row.get('http.request.full_uri', '')
                    
                    if url:
                        ml_prediction, confidence, pattern_detection = st.session_state.detector.predict(url)
                        
                        results.append({
                            'packet_number': row.get('frame.number', idx),
                            'timestamp': row.get('frame.time', ''),
                            'src_ip': row.get('ip.src', ''),
                            'dst_ip': row.get('ip.dst', ''),
                            'method': row.get('http.request.method', ''),
                            'url': url,
                            'host': row.get('http.host', ''),
                            'ml_prediction': ml_prediction,
                            'confidence': confidence,
                            'pattern_detection': pattern_detection,
                            'final_verdict': pattern_detection if pattern_detection != 'benign' else ml_prediction
                        })
                
                results_df = pd.DataFrame(results)
                st.session_state.analysis_results = results_df
            
            # Display results
            st.subheader("Analysis Results")
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            total_requests = len(results_df)
            attacks_detected = len(results_df[results_df['final_verdict'] != 'benign'])
            benign_requests = total_requests - attacks_detected
            attack_rate = (attacks_detected / total_requests * 100) if total_requests > 0 else 0
            
            with col1:
                st.metric("Total Requests", total_requests)
            with col2:
                st.metric("Attacks Detected", attacks_detected, delta=f"{attack_rate:.1f}%")
            with col3:
                st.metric("Benign Requests", benign_requests)
            with col4:
                avg_confidence = results_df['confidence'].mean()
                st.metric("Avg Confidence", f"{avg_confidence:.2%}")
            
            # Attack distribution
            if attacks_detected > 0:
                st.subheader("Attack Type Distribution")
                attack_types = results_df[results_df['final_verdict'] != 'benign']['final_verdict'].value_counts()
                fig = px.pie(values=attack_types.values, names=attack_types.index,
                           title="Detected Attack Types")
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed results
            st.subheader("Detailed Results")
            
            # Filter options
            col1, col2 = st.columns(2)
            with col1:
                filter_type = st.multiselect("Filter by Attack Type",
                                            options=results_df['final_verdict'].unique(),
                                            default=results_df['final_verdict'].unique())
            with col2:
                min_confidence = st.slider("Minimum Confidence", 0.0, 1.0, 0.0)
            
            filtered_df = results_df[
                (results_df['final_verdict'].isin(filter_type)) &
                (results_df['confidence'] >= min_confidence)
            ]
            
            # Highlight attacks
            def highlight_attacks(row):
                if row['final_verdict'] != 'benign':
                    return ['background-color: #ffebee'] * len(row)
                return [''] * len(row)
            
            styled_df = filtered_df.style.apply(highlight_attacks, axis=1)
            st.dataframe(styled_df, use_container_width=True, height=400)
            
            # Export options
            st.subheader("Export Results")
            col1, col2 = st.columns(2)
            
            with col1:
                csv = results_df.to_csv(index=False)
                st.download_button("📥 Download CSV", csv, "attack_analysis.csv", "text/csv")
            
            with col2:
                json_data = results_df.to_json(orient='records', indent=2)
                st.download_button("📥 Download JSON", json_data, "attack_analysis.json", "application/json")


def dashboard_page():
    st.header("📈 Analysis Dashboard")
    
    if st.session_state.analysis_results is None:
        st.info("No analysis results available. Please analyze a PCAP file first.")
        return
    
    results_df = st.session_state.analysis_results
    
    # Time series analysis
    if 'timestamp' in results_df.columns:
        st.subheader("Attack Timeline")
        
        # Parse timestamps
        results_df['timestamp_parsed'] = pd.to_datetime(results_df['timestamp'], errors='coerce')
        timeline_df = results_df.groupby([pd.Grouper(key='timestamp_parsed', freq='1min'), 'final_verdict']).size().reset_index(name='count')
        
        fig = px.line(timeline_df, x='timestamp_parsed', y='count', color='final_verdict',
                     title="Attacks Over Time", labels={'timestamp_parsed': 'Time', 'count': 'Count'})
        st.plotly_chart(fig, use_container_width=True)
    
    # Top attackers
    st.subheader("Top Source IPs")
    top_ips = results_df[results_df['final_verdict'] != 'benign']['src_ip'].value_counts().head(10)
    fig = px.bar(x=top_ips.index, y=top_ips.values,
                labels={'x': 'Source IP', 'y': 'Attack Count'},
                title="Top 10 Attacking IPs")
    st.plotly_chart(fig, use_container_width=True)
    
    # Confidence distribution
    st.subheader("Prediction Confidence Distribution")
    fig = px.histogram(results_df, x='confidence', nbins=20,
                      title="Distribution of Prediction Confidence")
    st.plotly_chart(fig, use_container_width=True)
    
    # Sample attacks
    st.subheader("Sample Detected Attacks")
    attacks = results_df[results_df['final_verdict'] != 'benign'].head(10)
    for idx, row in attacks.iterrows():
        with st.expander(f"🚨 {row['final_verdict'].upper()} - Packet #{row['packet_number']}"):
            st.markdown(f"**Source IP:** {row['src_ip']}")
            st.markdown(f"**Method:** {row['method']}")
            st.markdown(f"**Host:** {row['host']}")
            st.markdown(f"**Confidence:** {row['confidence']:.2%}")
            st.code(row['url'], language='text')


if __name__ == "__main__":
    main()
