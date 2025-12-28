"""
Desa-Secure 2025: OSINT Vendor Risk Dashboard
==============================================
A comprehensive audit tool for assessing OSINT risk of Indonesian 
Village Information System (Sistem Informasi Desa) vendors.

Focus: Domains ending in .desa.id
Author: Senior Python Developer & Cybersecurity Auditor
License: Open Source
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import socket
import ssl
import whois
import requests
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re

# =====================================================
# PAGE CONFIGURATION
# =====================================================
st.set_page_config(
    page_title="Desa-Secure 2025",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =====================================================
# CUSTOM CSS FOR MODERN UI
# =====================================================
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .risk-a { color: #28a745; font-weight: bold; }
    .risk-b { color: #20c997; font-weight: bold; }
    .risk-c { color: #ffc107; font-weight: bold; }
    .risk-d { color: #fd7e14; font-weight: bold; }
    .risk-f { color: #dc3545; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# =====================================================
# UTILITY FUNCTIONS
# =====================================================

def clean_domain(url_or_domain):
    """
    Extract clean domain from URL or domain string.
    
    Args:
        url_or_domain (str): Input URL or domain
        
    Returns:
        str: Clean domain name
    """
    # Remove protocol if present
    if '://' in url_or_domain:
        parsed = urlparse(url_or_domain)
        domain = parsed.netloc or parsed.path
    else:
        domain = url_or_domain
    
    # Remove www. prefix
    domain = re.sub(r'^www\.', '', domain)
    # Remove trailing slashes and paths
    domain = domain.split('/')[0]
    
    return domain.strip()


def validate_desa_domain(domain):
    """
    Validate if the domain ends with .desa.id
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if valid .desa.id domain
    """
    return domain.lower().endswith('.desa.id')

# =====================================================
# DOMAIN AUDIT MODULE
# =====================================================

def get_whois_data(domain):
    """
    Retrieve WHOIS information for a given domain.
    
    Args:
        domain (str): Domain name to query
        
    Returns:
        dict: WHOIS data including registrar, creation date, and expiry date
    """
    try:
        w = whois.whois(domain)
        
        # Handle creation_date and expiration_date which might be lists
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        
        return {
            'status': 'success',
            'registrar': w.registrar if w.registrar else 'N/A',
            'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'N/A',
            'expiration_date': expiration_date.strftime('%Y-%m-%d') if expiration_date else 'N/A',
            'expiration_datetime': expiration_date,
            'name_servers': w.name_servers if w.name_servers else []
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'registrar': 'N/A',
            'creation_date': 'N/A',
            'expiration_date': 'N/A',
            'expiration_datetime': None,
            'name_servers': []
        }


def resolve_domain_to_ip(domain):
    """
    Resolve domain name to IP address.
    
    Args:
        domain (str): Domain name to resolve
        
    Returns:
        dict: IP address and resolution status
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return {
            'status': 'success',
            'ip_address': ip_address
        }
    except socket.gaierror:
        return {
            'status': 'error',
            'ip_address': 'Unable to resolve',
            'error': 'DNS resolution failed'
        }
    except Exception as e:
        return {
            'status': 'error',
            'ip_address': 'Error',
            'error': str(e)
        }

# =====================================================
# SECURITY AUDIT MODULE
# =====================================================

def check_ssl_certificate(domain):
    """
    Check SSL/TLS certificate validity and details.
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        dict: SSL certificate information including validity and issuer
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                
                # Parse expiry date
                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                
                # Calculate days until expiry
                days_until_expiry = (expiry_date - datetime.now()).days
                
                return {
                    'status': 'success',
                    'has_ssl': True,
                    'issuer': dict(x[0] for x in cert['issuer'])['organizationName'],
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry,
                    'is_valid': days_until_expiry > 0
                }
    except ssl.SSLError as e:
        return {
            'status': 'error',
            'has_ssl': False,
            'error': f'SSL Error: {str(e)}',
            'issuer': 'N/A',
            'expiry_date': 'N/A',
            'days_until_expiry': 0,
            'is_valid': False
        }
    except Exception as e:
        return {
            'status': 'error',
            'has_ssl': False,
            'error': str(e),
            'issuer': 'N/A',
            'expiry_date': 'N/A',
            'days_until_expiry': 0,
            'is_valid': False
        }


def scan_common_ports(domain):
    """
    Passive port scanner for common ports.
    
    Args:
        domain (str): Domain or IP to scan
        
    Returns:
        dict: Port scanning results with status for each port
    """
    # Common ports to check
    ports_to_check = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    }
    
    results = {}
    open_ports = []
    sensitive_open = []
    
    for port, service in ports_to_check.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((domain, port))
            
            if result == 0:
                results[port] = {'status': 'open', 'service': service}
                open_ports.append(f"{port}/{service}")
                
                # Flag sensitive ports
                if port in [3306, 5432, 21, 22]:
                    sensitive_open.append(f"{port}/{service}")
            else:
                results[port] = {'status': 'closed', 'service': service}
            
            sock.close()
        except Exception as e:
            results[port] = {'status': 'error', 'service': service, 'error': str(e)}
    
    return {
        'status': 'success',
        'results': results,
        'open_ports': open_ports,
        'sensitive_open': sensitive_open
    }


def check_security_headers(domain):
    """
    Check for security headers in HTTP response.
    
    Args:
        domain (str): Domain to check
        
    Returns:
        dict: Security headers analysis
    """
    headers_to_check = [
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection'
    ]
    
    try:
        # Try HTTPS first
        try:
            response = requests.head(f'https://{domain}', timeout=5, allow_redirects=True)
        except:
            # Fallback to HTTP
            response = requests.head(f'http://{domain}', timeout=5, allow_redirects=True)
        
        found_headers = {}
        missing_headers = []
        
        for header in headers_to_check:
            if header in response.headers:
                found_headers[header] = response.headers[header]
            else:
                missing_headers.append(header)
        
        return {
            'status': 'success',
            'found_headers': found_headers,
            'missing_headers': missing_headers,
            'security_score': len(found_headers) / len(headers_to_check) * 100
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'found_headers': {},
            'missing_headers': headers_to_check,
            'security_score': 0
        }

# =====================================================
# RISK SCORING LOGIC
# =====================================================

def calculate_risk_score(whois_data, ssl_data, port_scan, headers_data):
    """
    Calculate overall risk score based on audit findings.
    
    Scoring Criteria:
    - SSL validity: 30 points
    - Domain expiry: 20 points
    - Sensitive ports: 25 points
    - Security headers: 25 points
    
    Grade Scale:
    A: 90-100 (Low Risk)
    B: 80-89 (Moderate Risk)
    C: 70-79 (Medium Risk)
    D: 60-69 (High Risk)
    F: 0-59 (Critical Risk)
    
    Args:
        whois_data (dict): WHOIS information
        ssl_data (dict): SSL certificate data
        port_scan (dict): Port scanning results
        headers_data (dict): Security headers data
        
    Returns:
        dict: Risk score, grade, and detailed breakdown
    """
    score = 0
    max_score = 100
    findings = []
    
    # 1. SSL Certificate Check (30 points)
    if ssl_data.get('has_ssl') and ssl_data.get('is_valid'):
        days_left = ssl_data.get('days_until_expiry', 0)
        if days_left > 90:
            score += 30
            findings.append("✓ Valid SSL certificate with 90+ days validity")
        elif days_left > 30:
            score += 20
            findings.append("⚠ SSL certificate expires in less than 90 days")
        else:
            score += 10
            findings.append("⚠ SSL certificate expires soon (< 30 days)")
    else:
        findings.append("✗ No valid SSL certificate found")
    
    # 2. Domain Expiry Check (20 points)
    if whois_data.get('expiration_datetime'):
        try:
            expiry = whois_data['expiration_datetime']
            days_until_expiry = (expiry - datetime.now()).days
            
            if days_until_expiry > 365:
                score += 20
                findings.append("✓ Domain valid for 365+ days")
            elif days_until_expiry > 90:
                score += 15
                findings.append("⚠ Domain expires in less than 1 year")
            elif days_until_expiry > 30:
                score += 10
                findings.append("⚠ Domain expires in less than 90 days")
            else:
                score += 5
                findings.append("✗ Domain expires soon (< 30 days)")
        except:
            score += 10
            findings.append("⚠ Unable to verify domain expiry")
    else:
        score += 10
        findings.append("⚠ Domain expiry date not available")
    
    # 3. Sensitive Ports Check (25 points)
    sensitive_open = port_scan.get('sensitive_open', [])
    if len(sensitive_open) == 0:
        score += 25
        findings.append("✓ No sensitive ports exposed")
    elif len(sensitive_open) == 1:
        score += 15
        findings.append(f"⚠ 1 sensitive port exposed: {sensitive_open[0]}")
    else:
        score += 5
        findings.append(f"✗ {len(sensitive_open)} sensitive ports exposed: {', '.join(sensitive_open)}")
    
    # 4. Security Headers Check (25 points)
    header_score = headers_data.get('security_score', 0)
    score += int(header_score * 0.25)
    
    if header_score >= 80:
        findings.append("✓ Good security headers implementation")
    elif header_score >= 40:
        findings.append("⚠ Partial security headers present")
    else:
        findings.append("✗ Missing critical security headers")
    
    # Determine grade
    if score >= 90:
        grade = 'A'
        risk_level = 'Low Risk'
    elif score >= 80:
        grade = 'B'
        risk_level = 'Moderate Risk'
    elif score >= 70:
        grade = 'C'
        risk_level = 'Medium Risk'
    elif score >= 60:
        grade = 'D'
        risk_level = 'High Risk'
    else:
        grade = 'F'
        risk_level = 'Critical Risk'
    
    return {
        'score': score,
        'max_score': max_score,
        'grade': grade,
        'risk_level': risk_level,
        'findings': findings
    }

# =====================================================
# VISUALIZATION FUNCTIONS
# =====================================================

def create_risk_gauge(score, grade):
    """
    Create a gauge chart for risk score visualization.
    
    Args:
        score (int): Risk score
        grade (str): Risk grade (A-F)
        
    Returns:
        plotly.graph_objects.Figure: Gauge chart
    """
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': f"Risk Score: Grade {grade}", 'font': {'size': 24}},
        delta={'reference': 70, 'increasing': {'color': "green"}},
        gauge={
            'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "darkblue"},
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, 60], 'color': '#ffcccc'},
                {'range': [60, 70], 'color': '#ffe5cc'},
                {'range': [70, 80], 'color': '#fff5cc'},
                {'range': [80, 90], 'color': '#e5ffcc'},
                {'range': [90, 100], 'color': '#ccffcc'}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))
    
    fig.update_layout(
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        paper_bgcolor="white",
        font={'color': "darkblue", 'family': "Arial"}
    )
    
    return fig


def create_findings_table(whois_data, ip_data, ssl_data, port_scan, headers_data):
    """
    Create a comprehensive findings table.
    
    Args:
        All audit data dictionaries
        
    Returns:
        pandas.DataFrame: Formatted findings table
    """
    findings_data = {
        'Category': [],
        'Item': [],
        'Value': [],
        'Status': []
    }
    
    # Domain Information
    findings_data['Category'].extend(['Domain', 'Domain', 'Domain', 'Domain'])
    findings_data['Item'].extend(['Registrar', 'Creation Date', 'Expiry Date', 'IP Address'])
    findings_data['Value'].extend([
        whois_data.get('registrar', 'N/A'),
        whois_data.get('creation_date', 'N/A'),
        whois_data.get('expiration_date', 'N/A'),
        ip_data.get('ip_address', 'N/A')
    ])
    findings_data['Status'].extend(['ℹ️', 'ℹ️', 'ℹ️', 'ℹ️'])
    
    # SSL Information
    ssl_status = '✅' if ssl_data.get('is_valid') else '❌'
    findings_data['Category'].extend(['Security', 'Security', 'Security'])
    findings_data['Item'].extend(['SSL Certificate', 'SSL Issuer', 'SSL Expiry'])
    findings_data['Value'].extend([
        'Valid' if ssl_data.get('is_valid') else 'Invalid/Missing',
        ssl_data.get('issuer', 'N/A'),
        ssl_data.get('expiry_date', 'N/A')
    ])
    findings_data['Status'].extend([ssl_status, 'ℹ️', 'ℹ️'])
    
    # Port Information
    open_ports = port_scan.get('open_ports', [])
    sensitive_ports = port_scan.get('sensitive_open', [])
    port_status = '❌' if sensitive_ports else '✅'
    
    findings_data['Category'].extend(['Security', 'Security'])
    findings_data['Item'].extend(['Open Ports', 'Sensitive Ports'])
    findings_data['Value'].extend([
        ', '.join(open_ports) if open_ports else 'None detected',
        ', '.join(sensitive_ports) if sensitive_ports else 'None exposed'
    ])
    findings_data['Status'].extend(['ℹ️', port_status])
    
    # Security Headers
    header_score = headers_data.get('security_score', 0)
    header_status = '✅' if header_score >= 60 else '⚠️' if header_score >= 40 else '❌'
    
    findings_data['Category'].extend(['Security'])
    findings_data['Item'].extend(['Security Headers'])
    findings_data['Value'].extend([f"{header_score:.0f}% implemented"])
    findings_data['Status'].extend([header_status])
    
    df = pd.DataFrame(findings_data)
    return df

# =====================================================
# MAIN APPLICATION
# =====================================================

def main():
    """
    Main application function for Desa-Secure 2025 dashboard.
    """
    # Sidebar - Project Information
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/security-checked.png", width=80)
        st.title("🔒 Desa-Secure 2025")
        st.markdown("---")
        st.subheader("About This Tool")
        st.markdown("""
        **OSINT Vendor Risk Dashboard** for Indonesian Village Information Systems.
        
        **Features:**
        - 🌐 Domain WHOIS Lookup
        - 🔐 SSL/TLS Certificate Check
        - 🔍 Port Security Scan
        - 🛡️ HTTP Security Headers
        - 📊 Risk Score Analysis
        
        **Target:** `.desa.id` domains
        """)
        st.markdown("---")
        st.info("🎓 **Academic Project**\nAudit Teknologi & Sistem Informasi\nSemester 5 - 2025")
        st.markdown("---")
        st.markdown("**Tech Stack:**")
        st.code("Python 3.x\nStreamlit\nPandas\nPlotly", language="")
        st.markdown("---")
        st.success("📄 **License:** Open Source")
        st.markdown("---")
        st.caption("👨‍💻 Built with ❤️ for Digital Village Security")
    
    # Main Header
    st.markdown('<div class="main-header">🔒 Desa-Secure 2025</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">OSINT Vendor Risk Dashboard for Indonesian Village Digital Ecosystem</div>', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Input Section
    st.subheader("🎯 Target Domain Input")
    col1, col2 = st.columns([3, 1])
    
    with col1:
        domain_input = st.text_input(
            "Enter domain or URL to audit:",
            placeholder="example.desa.id or https://example.desa.id",
            help="Enter a domain ending with .desa.id"
        )
    
    with col2:
        st.write("")  # Spacing
        st.write("")  # Spacing
        audit_button = st.button("🔍 Start Audit", type="primary", use_container_width=True)
    
    # Process audit when button is clicked
    if audit_button and domain_input:
        domain = clean_domain(domain_input)
        
        # Validate domain
        if not validate_desa_domain(domain):
            st.error(f"⚠️ Invalid domain: **{domain}**\n\nThis tool only supports `.desa.id` domains for Indonesian Village Information Systems.")
            return
        
        st.success(f"✅ Auditing: **{domain}**")
        st.markdown("---")
        
        # Create progress bar
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # 1. Domain Audit
        status_text.text("🔍 Performing WHOIS lookup...")
        progress_bar.progress(20)
        whois_data = get_whois_data(domain)
        
        status_text.text("🌐 Resolving IP address...")
        progress_bar.progress(30)
        ip_data = resolve_domain_to_ip(domain)
        
        # 2. Security Audit
        status_text.text("🔐 Checking SSL certificate...")
        progress_bar.progress(50)
        ssl_data = check_ssl_certificate(domain)
        
        status_text.text("🔍 Scanning common ports...")
        progress_bar.progress(70)
        port_scan = scan_common_ports(domain)
        
        status_text.text("🛡️ Analyzing security headers...")
        progress_bar.progress(85)
        headers_data = check_security_headers(domain)
        
        # 3. Risk Calculation
        status_text.text("📊 Calculating risk score...")
        progress_bar.progress(95)
        risk_data = calculate_risk_score(whois_data, ssl_data, port_scan, headers_data)
        
        progress_bar.progress(100)
        status_text.text("✅ Audit complete!")
        
        # Clear progress indicators
        import time
        time.sleep(1)
        progress_bar.empty()
        status_text.empty()
        
        st.markdown("---")
        
        # =====================================================
        # RESULTS DISPLAY
        # =====================================================
        
        # Risk Score Section
        st.header("📊 Risk Assessment")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="Risk Score",
                value=f"{risk_data['score']}/100",
                delta=f"{risk_data['score'] - 70} from threshold"
            )
        
        with col2:
            grade_class = f"risk-{risk_data['grade'].lower()}"
            st.markdown(f"**Grade**")
            st.markdown(f'<p class="{grade_class}" style="font-size: 2rem; margin: 0;">{risk_data["grade"]}</p>', unsafe_allow_html=True)
        
        with col3:
            st.metric(
                label="Risk Level",
                value=risk_data['risk_level']
            )
        
        with col4:
            ssl_status = "Valid ✅" if ssl_data.get('is_valid') else "Invalid ❌"
            st.metric(
                label="SSL Status",
                value=ssl_status
            )
        
        # Gauge Chart
        st.plotly_chart(create_risk_gauge(risk_data['score'], risk_data['grade']), use_container_width=True)
        
        # Key Findings
        st.subheader("🔍 Key Findings")
        for finding in risk_data['findings']:
            if '✓' in finding:
                st.success(finding)
            elif '⚠' in finding:
                st.warning(finding)
            else:
                st.error(finding)
        
        st.markdown("---")
        
        # Detailed Results
        st.header("📋 Detailed Audit Results")
        
        # Create tabs for different sections
        tab1, tab2, tab3, tab4 = st.tabs(["🌐 Domain Info", "🔐 SSL/TLS", "🔍 Port Scan", "🛡️ Security Headers"])
        
        with tab1:
            st.subheader("Domain Information")
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**WHOIS Data:**")
                st.write(f"**Registrar:** {whois_data.get('registrar', 'N/A')}")
                st.write(f"**Creation Date:** {whois_data.get('creation_date', 'N/A')}")
                st.write(f"**Expiration Date:** {whois_data.get('expiration_date', 'N/A')}")
            
            with col2:
                st.markdown("**Network Information:**")
                st.write(f"**IP Address:** {ip_data.get('ip_address', 'N/A')}")
                st.write(f"**Domain:** {domain}")
                
                if whois_data.get('name_servers'):
                    st.write("**Name Servers:**")
                    for ns in whois_data['name_servers'][:3]:
                        st.write(f"  - {ns}")
        
        with tab2:
            st.subheader("SSL/TLS Certificate Analysis")
            
            if ssl_data.get('has_ssl'):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("SSL Status", "Valid ✅" if ssl_data.get('is_valid') else "Expired ❌")
                
                with col2:
                    st.metric("Days Until Expiry", ssl_data.get('days_until_expiry', 'N/A'))
                
                with col3:
                    st.metric("Issuer", ssl_data.get('issuer', 'N/A')[:20] + "...")
                
                st.write(f"**Expiry Date:** {ssl_data.get('expiry_date', 'N/A')}")
            else:
                st.error("❌ No valid SSL certificate found")
                st.write(f"**Error:** {ssl_data.get('error', 'Unknown error')}")
        
        with tab3:
            st.subheader("Port Scanning Results")
            
            port_results = port_scan.get('results', {})
            
            # Create DataFrame for port results
            port_df_data = []
            for port, info in sorted(port_results.items()):
                port_df_data.append({
                    'Port': port,
                    'Service': info['service'],
                    'Status': info['status'].upper(),
                    'Risk': '⚠️ High' if port in [3306, 5432, 21, 22] and info['status'] == 'open' else '✅ Low'
                })
            
            port_df = pd.DataFrame(port_df_data)
            st.dataframe(port_df, use_container_width=True, hide_index=True)
            
            if port_scan.get('sensitive_open'):
                st.error(f"⚠️ **Alert:** {len(port_scan['sensitive_open'])} sensitive port(s) exposed: {', '.join(port_scan['sensitive_open'])}")
            else:
                st.success("✅ No sensitive ports exposed")
        
        with tab4:
            st.subheader("HTTP Security Headers Analysis")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Security Score", f"{headers_data.get('security_score', 0):.0f}%")
                
                st.markdown("**Found Headers:**")
                found = headers_data.get('found_headers', {})
                if found:
                    for header, value in found.items():
                        st.success(f"✅ {header}")
                else:
                    st.warning("No security headers found")
            
            with col2:
                st.markdown("**Missing Headers:**")
                missing = headers_data.get('missing_headers', [])
                if missing:
                    for header in missing:
                        st.error(f"❌ {header}")
                else:
                    st.success("All critical headers present!")
        
        st.markdown("---")
        
        # Summary Table
        st.header("📊 Audit Summary Table")
        findings_df = create_findings_table(whois_data, ip_data, ssl_data, port_scan, headers_data)
        st.dataframe(findings_df, use_container_width=True, hide_index=True)
        
        # Export Options
        st.markdown("---")
        st.subheader("💾 Export Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            csv = findings_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download CSV Report",
                data=csv,
                file_name=f"desa_secure_audit_{domain}_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            # Create summary text report
            report_text = f"""
DESA-SECURE 2025 - AUDIT REPORT
================================
Domain: {domain}
Audit Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

RISK ASSESSMENT
---------------
Score: {risk_data['score']}/100
Grade: {risk_data['grade']}
Risk Level: {risk_data['risk_level']}

KEY FINDINGS
------------
{chr(10).join(risk_data['findings'])}

DOMAIN INFORMATION
------------------
Registrar: {whois_data.get('registrar', 'N/A')}
Creation Date: {whois_data.get('creation_date', 'N/A')}
Expiry Date: {whois_data.get('expiration_date', 'N/A')}
IP Address: {ip_data.get('ip_address', 'N/A')}

SECURITY STATUS
---------------
SSL Valid: {ssl_data.get('is_valid', False)}
SSL Expiry: {ssl_data.get('expiry_date', 'N/A')}
Open Ports: {', '.join(port_scan.get('open_ports', [])) or 'None'}
Sensitive Ports: {', '.join(port_scan.get('sensitive_open', [])) or 'None'}
Security Headers Score: {headers_data.get('security_score', 0):.0f}%

Generated by Desa-Secure 2025
© 2025 - Open Source Project
            """
            
            st.download_button(
                label="📄 Download TXT Report",
                data=report_text,
                file_name=f"desa_secure_audit_{domain}_{datetime.now().strftime('%Y%m%d')}.txt",
                mime="text/plain",
                use_container_width=True
            )
    
    elif audit_button and not domain_input:
        st.warning("⚠️ Please enter a domain or URL to begin the audit.")
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 2rem 0;'>
        <p><strong>Desa-Secure 2025</strong> | OSINT Vendor Risk Dashboard</p>
        <p>Built for Academic Research - Audit Teknologi & Sistem Informasi</p>
        <p>Focus: Indonesian Village Digital Ecosystem Security</p>
        <p style='font-size: 0.8rem; margin-top: 1rem;'>
            ⚠️ <strong>Disclaimer:</strong> This tool is for educational and authorized auditing purposes only.
            Always ensure you have proper authorization before auditing any system.
        </p>
        <p style='font-size: 0.8rem;'>© 2025 - Open Source License</p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
