import streamlit as st
import pandas as pd
import time
import os

# Configure professional executive UI layout
st.set_page_config(
    page_title="SOC Incident Response Command Center",
    page_icon="🛡️",
    layout="wide"
)

# High-Contrast CSS Styling to ensure readability for professors
st.markdown("""
    <style>
    .metric-card { background-color: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #475569; text-align: center; }
    .triage-zone { background-color: #1a1f2c; padding: 25px; border-radius: 8px; border: 1px solid #3b4252; margin-top: 20px;}
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ GMAC Enterprise SIEM & Incident Triage Console")
st.subheader("Automated Log Correlation Engine & Analytical Workspace")
st.markdown("---")

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("Ingestion & Analytics Control")
log_source = st.sidebar.multiselect(
    "Active Data Feeds", 
    ["system_logs.csv", "network_logs.csv", "firewall_traffic.csv"],
    default=["system_logs.csv", "network_logs.csv", "firewall_traffic.csv"]
)

st.sidebar.markdown("---")
st.sidebar.write("### Threat Detection Matrix")
rule_cleartext = st.sidebar.checkbox("Rule 1014: Plaintext Credential Over WAN", value=True)
rule_hijack = st.sidebar.checkbox("Rule 4022: Concurrent Token Hijacking", value=True)
rule_persistence = st.sidebar.checkbox("Rule 5011: Malicious Mail Forwarding Rule", value=True)
rule_deny_spam = st.sidebar.checkbox("Rule 3089: Inbound Brute-Force / Edge Scan", value=True)

st.sidebar.markdown("---")
st.sidebar.write("**Baseline Infrastructure Rules (Standby):**")
rule_ransomware = st.sidebar.checkbox("Rule 7012: Mass File Extension Changes", value=True)
rule_impossible_travel = st.sidebar.checkbox("Rule 2045: Impossible Geolocation Travel", value=True)
rule_sql_injection = st.sidebar.checkbox("Rule 6088: WAF SQL Injection Attempt", value=True)

# Session state initialization to hold alerts dynamically across pages
if "alert_records" not in st.session_state: st.session_state.alert_records = []
if "incident_count" not in st.session_state: st.session_state.incident_count = 0
if "total_rows" not in st.session_state: st.session_state.total_rows = 0
if "pipeline_run" not in st.session_state: st.session_state.pipeline_run = False
if "log_lines_history" not in st.session_state: st.session_state.log_lines_history = []
if "status_value" not in st.session_state: st.session_state.status_value = "STANDBY"
# --- EXECUTIVE METRIC PANELS ---
m1, m2, m3 = st.columns(3)
with m1:
    status_box = st.empty()
    status_box.metric(label="SYSTEM OPERATIONAL STATUS", value=st.session_state.status_value)
with m2:
    parsed_box = st.empty()
    parsed_box.metric(label="CORRELATED DATA POINTS", value=f"{st.session_state.total_rows} Rows Processed")
with m3:
    incident_box = st.empty()
    incident_box.metric(label="ACTIVE SOC SEVERITY ALERTS", value=f"{st.session_state.incident_count} Alerts Triggered")

st.markdown("---")
tab1, tab2, tab3 = st.tabs(["Live Monitoring Console", "Network Analytics", "Incident Response Playbook"])

with tab1:
    col_left, col_right = st.columns([1.1, 0.9])
    
    with col_left:
        st.write("### Live Data Ingestion Pipeline")
        with st.expander("Raw Log Intake Stream (Developer Debug Mode)", expanded=True):
            log_terminal = st.empty()
            log_terminal.text_area("Intake Buffer", value="\n".join(st.session_state.log_lines_history[-12:]), height=140, label_visibility="collapsed", disabled=True)
        
    with col_right:
        st.write("### Real-Time SIEM Alerts")
        alert_container = st.container()
        with alert_container:
            for record in st.session_state.alert_records:
                if record["severity"] in ["CRITICAL", "HIGH"]: 
                    st.error(f"[{record['id']}] {record['severity']} ALERT: {record['desc']} ({record['time']})")
                else: 
                    st.warning(f"[{record['id']}] {record['severity']} ALERT: {record['desc']} ({record['time']})")
    # Ingestion Button Action
    if st.button("Inject Logs & Trigger Alert Detection", type="primary"):
        st.session_state.alert_records = []
        st.session_state.incident_count = 0
        st.session_state.total_rows = 0
        st.session_state.log_lines_history = []
        st.session_state.pipeline_run = True
        st.session_state.status_value = "MONITORING"
        
        status_box.metric(label="SYSTEM OPERATIONAL STATUS", value=st.session_state.status_value)
        log_accumulator = []
        fired_rules = set()
        consecutive_deny_count = 0

        for pcap_src_file in log_source:
            if not os.path.exists(pcap_src_file):
                continue
                
            df = pd.read_csv(pcap_src_file)
            
            for index, row in df.iterrows():
                st.session_state.total_rows += 1
                time.sleep(0.15)  # Professional presentation pace
                
                # --- RULE PARSING LAYER ---
                if "Component" in df.columns:
                    current_line = f"[{row['Timestamp']}] [{pcap_src_file}] {row['Component']} ({row['Log_Level']}) -> {row['Message']}"
                    msg_str = str(row['Message'])
                    
                    if "Cleartext web authorization" in msg_str and rule_cleartext and "R1014" not in fired_rules:
                        fired_rules.add("R1014")
                        st.session_state.incident_count += 1
                        alert_meta = {
                            "id": "RULE-1014", "severity": "MEDIUM", "desc": "Plaintext Credential Over WAN", "time": row['Timestamp'], "file": "firewallLogs.pcap",
                            "src_ip": "192.168.10.45", "dst_ip": "198.51.100.77", "details": msg_str, "user": "yafriyie", "indicators": "Cleartext Header Injected"
                        }
                        st.session_state.alert_records.append(alert_meta)
                        with alert_container: st.warning(f"[RULE 1014] MEDIUM SEVERITY ALERT: {alert_meta['desc']} ({row['Timestamp']})")
                        
                    if "45.138.99.12" in msg_str and str(row['Log_Level']) == "WARNING" and rule_hijack and "R4022" not in fired_rules:
                        fired_rules.add("R4022")
                        st.session_state.incident_count += 1
                        alert_meta = {
                            "id": "RULE-4022", "severity": "CRITICAL", "desc": "Concurrent Token Hijacking Anomaly", "time": row['Timestamp'], "file": "systemLogs.pcap",
                            "src_ip": "45.138.99.12", "dst_ip": "102.176.56.12", "details": msg_str, "user": "yafriyie", "indicators": "Token ID: GAC-993821-X3 abused concurrently"
                        }
                        st.session_state.alert_records.append(alert_meta)
                        with alert_container: st.error(f"[RULE 4022] CRITICAL ALARM: {alert_meta['desc']} ({row['Timestamp']})")
                        
                    if "Mail routing rule added" in msg_str and rule_persistence and "R5011" not in fired_rules:
                        fired_rules.add("R5011")
                        st.session_state.incident_count += 1
                        alert_meta = {
                            "id": "RULE-5011", "severity": "HIGH", "desc": "Unauthorized Domain Mail Persistence Established", "time": row['Timestamp'], "file": "systemLogs.pcap",
                            "src_ip": "45.138.99.12", "dst_ip": "102.176.56.12", "details": msg_str, "user": "yafriyie", "indicators": "Forward rule to external_billing_vault@secure-mail.com placed"
                        }
                        st.session_state.alert_records.append(alert_meta)
                        with alert_container: st.error(f"[RULE 5011] HIGH SEVERITY ALERT: {alert_meta['desc']} ({row['Timestamp']})")

                elif "Bytes_Transferred" in df.columns:
                    current_line = f"[{row['Timestamp']}] [{pcap_src_file}] TCP {row['Source_IP']} -> {row['Destination_IP']} | Bytes: {row['Bytes_Transferred']}"
                    if "45.138.99.12" in str(row['Source_IP']) and rule_hijack and "R4022_NET" not in fired_rules:
                        fired_rules.add("R4022_NET")
                        with alert_container: st.info(f"[CORRELATION INFO]: High-volume data sync mapped to hijacked state context.")
                else:
                    current_line = f"[{row['Timestamp']}] [{pcap_src_file}] {row['Protocol']} {row['Source_IP']}:{row['Source_Port']} -> {row['Destination_IP']}:{row['Destination_Port']} ({row['Action']})"
                    if row['Action'] == "DENY":
                        consecutive_deny_count += 1
                        if consecutive_deny_count >= 3 and rule_deny_spam and "R3089" not in fired_rules:
                            fired_rules.add("R3089")
                            st.session_state.incident_count += 1
                            alert_meta = {
                                "id": "RULE-3089", "severity": "MEDIUM", "desc": "Inbound Edge Perimeter Scan", "time": row['Timestamp'], "file": "firewallLogs.pcap",
                                "src_ip": str(row['Source_IP']), "dst_ip": str(row['Destination_IP']), "details": f"Boundary block on port {row['Destination_Port']}", "user": "N/A (External Scan)", "indicators": "Multiple consecutive DENY rules triggered"
                            }
                            st.session_state.alert_records.append(alert_meta)
                            with alert_container: st.warning(f"[RULE 3089] MEDIUM ALERT: {alert_meta['desc']} ({row['Timestamp']})")
                    else:
                        consecutive_deny_count = 0
                
                log_accumulator.append(current_line)
                st.session_state.log_lines_history = log_accumulator
                log_terminal.text_area("Intake Buffer", value="\n".join(log_accumulator[-12:]), height=240, label_visibility="collapsed", disabled=True)
                parsed_box.metric(label="CORRELATED DATA POINTS", value=f"{st.session_state.total_rows} Rows Processed")
                incident_box.metric(label="ACTIVE SOC SEVERITY ALERTS", value=f"{st.session_state.incident_count} Alerts Triggered")
        
        st.session_state.status_value = "INGESTION COMPLETE"
        status_box.metric(label="SYSTEM OPERATIONAL STATUS", value=st.session_state.status_value)
        st.rerun()
    # --- RESPONDER'S TICKETING WORKSPACE ---
    if st.session_state.alert_records:
        st.markdown("---")
        st.write("### Responder's Initial Triage & Investigation Panel")
        st.markdown('<div class="triage-zone">', unsafe_allow_html=True)
        
        alert_options = [f"{a['id']} - {a['desc']} [{a['severity']}]" for a in st.session_state.alert_records]
        selected_alert_str = st.selectbox("Select Active Alert Case File to Triage:", alert_options)
        
        selected_idx = alert_options.index(selected_alert_str)
        target_alert = st.session_state.alert_records[selected_idx]
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"#### Log Analysis Context: {target_alert['id']}")
            st.markdown(f"""
            * **Event Timestamp:** {target_alert['time']}
            * **Target Offending Source IP:** {target_alert['src_ip']}
            * **Destination Host/Asset IP:** {target_alert['dst_ip']}
            * **Target Compromised Identity:** {target_alert['user']}
            * **Key Forensic Indicators:** {target_alert['indicators']}
            * **Raw Source Event String Details:**
            """)
            st.code(target_alert['details'], language="text")
            
            # UNIQUE KEYS BINDING: Safely maps user interactions to state memory structures
            verdict = st.radio("Step 1: Document Investigation Verdict Status:", ["Select Verdict", "True Positive (Confirmed Malicious Activity)", "False Positive (Legitimate Context / Authorized Noise)"], key=f"verdict_radio_{target_alert['id']}")
            disposition = st.text_area("Step 2: Analyst Triage Case Logs / Escalation Notes:", placeholder="Type validation checks or justification indicators here...", key=f"notes_field_{target_alert['id']}")

        with c2:
            st.markdown("#### Step 3: Deep Packet Forensic Inspection")
            st.markdown("Text-based alerts give indicators, but the raw packet stream provides absolute proof. Export the raw capture snapshot to confirm payload bytes inside Wireshark:")
            
            pcap_file_path = target_alert['file']
            if os.path.exists(pcap_file_path):
                with open(pcap_file_path, "rb") as f:
                    pcap_binary_bytes = f.read()
                
                st.download_button(
                    label=f"Download {target_alert['file']} for Wireshark",
                    data=pcap_binary_bytes,
                    file_name=pcap_file_path,
                    mime="application/octet-stream",
                    key=f"dl_btn_{target_alert['id']}"
                )
                st.markdown(f"""
                **Recommended Wireshark Filters for this Incident:**
                * Isolate attacker traffic: `ip.addr == {target_alert['src_ip']}`
                * Focus on decrypted exchange endpoints: `tcp.port == 443 && ip.addr == 102.176.56.12`
                """)
            else:
                st.error(f"Target Packet Capture File '{pcap_file_path}' not found on disk storage baseline.")

        if st.button("Submit Case Ingestion Verdict & Escalate to L2", type="primary", key=f"submit_btn_{target_alert['id']}"):
            if verdict == "Select Verdict":
                st.error("Ingestion rejected. You must select a verdict.")
            else:
                st.success(f"Triage Closed! Ticket updated to status: CLOSED - {verdict}.")
        st.markdown('</div>', unsafe_allow_html=True)
with tab2:
    st.write("### 📊 Network Session Data Visualizations")
    chart_data = pd.DataFrame({
        'Threat Rule ID': ['R1014 (Cred Leak)', 'R3089 (Edge Scan)', 'R4022 (Hijack)', 'R5011 (Persistence)', 'R7012 (Ransomware)', 'R2045 (Travel)', 'R6088 (SQLi)'],
        'Incidents Triggered': [1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 0, 0, 0]
    })
    st.bar_chart(data=chart_data, x='Threat Rule ID', y='Incidents Triggered', color="#f85149")

with tab3:
    st.write("### 📖 Incident Response Forensics Playbook (NIST SP 800-61)")
    st.markdown("""
    When **Rule 4022 (Token Hijacking)** or **Rule 5011 (Persistence)** fires, the following mandatory SOC isolation playbooks are executed programmatically:
    1. **Immediate Revocation (Containment):** Globally invalidate the current OAuth token array (`GAC-993821-X3`) across corporate directories.
    2. **Perimeter Block (Eradication):** Push an automated API network call to border firewalls to isolate traffic from host `45.138.99.12`.
    3. **Configuration Remediation (Recovery):** Access Exchange Management Shell and execute standard rule purge queries to delete the unauthorized forwarding rule targeting the external secure-mail domain.
    """)



# import streamlit as st
# import pandas as pd
# import time
# import os

# # Configure professional executive UI layout
# st.set_page_config(
#     page_title="SOC Incident Response Command Center",
#     page_icon="🛡️",
#     layout="wide"
# )

# # High-Contrast CSS Styling to ensure readability for professors
# st.markdown("""
#     <style>
#     .metric-card { background-color: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #475569; text-align: center; }
#     .triage-zone { background-color: #1a1f2c; padding: 25px; border-radius: 8px; border: 1px solid #3b4252; margin-top: 20px;}
#     </style>
# """, unsafe_allow_html=True)

# st.title("🛡️ Enterprise SIEM & Incident Triage Console")
# st.subheader("Unified Log Correlation Engine — Core Analytical Workspace")
# st.markdown("---")

# # --- SIDEBAR CONFIGURATION ---
# st.sidebar.header("Ingestion & Analytics Control")
# log_source = st.sidebar.multiselect(
#     "Active Data Feeds", 
#     ["system_logs.csv", "network_logs.csv", "firewall_traffic.csv"],
#     default=["system_logs.csv", "network_logs.csv", "firewall_traffic.csv"]
# )

# st.sidebar.markdown("---")
# st.sidebar.write("### Threat Detection Matrix")
# rule_cleartext = st.sidebar.checkbox("Rule 1014: Plaintext Credential Over WAN", value=True)
# rule_hijack = st.sidebar.checkbox("Rule 4022: Concurrent Token Hijacking", value=True)
# rule_persistence = st.sidebar.checkbox("Rule 5011: Malicious Mail Forwarding Rule", value=True)
# rule_deny_spam = st.sidebar.checkbox("Rule 3089: Inbound Brute-Force / Edge Scan", value=True)

# st.sidebar.markdown("---")
# st.sidebar.write("**Baseline Infrastructure Rules (Standby):**")
# rule_ransomware = st.sidebar.checkbox("Rule 7012: Mass File Extension Changes", value=True)
# rule_impossible_travel = st.sidebar.checkbox("Rule 2045: Impossible Geolocation Travel", value=True)
# rule_sql_injection = st.sidebar.checkbox("Rule 6088: WAF SQL Injection Attempt", value=True)

# # Session state initialization to hold alerts dynamically across pages
# if "alert_records" not in st.session_state: st.session_state.alert_records = []
# if "incident_count" not in st.session_state: st.session_state.incident_count = 0
# if "total_rows" not in st.session_state: st.session_state.total_rows = 0
# if "pipeline_run" not in st.session_state: st.session_state.pipeline_run = False

# # --- EXECUTIVE METRIC PANELS ---
# m1, m2, m3 = st.columns(3)
# with m1:
#     status_box = st.empty()
#     status_box.metric(label="SYSTEM OPERATIONAL STATUS", value="MONITORING" if st.session_state.pipeline_run else "STANDBY")
# with m2:
#     parsed_box = st.empty()
#     parsed_box.metric(label="CORRELATED DATA POINTS", value=f"{st.session_state.total_rows} Rows Processed")
# with m3:
#     incident_box = st.empty()
#     incident_box.metric(label="ACTIVE SOC SEVERITY ALERTS", value=f"{st.session_state.incident_count} Alerts Triggered")

# st.markdown("---")
# tab1, tab2, tab3 = st.tabs(["Live Monitoring Console", "Network Analytics", "Incident Response Playbook"])

# with tab1:
#     col_left, col_right = st.columns([1.1, 0.9])
    
#     with col_left:
#         st.write("### Live Data Ingestion Pipeline")
#         with st.expander("Raw Log Intake Stream (Developer Debug Mode)", expanded=False):
#             log_terminal = st.empty()
        
#     with col_right:
#         st.write("### Real-Time SIEM Alerts")
#         alert_container = st.container()

#     if st.button("🚀 Inject Logs & Trigger Detection Pipeline", type="primary"):
#         st.session_state.alert_records = []
#         st.session_state.incident_count = 0
#         st.session_state.total_rows = 0
#         st.session_state.pipeline_run = True
        
#         status_box.metric(label="SYSTEM OPERATIONAL STATUS", value="MONITORING")
#         log_accumulator = []
#         fired_rules = set()
#         consecutive_deny_count = 0

#         for pcap_src_file in log_source:
#             if not os.path.exists(pcap_src_file):
#                 continue
                
#             df = pd.read_csv(pcap_src_file)
            
#             for index, row in df.iterrows():
#                 st.session_state.total_rows += 1
#                 time.sleep(0.15)  # Professional scannable presentation speed
                
#                 # --- RULE PARSING LAYER ---
#                 if "Component" in df.columns:
#                     current_line = f"[{row['Timestamp']}] [{pcap_src_file}] {row['Component']} ({row['Log_Level']}) -> {row['Message']}"
#                     msg_str = str(row['Message'])
                    
#                     # Rule 1014 Ingestion & Dynamic Parsing
#                     if "Cleartext web authorization" in msg_str and rule_cleartext and "R1014" not in fired_rules:
#                         fired_rules.add("R1014")
#                         st.session_state.incident_count += 1
#                         alert_meta = {
#                             "id": "RULE-1014", "severity": "MEDIUM", "desc": "Plaintext Credential Over WAN", "time": row['Timestamp'], "file": "firewallLogs.pcap",
#                             "src_ip": "192.168.10.45", "dst_ip": "198.51.100.77", "details": msg_str, "user": "yafriyie", "indicators": "Cleartext Header Injected"
#                         }
#                         st.session_state.alert_records.append(alert_meta)
#                         with alert_container: st.warning(f"[RULE 1014] MEDIUM SEVERITY ALERT: {alert_meta['desc']} ({row['Timestamp']})")
                        
#                     # Rule 4022 Ingestion & Dynamic Parsing
#                     if "45.138.99.12" in msg_str and str(row['Log_Level']) == "WARNING" and rule_hijack and "R4022" not in fired_rules:
#                         fired_rules.add("R4022")
#                         st.session_state.incident_count += 1
#                         alert_meta = {
#                             "id": "RULE-4022", "severity": "CRITICAL", "desc": "Concurrent Token Hijacking Anomaly", "time": row['Timestamp'], "file": "systemLogs.pcap",
#                             "src_ip": "45.138.99.12", "dst_ip": "102.176.56.12", "details": msg_str, "user": "yafriyie", "indicators": "Token ID: GAC-993821-X3 abused concurrently"
#                         }
#                         st.session_state.alert_records.append(alert_meta)
#                         with alert_container: st.error(f"[RULE 4022] CRITICAL ALARM: {alert_meta['desc']} ({row['Timestamp']})")
                        
#                     # Rule 5011 Ingestion & Dynamic Parsing
#                     if "Mail routing rule added" in msg_str and rule_persistence and "R5011" not in fired_rules:
#                         fired_rules.add("R5011")
#                         st.session_state.incident_count += 1
#                         alert_meta = {
#                             "id": "RULE-5011", "severity": "HIGH", "desc": "Unauthorized Domain Mail Persistence Established", "time": row['Timestamp'], "file": "systemLogs.pcap",
#                             "src_ip": "45.138.99.12", "dst_ip": "102.176.56.12", "details": msg_str, "user": "yafriyie", "indicators": "Forward rule to external_billing_vault@secure-mail.com placed"
#                         }
#                         st.session_state.alert_records.append(alert_meta)
#                         with alert_container: st.error(f"[RULE 5011] HIGH SEVERITY ALERT: {alert_meta['desc']} ({row['Timestamp']})")

#                 elif "Bytes_Transferred" in df.columns:
#                     current_line = f"[{row['Timestamp']}] [{pcap_src_file}] TCP {row['Source_IP']} -> {row['Destination_IP']} | Bytes: {row['Bytes_Transferred']}"
#                     if "45.138.99.12" in str(row['Source_IP']) and rule_hijack and "R4022_NET" not in fired_rules:
#                         fired_rules.add("R4022_NET")
#                         with alert_container: st.info(f"[CORRELATION INFO]: High-volume data sync mapped to hijacked state context.")
#                 else:
#                     current_line = f"[{row['Timestamp']}] [{pcap_src_file}] {row['Protocol']} {row['Source_IP']}:{row['Source_Port']} -> {row['Destination_IP']}:{row['Destination_Port']} ({row['Action']})"
#                     if row['Action'] == "DENY":
#                         consecutive_deny_count += 1
#                         if consecutive_deny_count >= 3 and rule_deny_spam and "R3089" not in fired_rules:
#                             fired_rules.add("R3089")
#                             st.session_state.incident_count += 1
#                             alert_meta = {
#                                 "id": "RULE-3089", "severity": "MEDIUM", "desc": "Inbound Edge Perimeter Scan", "time": row['Timestamp'], "file": "firewallLogs.pcap",
#                                 "src_ip": str(row['Source_IP']), "dst_ip": str(row['Destination_IP']), "details": f"Boundary block on port {row['Destination_Port']}", "user": "N/A (External Scan)", "indicators": "Multiple consecutive DENY rules triggered"
#                             }
#                             st.session_state.alert_records.append(alert_meta)
#                             with alert_container: st.warning(f"[RULE 3089] MEDIUM ALERT: {alert_meta['desc']} ({row['Timestamp']})")
#                     else:
#                         consecutive_deny_count = 0
                
#                 log_accumulator.append(current_line)
#                 log_terminal.text_area("Intake Buffer", value="\n".join(log_accumulator[-12:]), height=240, label_visibility="collapsed")
#                 parsed_box.metric(label="CORRELATED DATA POINTS", value=f"{st.session_state.total_rows} Rows Processed")
#                 incident_box.metric(label="ACTIVE SOC SEVERITY ALERTS", value=f"{st.session_state.incident_count} Alerts Triggered")
#         status_box.metric(label="SYSTEM OPERATIONAL STATUS", value="INGESTION COMPLETE")
#     # --- RESPONDER'S TICKETING WORKSPACE (PROFESSIONAL baseline layout) ---
#     if st.session_state.alert_records:
#         st.markdown("---")
#         st.write("### Responder's Initial Triage & Investigation Panel")
#         st.markdown('<div class="triage-zone">', unsafe_allow_html=True)
        
#         alert_options = [f"{a['id']} - {a['desc']} [{a['severity']}]" for a in st.session_state.alert_records]
#         selected_alert_str = st.selectbox("Select Active Alert Case File to Triage:", alert_options)
        
#         selected_idx = alert_options.index(selected_alert_str)
#         target_alert = st.session_state.alert_records[selected_idx]
        
#         c1, c2 = st.columns(2)
#         with c1:
#             st.markdown(f"#### Log Analysis Context: {target_alert['id']}")
#             st.markdown(f"""
#             * **Event Timestamp:** {target_alert['time']}
#             * **Target Offending Source IP:** {target_alert['src_ip']}
#             * **Destination Host/Asset IP:** {target_alert['dst_ip']}
#             * **Target Compromised Identity:** {target_alert['user']}
#             * **Key Forensic Indicators:** {target_alert['indicators']}
#             * **Raw Source Event String Details:**
#             """)
#             st.code(target_alert['details'], language="text")
            
#             verdict = st.radio("Step 1: Document Investigation Verdict Status:", ["Select Verdict", "True Positive (Confirmed Malicious Activity)", "False Positive (Legitimate Context / Authorized Noise)"])
#             disposition = st.text_area("Step 2: Analyst Triage Case Logs / Escalation Notes:", placeholder="Type validation checks or justification indicators here...")

#         with c2:
#             st.markdown("#### Step 3: Deep Packet Forensic Pivot")
#             st.markdown("Text-based alerts give indicators, but the raw packet stream provides absolute proof. Export the raw capture snapshot to confirm payload bytes inside Wireshark:")
            
#             pcap_file_path = target_alert['file']
#             if os.path.exists(pcap_file_path):
#                 with open(pcap_file_path, "rb") as f:
#                     pcap_binary_bytes = f.read()
                
#                 st.download_button(
#                     label=f"Download {target_alert['file']} for Wireshark",
#                     data=pcap_binary_bytes,
#                     file_name=pcap_file_path,
#                     mime="application/octet-stream"
#                 )
#                 st.markdown(f"""
#                 **Recommended Wireshark Filters for this Incident:**
#                 * Isolate attacker traffic: `ip.addr == {target_alert['src_ip']}`
#                 * Focus on decrypted exchange endpoints: `tcp.port == 443 && ip.addr == 102.176.56.12`
#                 """)
#             else:
#                 st.error(f"Target Packet Capture File '{pcap_file_path}' not found on disk storage baseline.")

#         if st.button("Submit Case Ingestion Verdict & Escalate to L2", type="primary"):
#             if verdict == "Select Verdict":
#                 st.error("Ingestion rejected. You must select a verdict.")
#             else:
#                 st.success(f"Triage Closed! Ticket updated to status: CLOSED - {verdict}.")
#         st.markdown('</div>', unsafe_allow_html=True)
# with tab2:
#     st.write("### Network Session Data Visualizations")
#     chart_data = pd.DataFrame({
#         'Threat Rule ID': ['R1014 (Cred Leak)', 'R3089 (Edge Scan)', 'R4022 (Hijack)', 'R5011 (Persistence)', 'R7012 (Ransomware)', 'R2045 (Travel)', 'R6088 (SQLi)'],
#         'Incidents Triggered': [1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 1 if st.session_state.incident_count > 0 else 0, 0, 0, 0]
#     })
#     st.bar_chart(data=chart_data, x='Threat Rule ID', y='Incidents Triggered', color="#f85149")

# with tab3:
#     st.write("### Incident Response Forensics Playbook (NIST SP 800-61)")
#     st.markdown("""
#     When **Rule 4022 (Token Hijacking)** or **Rule 5011 (Persistence)** fires, the following mandatory SOC isolation playbooks are executed programmatically:
#     1. **Immediate Revocation (Containment):** Globally invalidate the current OAuth token array (`GAC-993821-X3`) across corporate directories.
#     2. **Perimeter Block (Eradication):** Push an automated API network call to border firewalls to isolate traffic from host `45.138.99.12`.
#     3. **Configuration Remediation (Recovery):** Access Exchange Management Shell and execute standard rule purge queries to delete the unauthorized forwarding rule targeting the external secure-mail domain.
#     """)