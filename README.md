# GCMA Enterprise SIEM & Incident Triage Console
An end-to-end incident detection and analysis pipeline built in accordance with the NIST SP 800-61 Incident Handling Guide. This platform correlates multi-source log feeds in real time to isolate an active session hijacking and unauthorized persistence attempt targeting high-value infrastructure identities.

👉 **[Live SIEM Interactive Console](https://gcma-siem.streamlit.app)**

<img width="1564" height="867" alt="Screenshot of the SIEM Dashboard" src="https://github.com/user-attachments/assets/7ff6d69e-d43d-40fc-8fea-1baac0e6e385" />

## Project Architecture
The platform ingests three distinct, normalized logging feeds to reconstruct an attack timeline:
* **workstation_logs.csv:** Application-level heartbeats and event sequences tracking active authentication cookies.
* **network_traffic.csv:** Transaction volume and payload session data fields tracking endpoint byte metrics.
* **firewall_traffic.csv:** Perimeter edge rule actions monitoring boundary protocol packets.

<img width="1000" alt=".csv logs and .pcap file logs" src="https://github.com/user-attachments/assets/138f4d8c-f82b-45c4-b06a-9ed866c0c848" />


## Core Features & NIST Phase 1 Mapping
* **Real-Time Correlation Engine:** Evaluates streaming log sequences against a multi-layered threat detection matrix without freezing the UI.
* **Dynamic Alert Enrichment:** Extracts critical attacker variables (offending source IP, victim identity, timestamp parameters) into a localized triage ticket workspace immediately upon signature breaches.
* **Forensic PCAP Exporter:** Uses Python's Scapy library under the hood to compile corresponding low-level network captures, allowing an investigator to download targeted `.pcap` slices directly for deep packet validation inside Wireshark.

## Threat Detection Matrix Rules
* **Rule 1014 (Medium Severity):** Identifies plaintext credential or web authorization header transmission over public WAN interfaces.
* **Rule 4022 (Critical Severity):** Flags concurrent token usage anomalies from foreign remote IP interfaces.
* **Rule 5011 (High Severity):** Isolates application modifications mapping unauthorized domain persistence mechanisms (e.g., hidden exchange mail routing rules).
* **Rule 3089 (Medium Severity):** Detects inbound perimeter port scans by tracking rapid, consecutive firewall blocks.

<img width="667" height="299" alt="Screenshot of alert of SIEM Dashboard" src="https://github.com/user-attachments/assets/5edbedd0-dc15-478b-97da-3b65d58c100c" />

## Repository Directory Structure
The repository workspace contains all the required historical logs, binary network captures, and deployment code engines:

```txt
├── app.py                      # Main production multi-tab Streamlit dashboard
├── SIEM.py                     # CLI baseline correlation script
├── system_logs.csv             # Raw application event logs (Mrs. Afriyie's session data)
├── network_logs.csv            # Raw application network traffic log rows
├── firewall_traffic.csv        # Raw border firewall interface block/allow records
├── systemLogs.pcap             # Binary packet trace matching system log events
├── networkLogs.pcap            # Binary packet trace matching transaction metrics
├── firewallLogs.pcap           # Binary packet trace matching boundary traffic
└── reconstructed_combined.pcap # Final master merged pcap tracking the global incident timeline
```

## Local Deployment Instructions

### Prerequisites
Ensure your local environment runs Python 3.9+ (or an active Anaconda virtual profile).

### 1. Clone the Workspace Repository
```bash
git clone https://github.com
cd your-repo-name
```

### 2. Install Project Dependencies
Install the required analytical and data libraries:
```bash
pip install streamlit pandas scapy
```

### 3. Launch the SIEM Platform
Execute the web server interface locally:
```bash
streamlit run app.py
```
The terminal console will initialize a lightweight server and launch the workspace dashboard inside your default browser at `http://localhost:8501`.

## Wireshark Forensic Validation Guide
When validating alerts from the triage panel, download the corresponding `.pcap` capture file from the SIEM interface and apply these standardized display filters within Wireshark for deep packet inspection:

<img width="1435" height="721" alt="Screenshot 2026-09-26 at 7 01 12 PM" src="https://github.com/user-attachments/assets/7419a69b-5a1b-4dcc-b1db-edf10bc262a7" />

### 1. Isolate Threat Actor Footprint
To track all network conversations, handshakes, and transaction blocks tied directly to the rogue external interface:
```text
ip.addr == 45.138.99.12
```

<img width="1430" height="711" alt="Screenshot of ip address filter" src="https://github.com/user-attachments/assets/5e0e8d75-c627-42b8-81d1-895015fc4550" />

### 2. Inspect Cleartext Credential Exfiltration
To view raw unencrypted payload strings and pinpoint the HTTP POST request headers that exposed the authorization session token:
```text
http.request.method == "POST" || tcp.port == 80
```

<img width="1430" height="711" alt="Screenshot of POST request filtering on tcp port 80 " src="https://github.com/user-attachments/assets/7c5fda47-b258-4460-8f93-b8db490a7714" />

### 3. Analyze Malicious Exchange Exchange Sync Data
To focus directly on the decrypted port 443 web server endpoint and trace what specific files were systematically extracted by the attacker:
```text
tcp.port == 443 && ip.addr == 102.176.56.12
```

<img width="1430" height="711" alt="Screenshot of port filtering for ip address" src="https://github.com/user-attachments/assets/fd6530a3-f05f-4ee0-b8b0-8d015b88d680" />

*Forensic Tip: Right-click a matching packet and select **Follow -> TCP Stream** to reconstruct the exact data conversation chronologically.*

<img width="1430" height="711" alt="Screenshot of analyzing one packet" src="https://github.com/user-attachments/assets/79aa4dff-29b2-4b1e-ba94-79e6e5ffaf14" />

<img width="1430" height="711" alt="Screenshot of seeing the conversation in the packet" src="https://github.com/user-attachments/assets/2a00cf77-07b0-4d71-9745-8ddb955caf2e" />

## Incident Playbook Summary (NIST Phase 2-4)
1. **Containment:** Revoke the compromised OAuth identity session token across corporate directories and block the offending source IP (`45.138.99.12`) at the perimeter switch interface.
2. **Eradication:** Purge the unauthorized mail forwarding rule targeting the external billing vault server using administrative terminal shells.
3. **Recovery & Lessons Learned:** Enforce phishing-resistant Multi-Factor Authentication (MFA) across high-profile financial identity vectors and tighten unencrypted web protocol block constraints.



## Live Deployment
For quick review without a local development environment, access the production cloud deployment directly:
👉 **[Live SIEM Interactive Console](https://gcma-siem.streamlit.app)**

https://gcma-siem.streamlit.app
