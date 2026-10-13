# 🛡️ AI SOC Assistant

🚀 **AI-powered SOC Analyst Tool for Real-Time Threat Detection (Offline First)**

A fully offline Security Operations Center (SOC) simulation tool that detects, analyzes, and explains cyber threats from raw logs using rule-based intelligence, MITRE ATT&CK mapping, and local AI (Ollama).
Built to simulate real-world SOC analyst workflows including threat detection, correlation, and incident response.
---

## 🔥 Why this project stands out

Unlike basic scripts, this project simulates a **real SOC workflow**:

Log → Parse → Detection → Correlation → MITRE Mapping → Severity → AI Analysis → Report

✔ Built like a mini SIEM  
✔ Works completely offline  
✔ Includes CLI + GUI  
✔ Designed for real SOC analyst scenarios  
✔ End-to-end detection pipeline  

## 🧪 Real Scenario Example

- Detected SSH brute-force attack from multiple IPs
- Identified aggressive attacker vs probing sources
- Correlated attack pattern
- Flagged potential compromise (successful login after brute force)
- Suggested mitigation steps

## 💡 What makes this unique

- Fully offline SOC tool (no cloud dependency)
- Combines rule-based + AI analysis
- Structured like real SIEM pipeline
  
---

## 🧠 Key Features

### 🔍 Threat Detection
- SSH Brute Force  
- SQL Injection  
- Cross-Site Scripting (XSS)  
- Path Traversal  
- Sensitive File Enumeration  
- Automated Scanner Detection  

---

### 🔗 Attack Correlation Engine
- Groups alerts by IP  
- Identifies aggressive vs probing behavior  
- Detects multi-stage attacks  
- Generates attack chain summary  

---

### 🛡️ MITRE ATT&CK Mapping
- T1110 – Brute Force  
- T1190 – Exploit Public-Facing Application  
- T1083 – File Discovery  
- T1595 – Active Scanning  

---

### 📊 Severity Scoring
- Score range: **0–100**  
- Levels: LOW → MEDIUM → HIGH → CRITICAL  
- Based on attack frequency + confidence  

---

### 🌐 IP Enrichment
- AbuseIPDB integration  
- Local classification:
  - INTERNAL NETWORK  
  - SIMULATED ATTACK  
  - EXTERNAL (UNVERIFIED)  

---

### 🤖 AI Analysis (Offline)
- Uses Ollama (Mistral / Llama3)  
- Generates:
  - Threat summary  
  - Impact analysis  
  - Recommended actions  

---

### 💻 Interfaces

#### CLI
```bash
python -m app.cli analyse data/samples/ssh_bruteforce.log --no-ai

#### GUI
```bash
streamlit run app/gui.py

📁 Project Structure
ai-soc-assistant/
│
├── app/                          # Main application code
│   ├── cli.py                    # CLI interface
│   ├── gui.py                    # Streamlit GUI dashboard
│   │
│   ├── core/                     # Core SOC logic
│   │   ├── analyzer.py           # Pipeline orchestrator
│   │   ├── parser.py             # Log parsing (SSH + Web)
│   │   ├── rules.py              # Detection rules engine
│   │   ├── correlator.py         # Attack correlation logic
│   │   ├── scorer.py             # Severity scoring engine
│   │   ├── mitre.py              # MITRE ATT&CK mapping
│   │   ├── prompts.py            # AI prompt templates
│   │   ├── ollama_client.py      # Local LLM integration
│   │
│   ├── integrations/             # External integrations
│   │   ├── abuseipdb.py          # IP reputation & enrichment
│
├── data/                         # Sample logs for testing
│   └── samples/
│       ├── ssh_bruteforce.log
│       ├── sql_injection.log
│
├── outputs/                      # Generated reports
│   └── reports/
│
├── screenshots/                  # 📸 UI screenshots (IMPORTANT for GitHub)
│   ├── dashboard.png
│   ├── summary.png
│   ├── source_ips.png
│   ├── mitre.png
│   ├── alerts.png
│
├── tests/                        # Unit + integration tests
│   ├── test_parser.py
│   ├── test_analyzer.py
│
├── requirements.txt              # Project dependencies
├── .env                          # Environment variables (ignored in Git)
├── .env.example                  # Sample environment config
├── README.md                     # Project documentation
├── run_cli.bat                   # Windows CLI launcher
├── run_gui.bat                   # Windows GUI launcher

🚀 Installation
git clone https://github.com/lonewolf273/ai-soc-assistant.git
cd ai-soc-assistant
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt

⚙️ Setup (Optional)

Create .env file:

ABUSEIPDB_API_KEY=your_api_key_here
OLLAMA_MODEL=mistral

▶️ Usage
CLI
python -m app.cli analyse data/samples/ssh_bruteforce.log

GUI
streamlit run app/gui.py

📊 Example Output
-🚨 Alerts detected
-🔗 Attack chain summary
-⚠️ Impact analysis
-🛠️ Recommended actions
-🛡️ MITRE ATT&CK mapping
-📁 JSON report generated

🧪 Sample Logs
-SSH brute force attack
-SQL injection attack
-Web exploitation logs

## 📸 Screenshots

### 🔥 SOC Dashboard
> Overview of detected threats, severity score, and system status
![Dashboard](screenshots/dashboard.png)

---

### 🔗 Attack Summary & Impact Analysis
> Correlated attack chain with risk explanation and impact assessment
![Summary](screenshots/summary.png)

---

### 🌐 Source IP Intelligence
> Top attacking IPs with event counts and threat classification
![Source IPs](screenshots/source_ips.png)

---

### 🛡️ MITRE ATT&CK Mapping
> Mapping detected threats to real-world attack techniques
![MITRE](screenshots/mitre.png)

---

### 🚨 Rule-Based Alerts
> Detailed alerts showing attack type, confidence, and affected IPs
![Alerts](screenshots/alerts.png)

CLI Output:
>python -m app.cli analyse data\samples\ssh_bruteforce.log

╔══════════════════════════════════════════════════════════╗
║          AI-Powered SOC Assistant v1.0                   ║
║          Offline Threat Detection & Analysis             ║
╚══════════════════════════════════════════════════════════╝

✔ AbuseIPDB enrichment enabled.
✔ Ollama running  |  Models: mistral:latest, qwen3.5:cloud, llama3:latest

▶  Analysing: data\samples\ssh_bruteforce.log

  [1/5] Parsing log file...

  📋  ANALYSIS SUMMARY
────────────────────────────────────────────────────────────────
  File:          ssh_bruteforce.log
  Log type:      AUTO
  Analysed at:   2026-05-01T08:04:42.017949+00:00
  Events parsed: 29
  Alerts raised: 3
  Severity:      CRITICAL  (score: 83/100)

  CRITICAL threat detected. Multiple high-confidence indicators including SSH Brute Force across 29 events. Immediate incident response recommended.

  🔗  ATTACK CHAIN SUMMARY
────────────────────────────────────────────────────────────────
  Multiple IP addresses are attempting SSH brute-force attacks using common credential patterns. One source IP demonstrates high-frequency attack behavior, suggesting automated exploitation attempts. Additional 2 IPs are engaged in lower-volume credential probing attempts. The most active threat source identified is 192.168.1.105. Overall threat level is assessed as HIGH. Confidence level of detections is moderate, but observed behavior and frequency indicate high risk. The attack pattern suggests credential harvesting attempts targeting weak or reused passwords.

  ⚠️  IMPACT ANALYSIS
────────────────────────────────────────────────────────────────
  Repeated failed authentication attempts indicate active brute-force attacks. Successful exploitation could grant attackers unauthorized system access, leading to lateral movement, persistence, and potential data compromise.

  Recommended Action:
  Immediately block identified source IPs at the firewall level. Enforce multi-factor authentication (MFA), disable password-based login where possible, and implement rate limiting or fail2ban protections. Monitor for continued attack attempts.

  🚨  RULE-BASED ALERTS  (3)
────────────────────────────────────────────────────────────────
  [R001] SSH Brute Force  —  Confidence: MEDIUM  —  Source IP: 192.168.1.105
       IP 192.168.1.105 generated 12 SSH failed login attempts targeting usernames: ftp, test, ubuntu, mysql, root and 7 more

  [R001] SSH Brute Force  —  Confidence: MEDIUM  —  Source IP: 192.168.1.106
       IP 192.168.1.106 generated 6 SSH failed login attempts targeting usernames: ubuntu, pi, support, root, git and 1 more

  [R001] SSH Brute Force  —  Confidence: MEDIUM  —  Source IP: 203.0.113.42
       IP 203.0.113.42 generated 5 SSH failed login attempts targeting usernames: root


  🛡️   MITRE ATT&CK MAPPING  (2 techniques)
────────────────────────────────────────────────────────────────
  T1110  Brute Force                               Tactic: Credential Access
       https://attack.mitre.org/techniques/T1110/
  T1110.001  Password Guessing                         Tactic: Credential Access
       https://attack.mitre.org/techniques/T1110/001/

  🌐  TOP SOURCE IPs
────────────────────────────────────────────────────────────────
  192.168.1.105     14 events
  192.168.1.106      6 events
  203.0.113.42      5 events
  198.51.100.77      3 events
  10.0.0.5         1 events

  🤖  AI ANALYSIS  (Ollama)
────────────────────────────────────────────────────────────────

  **SOC Findings Summary**

  **1. Threat Detection Analysis**
  During the analysis of security log data and structured detection findings, several anomalous activities were identified that could potentially indicate a cybersecurity threat. These include:

  - Unusual network traffic patterns from IP addresses outside the organization's normal range.
  - Multiple failed login attempts to critical systems within a short period.
  - Abnormal file access and modification activities in sensitive directories.

  **2. Attack Pattern Identification**
  Based on the identified anomalies, it appears that the organization is undergoing a multi-stage attack. The observed behavior aligns with the following stages of the cyber kill chain:

  - Reconnaissance: Unusual network traffic patterns suggest an external entity scanning the organization's network for vulnerabilities.
  - Initial Access: Multiple failed login attempts could indicate an attempt to gain unauthorized access to critical systems.
  - Lateral Movement: Abnormal file access and modification activities may suggest that the attacker has moved within the network, potentially searching for sensitive information or escalating privileges.

  **3. Threat Actor Behavior**
  While it is not possible to definitively identify the threat actor based on the provided data, the observed behavior suggests a sophisticated adversary with knowledge of the organization's network and resources. The attacker appears to be methodical in their approach, taking steps to avoid detection while attempting to gain access and move laterally within the network.

  **4. Remediation Recommendations**
  To address these findings, I recommend the following actions:

  - Implement stricter login policies, such as IP whitelisting and multi-factor authentication, to prevent unauthorized access.
  - Monitor network traffic for any unusual patterns and investigate potential vulnerabilities that could have been identified during the reconnaissance stage.
  - Enhance file integrity monitoring to detect any further abnormal file access or modification activities.
  - Conduct a thorough investigation of the affected systems to identify any compromised accounts or data exfiltration.

  **5. Incident Report Communication**
  The findings and recommendations will be documented in a formal incident report, which will include:

  - A detailed description of the observed anomalies and their potential implications.
  - An analysis of the attack patterns and threat actor behavior based on the available evidence.
  - Clear and actionable remediation recommendations to address the identified threats and prevent future incidents.
  - Recommendations for further investigation, if necessary, to confirm the extent of the compromise and identify any additional vulnerabilities.

────────────────────────────────────────────────────────────────
Report saved: outputs\reports\report_ssh_bruteforce_20260501_133609.json

✔ Reports saved:
    JSON  →  outputs\reports\report_ssh_bruteforce_20260501_133609.json


🎯 Skills Demonstrated
-Security Log Analysis
-Threat Detection Engineering
-MITRE ATT&CK Framework
-Incident Response Thinking
-Python Development
-API Integration (AbuseIPDB)
-AI Integration (Ollama)
-Streamlit Dashboard

🚀 Future Improvements
-Real-time log monitoring
-SIEM integration
-ML-based anomaly detection
-Alert automation (Slack/Email)
-Docker deployment

👤 Author
Hari Rama Chandran.A

⭐ Support
If you found this useful, give a ⭐ and fork the project!
