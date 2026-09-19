# 🛡️ URL Security Using IP-Based Threat Analysis

An AI-powered defensive security system for detecting and analyzing potentially malicious URLs using a **hybrid detection approach** that combines URL-based machine learning, rule-based analysis, IP intelligence, and network/traffic information.

The project is designed as an academic cybersecurity project with a practical **SOC-style URL investigation workflow**.

> **Repository:** `https://github.com/Abhiz084/url-security-ip-analysis`  
> **Purpose:** Educational and defensive security analysis

---

## ✨ Key Features

### 🔍 URL & Threat Detection

- **Hybrid URL detection** using machine-learning models and rule-based heuristics
- URL structure and lexical feature extraction
- IP-based threat analysis
- Suspicious URL and IP alert generation
- Real-time and simulated traffic analysis
- Prediction and detection results stored for later investigation

### 🤖 Machine Learning

The ML pipeline supports models such as:

- Random Forest
- XGBoost
- Scikit-learn models
- TensorFlow-based models

The system extracts URL, IP, DNS, geographic, and traffic-related features and uses them for malicious URL classification.

> **Important:** Model performance should be reported using a reproducible test methodology. High accuracy on a dataset does not by itself guarantee real-world detection performance.

### 🌐 IP Intelligence

- IP reputation analysis
- AbuseIPDB integration
- Internal threat database support
- IP information enrichment
- Suspicious IP identification

### 📡 Real-Time Monitoring

- Network traffic capture using **Scapy**
- Windows packet capture support through **Npcap**
- URL extraction from observed traffic
- Automated suspicious URL/IP alerts
- Simulation mode for development and demonstrations

### 📊 Interactive Dashboard

The Streamlit dashboard provides:

- URL scanning
- IP intelligence
- Prediction results
- Alert monitoring
- Security analytics
- Investigation-oriented views

### 🔌 REST API

A FastAPI backend provides endpoints for:

- URL scanning
- IP reputation
- Alert management
- Prediction access
- Dashboard statistics
- API documentation through Swagger/OpenAPI

### 🗄️ Database

MySQL is used to persist security-related information including:

- URLs
- IP information
- Alerts
- Extracted features
- Prediction results
- Threat-analysis records

---

# 🏗️ System Architecture

```text
                         ┌─────────────────────────┐
                         │   URLs / Network Traffic│
                         │   / Threat Intelligence │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │      Data Collector     │
                         │ Scapy / APIs / Threat   │
                         │          Feeds          │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │   Feature Engineering   │
                         │ URL / IP / DNS / Geo /  │
                         │        Traffic          │
                         └────────────┬────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                 ▼
          ┌─────────────────────┐          ┌─────────────────────┐
          │ Rule-Based Analysis │          │ Machine Learning    │
          │ Heuristics / Rules  │          │ Classification      │
          └──────────┬──────────┘          └──────────┬──────────┘
                     │                                │
                     └────────────────┬───────────────┘
                                      ▼
                         ┌─────────────────────────┐
                         │ Combined Threat Result │
                         │ Risk / Severity /       │
                         │ Detection Information   │
                         └────────────┬────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
        ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
        │     MySQL      │   │    FastAPI     │   │   Streamlit    │
        │    Database    │   │    REST API    │   │    Dashboard   │
        └────────────────┘   └────────────────┘   └────────────────┘
```

---

# 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3.11 |
| Backend API | FastAPI |
| Dashboard | Streamlit |
| Database | MySQL 8.0 |
| Machine Learning | Scikit-learn, XGBoost, TensorFlow |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly, Matplotlib |
| Packet Capture | Scapy, Npcap |
| Environment | Python Virtual Environment |
| API Documentation | Swagger / OpenAPI |
| Threat Intelligence | AbuseIPDB |
| Version Control | Git / GitHub |

---

# 📁 Project Structure

```text
url-security-ip-analysis/
│
├── src/
│   ├── data_collector/
│   │   └── # URL collection and threat-feed processing
│   │
│   ├── feature_engineering/
│   │   └── # URL, IP, DNS, geographic and traffic features
│   │
│   ├── ml_pipeline/
│   │   └── # Model training, evaluation and prediction
│   │
│   └── real_time_monitor/
│       └── # Traffic capture and alert processing
│
├── dashboard/
│   ├── app.py
│   └── pages/
│       └── # Dashboard pages
│
├── scripts/
│   ├── setup_database.py
│   ├── train_model.py
│   ├── run_api.py
│   ├── live_monitor.py
│   ├── quick_monitor.py
│   ├── run_week2.py
│   └── check_urls.py
│
├── database/
│   ├── connection.py
│   └── crud_operations.py
│
├── config/
│   ├── settings.py
│   └── database.py
│
├── models/
│   └── # Trained model artifacts
│
├── requirements.txt
├── .gitignore
├── start_project.py
├── test_unknown_urls.py
└── README.md
```

---

# 🚀 Installation

## Prerequisites

Install the following:

- Python 3.11
- MySQL 8.0+
- Git
- Npcap on Windows for live packet capture
- libpcap on Linux/macOS if packet capture is required
- AbuseIPDB API key if external IP reputation lookup is enabled

---

## 1. Clone the Repository

```bash
git clone https://github.com/Abhiz084/url-security-ip-analysis.git
cd url-security-ip-analysis
```

---

## 2. Create a Virtual Environment

### Windows

```cmd
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables

Create a `.env` file in the project root.

Example:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=url_threat_analysis

API_HOST=127.0.0.1
API_PORT=8001

ABUSEIPDB_API_KEY=your_api_key
```

### 🔐 Security

**Never commit `.env`, API keys, passwords, or other secrets to GitHub.**

Recommended `.gitignore` entries:

```text
.env
venv/
.venv/
__pycache__/
*.pyc
logs/
data/
```

---

# 🗄️ Database Setup

Make sure MySQL is running and execute:

```bash
python scripts/setup_database.py
```

The database stores information required for URL analysis, IP intelligence, alerts, features, and prediction results.

---

# 🤖 Model Training

After the required data has been collected/configured, run:

```bash
python scripts/train_model.py
```

The training pipeline prepares features, trains the supported models, evaluates them, and stores the resulting model artifacts according to the project configuration.

For an academic evaluation, report:

- Accuracy
- Precision
- Recall
- F1-score
- Confusion matrix
- ROC-AUC where applicable

Avoid presenting training-set performance as evidence of real-world detection capability.

---

# 🖥️ Running the Application

## Start the FastAPI Server

```bash
python scripts/run_api.py
```

API:

```text
http://localhost:8001
```

Swagger/OpenAPI documentation:

```text
http://localhost:8001/docs
```

Health endpoint:

```text
http://localhost:8001/health
```

---

## Start the Streamlit Dashboard

```bash
streamlit run dashboard/app.py
```

Dashboard:

```text
http://localhost:8501
```

---

## Start Live Monitoring

On Windows, packet capture may require administrator privileges and Npcap:

```bash
python scripts/live_monitor.py
```

The monitor can capture network traffic, extract relevant indicators, analyze them, and generate alerts.

---

# 🔎 Detection Methodology

The project follows a multi-stage detection workflow:

```text
Input URL / Traffic
        ↓
URL Extraction
        ↓
Feature Engineering
        ↓
Rule-Based Analysis
        ↓
Machine Learning Prediction
        ↓
IP / Reputation Intelligence
        ↓
Combined Threat Assessment
        ↓
Risk / Severity
        ↓
Dashboard + API + Database
```

### URL Features

Examples include:

- URL length
- Hostname length
- Number of subdomains
- Special characters
- Digits
- Suspicious URL patterns
- IP-based hostname indicators
- Encoded characters
- Path/query characteristics

### IP Features

Examples include:

- IP address
- Reputation information
- Abuse reports
- Geographic information
- Network/hosting information
- Threat database matches

### Traffic Features

The monitoring component can use network observations to extract URLs and related indicators for further analysis.

---

# 🎯 Hybrid Detection

The core concept is to avoid depending on only one signal.

The system can combine:

```text
URL Characteristics
        +
Rule-Based Indicators
        +
Machine Learning Prediction
        +
IP Reputation
        +
Network / Threat Intelligence
        ↓
   Threat Assessment
```

This provides additional context for security analysis and helps present a more useful investigation result than a single binary ML prediction.

---

# 📊 Dashboard

The dashboard is intended to provide a security-investigation workflow rather than only displaying a model prediction.

Typical investigation information includes:

- Submitted URL
- Extracted IP
- ML prediction
- Risk/severity information
- IP reputation
- Triggered security indicators
- Alerts
- Historical statistics

---

# 🔐 Security Considerations

This project is designed for defensive and educational security analysis.

When extending the scanner with active URL fetching or deep analysis, implement protections against:

- SSRF
- Private/internal IP access
- Loopback addresses
- Cloud metadata endpoints
- Dangerous URL schemes
- DNS rebinding
- Untrusted redirects

Do not blindly request arbitrary user-supplied URLs from a privileged network environment.

---

# 🧪 Testing

The repository currently contains project-level test scripts for validating URL detection behavior.

Example:

```bash
python test_unknown_urls.py
```

For future development, the test suite can be expanded with:

- URL feature tests
- IP intelligence tests
- Rule-engine tests
- Risk-engine tests
- API integration tests
- ML prediction tests
- Security/SSRF tests

Automated CI/CD is **not required for the core academic implementation** and is intentionally kept outside the main project requirements.

---

# 📈 Evaluation

For a meaningful ML evaluation, the dataset should be checked for:

- Duplicate URLs
- Duplicate domains
- Data leakage
- Class imbalance
- Train/test overlap
- Dataset-specific patterns

A domain-aware train/test split is preferable when URLs from the same domains could otherwise appear in both training and testing data.

The project should distinguish between:

**Model performance on the evaluation dataset**

and

**Expected real-world detection performance.**

---

# ⚠️ Known Limitations

- External threat-intelligence services depend on API availability and quotas.
- IP reputation can change over time.
- A domain being new does not automatically mean it is malicious.
- ML performance depends heavily on dataset quality and feature distribution.
- Live packet capture requires appropriate operating-system permissions and packet-capture drivers.
- HTTPS traffic generally limits visibility into encrypted application-layer content unless traffic is explicitly decrypted in a controlled environment.
- Threat verdicts should be treated as security-analysis signals rather than absolute proof of maliciousness.

---

# 🔮 Future Improvements

Potential extensions include:

1. Domain-aware ML evaluation
2. SHAP-based prediction explanations
3. Advanced DNS and WHOIS intelligence
4. Typosquatting and homograph detection
5. URL normalization
6. Hybrid numerical risk scoring
7. Stronger SSRF protection
8. Redirect-chain analysis
9. TLS/certificate intelligence
10. Additional threat-feed integrations
11. Analyst feedback and historical investigation
12. Automated report generation

---

# 🎓 Academic Value

This project demonstrates concepts across multiple cybersecurity and software-engineering areas:

- Cyber threat detection
- Machine learning
- Feature engineering
- Threat intelligence
- Network monitoring
- IP reputation analysis
- REST API development
- Database design
- Security analytics
- Interactive visualization
- Defensive security engineering

It can also be demonstrated as a simplified **SOC-style URL investigation and threat-analysis platform**.

---

# ⚠️ Disclaimer

This project is intended for **educational, research, and defensive security purposes**.

Do not use the system to access, attack, disrupt, or interfere with systems that you do not own or have explicit authorization to test.

Threat-intelligence and ML results are indicators for analysis and should be validated using appropriate security procedures.

---

# 👨‍💻 Author

**Abhinay Hari**

B.Tech – Computer Science Engineering

Hyderabad Institute of Technology and Management (HITAM)

---

# 📄 License

This project is intended primarily for academic and educational use.
