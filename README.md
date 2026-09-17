# 🛡️ URL Security Using IP-Based Threat Analysis

An AI-powered security system for detecting malicious URLs in real time using **rule-based heuristics**, **IP intelligence**, and **machine learning**. The system analyzes URL structure, associated IP addresses, DNS/traffic features, and reputation data to identify potentially malicious activity and present actionable results through an interactive dashboard.

> **Project:** `url-security-ip-analysis`  
> **Purpose:** Educational and defensive security analysis

---

## ✨ Features

- 🔍 **Hybrid Detection** – Combines rule-based heuristics with machine-learning models such as Random Forest and XGBoost.
- 📡 **Live Traffic Capture** – Captures network traffic and extracts URLs using Scapy/Npcap.
- 🚨 **Automated Alerts** – Generates alerts for suspicious URLs and IP addresses with severity levels.
- 🌐 **IP Intelligence** – Checks IP reputation using AbuseIPDB and an internal threat database.
- 📊 **Interactive Dashboard** – Streamlit dashboard for monitoring URLs, IPs, predictions, and alerts.
- 🔌 **REST API** – FastAPI endpoints for URL scanning, alert management, IP reputation, and dashboard statistics.
- 🗄️ **MySQL Storage** – Persists URLs, IP information, alerts, features, and prediction results.
- 🧠 **Feature Engineering** – Extracts URL, IP, DNS, geographic, and traffic-related features for detection.
- ⚡ **Real-Time Analysis** – Supports both live monitoring and simulated traffic for development/testing.

---

## 🏗️ System Architecture

```text
                    ┌──────────────────────┐
                    │   Network Traffic    │
                    │   / URLs / Feeds     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Data Collector     │
                    │ Scapy / APIs / Feeds │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Feature Engineering  │
                    │ URL / IP / DNS / Geo │
                    └──────────┬───────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
        ┌──────────────────┐      ┌──────────────────┐
        │ Rule-Based       │      │ Machine Learning │
        │ Detection Engine │      │ Prediction       │
        └────────┬─────────┘      └────────┬─────────┘
                 │                         │
                 └────────────┬────────────┘
                              ▼
                    ┌──────────────────────┐
                    │ Combined Decision    │
                    │ Risk / Severity      │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
        ┌──────────────┐ ┌────────────┐ ┌──────────────┐
        │ MySQL        │ │ FastAPI    │ │ Streamlit    │
        │ Database     │ │ REST API   │ │ Dashboard    │
        └──────────────┘ └────────────┘ └──────────────┘
```

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Backend | Python 3.11 |
| API Framework | FastAPI |
| Dashboard | Streamlit |
| Database | MySQL 8.0 |
| Machine Learning | Scikit-learn, XGBoost, TensorFlow |
| Packet Capture | Scapy, Npcap |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly, Matplotlib |
| Environment | Python Virtual Environment |
| API Documentation | Swagger / OpenAPI |

---

## 📁 Project Structure

```text
url-security-ip-analysis/
│
├── src/
│   ├── data_collector/
│   │   └── # URL collection from APIs and threat feeds
│   │
│   ├── feature_engineering/
│   │   └── # URL, IP, DNS, Geo and traffic feature extraction
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
│       └── # Home, Scanner, IP, Alerts, etc.
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
├── requirements.txt
├── .env.example
└── README.md
```

> File names may vary depending on the current implementation. Keep this structure synchronized with the actual repository.

---

# 🚀 Installation

## Prerequisites

Make sure the following are installed:

- **Python 3.9+** (Python 3.11 recommended)
- **MySQL 8.0+**
- **Git**
- **Npcap** on Windows for live packet capture
- **libpcap** on Linux/macOS for packet capture
- An **AbuseIPDB API key** if external IP reputation lookup is enabled

---

## 1. Clone the Repository

```bash
git clone https://github.com/your-username/url-security-ip-analysis.git
cd url-security-ip-analysis
```

Replace `your-username` with the GitHub username that owns the repository.

---

## 2. Create a Virtual Environment

### Windows

```bash
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
pip install --upgrade pip
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
DB_PASSWORD=yourpassword
DB_NAME=url_threat_analysis

API_HOST=127.0.0.1
API_PORT=8001

ABUSEIPDB_API_KEY=your_api_key
```

### Security Note

Never commit `.env` or API keys to GitHub.

Add the following to `.gitignore` if necessary:

```gitignore
.env
venv/
__pycache__/
*.pyc
```

---

## 5. Create the Database

Make sure MySQL is running, then initialize the database:

```bash
python scripts/setup_database.py
```

The database should contain the tables required for URLs, IP information, alerts, predictions, and related records.

---

## 6. Collect Data and Train the Models

If the project includes the initial data-collection workflow:

```bash
python scripts/run_week2.py
```

Then train the models:

```bash
python scripts/train_model.py
```

The exact generated model files depend on the implementation and training configuration.

---

# 🖥️ Usage

## 1. Start the FastAPI Server

```bash
python scripts/run_api.py
```

The API will normally be available at:

```text
http://localhost:8001
```

Interactive API documentation:

```text
http://localhost:8001/docs
```

FastAPI also provides OpenAPI documentation that can be used to test endpoints directly from the browser.

---

## 2. Start the Streamlit Dashboard

Open another terminal with the virtual environment activated:

```bash
streamlit run dashboard/app.py
```

The dashboard is normally available at:

```text
http://localhost:8501
```

The dashboard can be used to:

- Scan URLs
- View malicious/suspicious URLs
- Inspect IP reputation
- Review alerts
- View prediction results
- Monitor security statistics
- Analyze detection activity

---

## 3. Run Live Traffic Monitoring

### Windows

Run PowerShell or Command Prompt as Administrator if required by the packet-capture configuration:

```bash
python scripts/live_monitor.py
```

### Linux

Depending on your packet-capture configuration and permissions:

```bash
sudo python scripts/live_monitor.py
```

> Only capture and analyze traffic on networks and systems where you have authorization.

---

## 4. Run Simulated Monitoring

For development or demonstrations where live packet capture is not required:

```bash
python scripts/quick_monitor.py
```

This is useful for testing the alerting and dashboard workflow without depending on live network traffic.

---

# 🔍 URL Scanning

A typical workflow is:

```text
User / Application
       │
       ▼
   Submit URL
       │
       ▼
URL Normalization
       │
       ▼
Feature Extraction
       │
       ├───────────────┐
       ▼               ▼
Rule Engine       ML Prediction
       │               │
       └───────┬───────┘
               ▼
        Risk Aggregation
               │
               ▼
      Benign / Suspicious /
          Malicious
```

The resulting prediction can include information such as:

- URL
- Domain
- Resolved IP
- Rule-based score
- ML prediction
- Confidence/probability
- Severity
- Triggered indicators
- IP reputation
- Final classification

---

# 🧠 Detection Methodology

The project uses a **hybrid detection architecture**.

## 1. Rule-Based Detection

The rule engine checks for indicators such as:

- Known benign domains
- High-risk or suspicious TLDs
- Brand impersonation
- Typosquatting
- Suspicious keywords
- Excessive URL length
- Unusual subdomains
- Executable file extensions
- URL encoding anomalies
- Suspicious IP-based URLs
- Other structural URL anomalies

### Example

```text
https://paypaI.example.com/login/verify
```

Potential indicators could include:

- Brand impersonation
- Suspicious subdomain
- Login/verification keyword
- Character substitution

The rules produce signals that contribute to the final risk assessment.

---

## 2. IP Intelligence

The system can associate a URL with its resolved IP address and evaluate IP-related information.

Possible inputs include:

- IP reputation
- Abuse reports
- Geographic information
- Autonomous System information
- Internal threat intelligence
- Historical observations

External reputation services should be treated as supplementary intelligence rather than a single source of truth.

---

## 3. Machine Learning

The ML pipeline uses extracted URL/IP-related features to classify URLs.

Models supported by the project include:

- XGBoost
- Random Forest
- Gradient Boosting
- Neural Network
- Logistic Regression

The current implementation uses a selected feature set for model training and prediction.

---

## 4. Combined Decision

The final decision combines rule-based and ML signals.

Conceptually:

```text
                 URL
                  │
          ┌───────┴────────┐
          ▼                ▼
     Rule Engine       ML Models
          │                │
          ▼                ▼
      Rule Score       ML Score
          │                │
          └───────┬────────┘
                  ▼
          Decision Engine
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
      Benign   Suspicious  Malicious
```

Rules can provide strong signals for known patterns, while ML can help generalize to less obvious cases.

---

# 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | API health check |
| `POST` | `/scan` | Scan a single URL |
| `GET` | `/scan?url=...` | Scan a URL using query parameters |
| `POST` | `/scan/batch` | Scan multiple URLs |
| `GET` | `/alerts` | Retrieve alerts |
| `PUT` | `/alerts/{id}` | Update alert status |
| `GET` | `/ip/{ip}` | Check IP reputation/details |
| `GET` | `/dashboard/summary` | Retrieve dashboard statistics |

### API Documentation

After starting the API server, open:

```text
http://localhost:8001/docs
```

Use the Swagger UI to inspect request parameters, responses, and available operations.

---

# 🧪 Testing

## Predictor Test

Run the prediction module:

```bash
python -m src.ml_pipeline.prediction
```

---

## Database Verification

If the repository contains the database-checking script:

```bash
python scripts/check_urls.py
```

---

## Recommended Test Categories

Test the detector with:

### Benign URLs

```text
https://www.google.com
https://www.microsoft.com
https://www.wikipedia.org
```

### Suspicious URLs

```text
https://example.xyz/login/verify
https://secure-example.invalid/account/login
```

### Typosquatting Examples

```text
https://gooogle.example
https://micros0ft.example
```

> Use controlled/test domains when demonstrating suspicious URL patterns. Do not intentionally visit unknown malicious URLs.

---

# 📊 Model Evaluation

Example evaluation results from the project dataset:

| Model | Accuracy | F1 Score |
|---|---:|---:|
| XGBoost | 100% | 1.0000 |
| Random Forest | 99% | 0.9901 |
| Gradient Boosting | 100% | 1.0000 |
| Neural Network | 100% | 1.0000 |
| Logistic Regression | 98% | 0.9800 |

### Important

These results are **dataset-specific**. A reported 100% test accuracy does not imply that the detector will achieve 100% accuracy on real-world URLs.

For a production-grade evaluation, measure performance on an independent, representative dataset and report metrics such as:

- Precision
- Recall
- F1 score
- ROC-AUC
- False-positive rate
- False-negative rate
- Confusion matrix

---

# 📈 Dashboard

The Streamlit dashboard is intended to provide security analysts with a centralized view of the detection system.

Typical dashboard sections include:

### 🏠 Home

- Total URLs analyzed
- Malicious URL count
- Suspicious URL count
- Alert statistics
- Recent activity

### 🔎 Scanner

- Enter a URL
- Run detection
- Display risk score
- Show triggered rules
- Display ML prediction

### 🌐 IP Intelligence

- IP address information
- Reputation information
- Related URLs
- Threat observations

### 🚨 Alerts

- Alert severity
- Source URL/IP
- Detection reason
- Timestamp
- Alert status

---

# 🗄️ Database

MySQL is used for persistent storage.

The database layer is responsible for:

- Connection management
- URL records
- IP records
- Alerts
- Prediction results
- Detection metadata
- Dashboard statistics

The main database configuration can be found under:

```text
config/
database/
```

---

# 🔐 Security Considerations

This project should be deployed carefully because URL and network analysis can involve sensitive data.

Recommended practices:

- Never commit API keys or passwords.
- Use environment variables for secrets.
- Restrict database access.
- Validate and sanitize API inputs.
- Use HTTPS when deploying the API publicly.
- Apply authentication/authorization for production deployments.
- Avoid storing unnecessary personal or network-identifying information.
- Restrict packet capture to authorized interfaces.
- Run live capture with the minimum required privileges.
- Treat third-party IP reputation data as potentially incomplete or stale.
- Log security events without exposing sensitive credentials.

---

# ⚠️ Limitations

The detector may produce false positives or false negatives.

Potential limitations include:

- Domain reputation can change over time.
- Attackers can rapidly rotate domains and IP addresses.
- IP reputation services may have incomplete coverage.
- DNS/CDN infrastructure can make IP attribution ambiguous.
- URL-based features alone cannot guarantee malicious intent.
- ML performance depends heavily on training data quality.
- High benchmark accuracy can result from dataset characteristics or leakage.
- HTTPS encrypts URL paths, limiting what passive network monitoring can observe.
- Live packet capture requires appropriate permissions and platform-specific configuration.

---
### Model Evaluation Methodology

We use **GroupShuffleSplit by domain** to prevent data leakage. This ensures 
all URLs from a given domain appear in exactly one of the train/test sets, 
giving a realistic evaluation of generalization to unseen domains.

| Model | Precision | Recall | F1 Score |
|-------|-----------|--------|----------|
| ...   | ...       | ...    | ...      |

# 🚀 Future Enhancements

Possible extensions include:

- 🔄 Continuous threat-intelligence feed updates
- 🧠 Deep-learning URL classification
- 🌍 DNS and WHOIS intelligence
- 🛰️ ASN and hosting-provider analysis
- 🧩 Browser-extension integration
- 📱 Mobile-friendly monitoring dashboard
- 🔔 Email/Slack notification integration
- 📈 Historical threat analytics
- 🧪 Automated model retraining
- 🔐 Role-based access control
- ☁️ Cloud deployment
- 🧬 Graph-based relationship analysis between domains, IPs, and URLs
- ⚡ Streaming analysis using Kafka or Redis
- 🛡️ Integration with SIEM platforms

---

# 🤝 Contributing

Contributions are welcome.

## Development Workflow

1. Fork the repository.
2. Create a feature branch.

```bash
git checkout -b feature/your-feature
```

3. Make your changes.
4. Test the implementation.
5. Commit your changes.

```bash
git add .
git commit -m "Add your feature"
```

6. Push the branch.

```bash
git push origin feature/your-feature
```

7. Open a Pull Request.

Please keep contributions focused, documented, and tested where practical.

---

# 📄 License

This project is intended for **educational and defensive security purposes**.

You may modify and distribute the project according to the license terms included in the repository. If no separate license file is present, add an appropriate `LICENSE` file before treating the project as an open-source distribution.

---

# 👤 Author

**Priya**

### Project

**URL Security Using IP-Based Threat Analysis**

Repository name:

```text
url-security-ip-analysis
```

---

# ⚠️ Disclaimer

This project is intended for **authorized security testing, research, education, and defensive monitoring only**.

Do not use this software to intercept, monitor, scan, or analyze networks, URLs, systems, or data without appropriate authorization. The authors and contributors are not responsible for misuse of the software or for damages resulting from its use.

---

# 📸 Screenshots

Add dashboard screenshots to a `screenshots/` directory and reference them here.

Example:

```text
screenshots/
├── dashboard.png
├── url-scanner.png
├── ip-analysis.png
└── alerts.png
```

Then add:

```markdown
![Dashboard](screenshots/dashboard.png)

![URL Scanner](screenshots/url-scanner.png)

![IP Analysis](screenshots/ip-analysis.png)

![Alerts](screenshots/alerts.png)
```

---

# ⭐ Quick Start

For a quick local setup:

```bash
# Clone
git clone https://github.com/your-username/url-security-ip-analysis.git
cd url-security-ip-analysis

# Environment
python -m venv venv

# Windows
venv\Scripts\activate

# Install
pip install -r requirements.txt

# Configure .env
# Then initialize the database
python scripts/setup_database.py

# Train model
python scripts/train_model.py

# Start API
python scripts/run_api.py

# In another terminal, start dashboard
streamlit run dashboard/app.py
```

Open:

```text
API:       http://localhost:8001
API Docs:  http://localhost:8001/docs
Dashboard: http://localhost:8501
```

---

## ⭐ Project Summary

**URL Security Using IP-Based Threat Analysis** combines **URL heuristics, IP intelligence, machine learning, real-time traffic monitoring, FastAPI, Streamlit, and MySQL** into a unified security-analysis platform.

The goal is to provide security analysts and students with an understandable, extensible system for investigating potentially malicious URLs and their associated network infrastructure.
