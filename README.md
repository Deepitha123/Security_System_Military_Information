# 🛡️ AI-Driven Security Framework for Secure Military Information Systems

An AI-powered cybersecurity framework for detecting, classifying, explaining, and prioritizing network-based cyber threats in sensitive military information systems.

The project combines **XGBoost-based attack classification**, **SHAP Explainable AI**, **threat severity mapping**, **risk scoring**, and a **Streamlit cybersecurity dashboard** into an end-to-end security monitoring pipeline.

> **Note:** This project is an academic/prototype cybersecurity framework. It is not an operational military security system.

---

## 🚀 Key Features

- 🧠 **AI-based network attack classification**
- 🎯 **9-class attack classification**
- ⚖️ **Class-balanced XGBoost**
- 📊 **Performance evaluation using accuracy, precision, recall, and F1-score**
- 🔍 **Confusion matrix analysis**
- 🧠 **SHAP Explainable AI**
- 🚨 **Threat severity classification**
- 📈 **Numerical risk scoring**
- 🔔 **Security alert generation**
- 🖥️ **Interactive Streamlit dashboard**
- 📁 **CSV-based network traffic analysis**
- 📋 **Attack distribution and risk distribution visualization**

---

## 🏗️ System Architecture

```text
                 Network Traffic
                       │
                       ▼
              194 Network Features
                       │
                       ▼
              Preprocessing / Encoding
                       │
                       ▼
        Class-Balanced XGBoost Model
                       │
                       ▼
             Attack Classification
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
   SHAP Explainability        Confidence Score
          │                         │
          └────────────┬────────────┘
                       ▼
                Risk Assessment
                       │
                       ▼
             Threat Severity Level
                       │
                       ▼
                Security Alert
                       │
                       ▼
             Streamlit Dashboard
```

---

## 🎯 Attack Classes

The final attack-only classifier contains 9 classes:

| Class | Attack Type |
|---:|---|
| 0 | Analysis |
| 1 | Backdoor |
| 2 | DoS |
| 3 | Exploits |
| 4 | Fuzzers |
| 5 | Generic |
| 6 | Reconnaissance |
| 7 | Shellcode |
| 8 | Worms |

The project also used a 10-class dataset configuration that included **Normal** traffic. The final dashboard attack-analysis pipeline focuses on the 9 attack classes.

---

## 🤖 Final Model

The selected model is the **Attack-Only Class-Balanced XGBoost classifier**.

### Evaluation Results

| Metric | Score |
|---|---:|
| Accuracy | 75.17% |
| Weighted Precision | 86.67% |
| Weighted Recall | 75.17% |
| Weighted F1 | 79.03% |
| Macro F1 | 55.84% |

The model was selected after comparing standard multiclass XGBoost, class-balanced XGBoost, tuned class-balanced XGBoost, and the attack-only classification approach.

---

## 🧠 Explainable AI

SHAP (SHapley Additive exPlanations) is used to identify which network features contribute most strongly to attack classification.

The project exports the top feature importance values to:

```text
dashboard_data/shap_feature_importance.csv
```

The SHAP analysis used a sample of network traffic and calculated feature contributions for the multiclass XGBoost model.

---

## 🚨 Threat Severity and Risk Scoring

The framework maps predicted attack categories to security severity levels.

| Attack Type | Severity |
|---|---|
| Analysis | Low |
| Fuzzers | Medium |
| Reconnaissance | Medium |
| Generic | Medium |
| DoS | High |
| Exploits | High |
| Backdoor | Critical |
| Shellcode | Critical |
| Worms | Critical |

The final risk score combines the base severity score with model confidence.

Risk levels:

```text
Low
Medium
High
Critical
```

Security alert priorities are generated as:

```text
Low       → LOW PRIORITY
Medium    → MONITOR
High      → HIGH PRIORITY
Critical  → IMMEDIATE ACTION
```

---

## 📊 Dashboard

The Streamlit dashboard provides sections for:

- 🏠 Security Overview
- 🎯 Attack Analysis
- 🚨 Threat Risk
- 🧠 Explainable AI
- 🔔 Security Alerts
- 📋 Threat Data
- 🔬 Live Network Threat Analysis

The live analysis interface accepts a CSV containing the **194 processed features** expected by the trained XGBoost model.

---

## 📁 Project Structure

```text
AI_Military_Security_Dashboard/
│
├── dashboard_data/
│   ├── attack_distribution.csv
│   ├── attack_xgb_model.pkl
│   ├── feature_names.pkl
│   ├── risk_distribution.csv
│   ├── risk_results.csv
│   └── shap_feature_importance.csv
│
├── venv/
│
├── app.py
├── requirements.txt
├── README.md
└── .gitignore
```

### Important files

**`app.py`**
- Main Streamlit dashboard application.

**`dashboard_data/attack_xgb_model.pkl`**
- Trained attack-only XGBoost model.

**`dashboard_data/feature_names.pkl`**
- Feature ordering expected by the trained model.

**`dashboard_data/shap_feature_importance.csv`**
- Exported SHAP feature importance results.

**`dashboard_data/risk_results.csv`**
- Threat-level and risk-scoring results.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd AI_Military_Security_Dashboard
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If XGBoost is missing:

```bash
python -m pip install xgboost
```

---

## ▶️ Run the Dashboard

From the project root:

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal, normally:

```text
http://localhost:8501
```

---

## 📤 Live Threat Analysis Input

The Live Network Threat Analysis section expects a CSV containing the same **194 processed features** used during model training.

The feature order must match:

```text
dashboard_data/feature_names.pkl
```

For testing the dashboard, a synthetic 194-feature CSV can be used. Synthetic data is intended only for verifying the application pipeline and does not represent real military network traffic.

---

## 📦 Requirements

The project uses the following major Python libraries:

- Streamlit
- Pandas
- NumPy
- Scikit-learn
- XGBoost
- Joblib
- SHAP
- Matplotlib
- Seaborn

Install them using:

```bash
pip install -r requirements.txt
```

---

## 🔬 Machine Learning Workflow

### Step 1 — Data Preparation
Network traffic data is processed into numerical features.

### Step 2 — Label Encoding
Attack categories are converted into numerical class IDs.

### Step 3 — Multiclass Classification
Several XGBoost configurations are evaluated.

### Step 4 — Class Imbalance Handling
Balanced sample weights are used to improve recognition of minority attack classes.

### Step 5 — Attack-Only Classification
Normal traffic is separated and the remaining traffic is classified into 9 attack categories.

### Step 6 — Model Evaluation
Accuracy, precision, recall, weighted F1, macro F1, and confusion matrices are analyzed.

### Step 7 — Explainability
SHAP identifies important network features influencing model decisions.

### Step 8 — Risk Assessment
Predicted attack type and model confidence are converted into a threat severity and risk level.

### Step 9 — Security Alert
A priority alert is generated based on the resulting risk level.

### Step 10 — Dashboard
The complete workflow is presented through an interactive Streamlit interface.

---

## 🛡️ Military Cybersecurity Relevance

The framework demonstrates how AI can support the protection of sensitive information systems by:

- Detecting suspicious network activity
- Identifying different categories of cyber attacks
- Prioritizing threats according to severity
- Providing interpretable model decisions
- Supporting security analysts with automated alerts
- Presenting security information through a centralized monitoring dashboard

The military context is represented as an application scenario for protecting sensitive information infrastructure.

---

## ⚠️ Limitations

- The current system is a research/academic prototype.
- Dashboard input must match the feature representation used during training.
- Model performance depends on the underlying dataset and feature quality.
- Rare attack classes remain more difficult to classify reliably.
- The risk mapping is a project-defined scoring framework, not a real-world military security standard.
- The dashboard does not directly capture live network packets.

---

## 🔮 Future Enhancements

Possible extensions include:

- Real-time packet capture using a network monitoring interface
- Streaming threat detection
- Automated SOC-style alert management
- Time-series attack analysis
- More advanced ensemble models
- Improved minority-class detection
- Authentication and role-based dashboard access
- Secure model serving
- Database-backed event storage
- Automated incident response workflows
- Deployment in a controlled cybersecurity laboratory environment

---

## 👩‍💻 Project

**Project Title:** AI-Driven Security Framework for Secure Military Information Systems

**Technology Stack:**

```text
Python
XGBoost
SHAP
Scikit-learn
Pandas
NumPy
Streamlit
Matplotlib
Seaborn
Joblib
```

---

## 📜 Disclaimer

This project is developed for educational, research, and cybersecurity demonstration purposes. It should be tested only with authorized network data and controlled environments.
