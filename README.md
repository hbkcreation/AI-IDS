# AI-IDS
# 🛡️ AI-Based Network Intrusion Detection System (AI-IDS)

## 📌 Overview

This project presents an **Artificial Intelligence-Based Network Intrusion Detection System (AI-IDS)** that combines **Machine Learning**, **Real-Time Packet Analysis**, **Phishing Detection**, and **Access Control** to identify malicious network activities.

The system uses a **Random Forest Classifier** trained on the **CICIDS2017 dataset** to detect **DoS/DDoS attacks** and monitor network traffic in real time using **Scapy**.

---

## 🚀 Features

- Real-time packet capture using Scapy
- Machine Learning-based intrusion detection
- DoS / DDoS attack detection
- DNS-based phishing website detection
- Website access control
- Telegram alert notifications
- Automatic IP blocking
- ROC Curve and Performance Evaluation
- Lightweight Linux deployment

---

## 📂 Dataset

**Dataset:** CICIDS2017

### Files Used

- Monday-WorkingHours.pcap_ISCX.csv
- Tuesday-WorkingHours.pcap_ISCX.csv
- Wednesday-workingHours.pcap_ISCX.csv
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

---

## 🏗️ System Architecture

```text
Network Traffic
       │
       ▼
 Packet Capture
   (Scapy)
       │
       ▼
 Feature Extraction
       │
       ▼
 Random Forest Model
       │
       ▼
 ┌─────────────┬─────────────┬─────────────┐
 │             │             │
 ▼             ▼             ▼
DoS Alert   Phishing     Website
Detection   Detection    Control
 │             │             │
 └──────┬──────┴──────┬──────┘
        ▼
 Telegram Alerts
        │
        ▼
   IP Blocking
```

---

## 🧠 Machine Learning Model

### Algorithm

**Random Forest Classifier**

### Features Used

- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Flow Bytes/s
- Flow Packets/s

### Label Mapping

| Label | Class |
|--------|--------|
| 0 | Benign |
| 1 | DoS / DDoS |

---

## 📊 Model Performance

### Classification Report

| Class | Precision | Recall | F1-Score |
|--------|----------|--------|----------|
| Benign | 0.979 | 0.937 | 0.957 |
| DoS | 0.940 | 0.980 | 0.959 |

### Overall Metrics

| Metric | Value |
|----------|---------|
| Accuracy | 95.8% |
| AUC Score | 0.99 |

---

## 📉 Confusion Matrix

|                | Predicted Benign | Predicted DoS |
|----------------|-----------------|---------------|
| Actual Benign  | 4591 | 309 |
| Actual DoS     | 100 | 4800 |

---

## 📈 ROC Curve

The Random Forest classifier achieved an **AUC Score of 0.99**, indicating excellent discrimination between benign and malicious traffic. The ROC curve remains close to the upper-left corner, demonstrating strong detection capability with low false-positive rates.

---

## 🔔 Telegram Alert System

When suspicious activity is detected, the system automatically sends alerts through Telegram.

### Example Alert

```text
🚨 DoS Attack Detected

Source IP: 192.168.1.15

Action Taken: Blocked
```

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- Pandas
- NumPy
- Scikit-Learn
- Matplotlib
- Requests
- Telegram Bot API
- Linux
- VirtualBox

---

## 📦 Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/AI-IDS.git
cd AI-IDS
```

### Install Dependencies

```bash
pip install pandas numpy scikit-learn matplotlib requests scapy
```

---

## ▶️ Train the Model

```bash
python3 rf_model.py
```

### Sample Output

```text
Accuracy: 0.958

AUC Score: 0.99

Model saved → rf_model.pkl
```

---

## ▶️ Run the IDS

```bash
sudo python3 ai_ids.py
```

### Sample Output

```text
🚀 AI IDS Running...

Normal → IP / TCP

🚨 DoS Attack Detected

🎣 Phishing Domain Detected

🚫 Unauthorized Website Blocked
```

---

## 📋 Project Workflow

1. Load CICIDS2017 dataset
2. Data preprocessing and cleaning
3. Feature selection
4. Train Random Forest model
5. Evaluate using Accuracy, ROC, AUC, and Confusion Matrix
6. Save trained model
7. Capture live packets using Scapy
8. Extract packet features
9. Classify traffic as Benign or DoS
10. Generate alerts and enforce access control

---

## 📈 Results

The proposed AI-IDS achieved:

- **Accuracy:** 95.8%
- **AUC Score:** 0.99
- High DoS detection rate
- Low false negative rate
- Real-time packet inspection capability
- Telegram-based alert generation

---

## 🔮 Future Enhancements

- Deep Learning-based Intrusion Detection
- Explainable AI (XAI)
- Multi-class Attack Classification
- Web Dashboard Monitoring
- Cloud Deployment
- SIEM Integration

---

## 👨‍💻 Author

**Sri Hari HBK**

B.Tech Final Year Project

Artificial Intelligence Based Network Intrusion Detection System

---

## 📄 License

This project is intended for academic, educational, and research purposes.
