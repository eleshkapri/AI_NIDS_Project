---
title: AI NIDS Project
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: streamlit
sdk_version: 1.31.0
app_file: app.py
pinned: false
---
# 🛡️ AI-Based Network Intrusion Detection System (AI-NIDS)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![AI](https://img.shields.io/badge/AI-Groq%20Cloud-orange)
![Sklearn](https://img.shields.io/badge/ML-Random%20Forest-green)

An advanced cybersecurity dashboard that detects network attacks (DDoS, Port Scans, etc.) using **Random Forest** and provides real-time explanations using **Generative AI (Groq Llama-3)**.

## 📊 Datasets (Required)
This project supports two modes. You need at least one of these datasets in your root folder:

1.  **Real Attack Data (Recommended):** `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (From CICIDS2017).
2.  **Demo/Custom Data:** `traffic_data.csv` (Your own Wireshark export).

👉 **[DOWNLOAD THE DATASET HERE](https://kaggle.com/datasets/2f6c2a024a8423c27bf83f299cadc275ce3c9e032d80127a09c4b08cf8cf0442)**

---

## 🚀 Features
* **Dual Dataset Support:** Switch between "Real DDoS Data" and "Custom Wireshark Logs" instantly from the sidebar.
* **Machine Learning:** Uses `RandomForestClassifier` to classify packets as **Safe (Benign)** or **Attack**.
* **AI Analyst:** Integrated **Groq API** (Llama-3 model) to explain *why* a specific packet is suspicious in plain English.
* **Threat Dashboard:** Simulates live traffic and displays packet details in a hacker-style vertical interface.

---

## 📂 Project Structure

```text
├── app.py                # Main application code (Streamlit + ML logic)
├── traffic_data.csv      # Dataset 1: Custom Wireshark export
├── Friday-Working...csv  # Dataset 2: Real DDoS Data (CICIDS2017)
├── requirements.txt      # List of dependencies
└── README.md             # Project documentation

```

---

## 🛠️ How to Run Locally

### 1. Clone the Repository

```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/AI_NIDS_Project.git](https://github.com/YOUR_GITHUB_USERNAME/AI_NIDS_Project.git)
cd AI_NIDS_Project

```

### 2. Create Virtual Environment

```bash
python -m venv venv

```

### 3. Activate Environment

* **Windows:** `.\venv\Scripts\activate`
* **Mac/Linux:** `source venv/bin/activate`

### 4. Install Dependencies

```bash
pip install -r requirements.txt

```

### 5. Start the App

```bash
streamlit run app.py

```

---

## 📸 Screenshots

### Dashboard (Real DDoS Data)
![image alt](https://github.com/eleshkapri/AI_NIDS_Project/blob/76f2e62b9ee9f8c10244148f8fb0e20068b5e04d/screenshots/Real%20DDoS%20Data.png)

### Dashboard (Demo Traffic)
![image alt](https://github.com/eleshkapri/AI_NIDS_Project/blob/76f2e62b9ee9f8c10244148f8fb0e20068b5e04d/screenshots/Demo%20Traffic.png)

---

## 🔑 AI Configuration

To use the "Ask AI Analyst" feature, you need a free API key from Groq:

1. Go to [Groq Console](https://console.groq.com/keys).
2. Create a free API Key.
3. Paste the key (`gsk_...`) into the app sidebar when running.

---

## ⚠️ Note

This project is for educational purposes. The "Demo Traffic" mode generates synthetic labels if ground truth is missing from the raw packet capture.
