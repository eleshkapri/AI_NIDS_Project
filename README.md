# 🛡️ AI-Based Network Intrusion Detection System (AI-NIDS)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![Machine Learning](https://img.shields.io/badge/AI-Random%20Forest-green)

An AI-powered dashboard that detects malicious network traffic using a **Random Forest Classifier**. This project can analyze live traffic logs or run in simulation mode.

## 📊 Dataset (Required)
This project relies on network traffic data (Wireshark logs or CIC-IDS2017). 
I have hosted the dataset on Kaggle for easy access.

👉 **[DOWNLOAD THE DATASET HERE](https://kaggle.com/datasets/2f6c2a024a8423c27bf83f299cadc275ce3c9e032d80127a09c4b08cf8cf0442)**

### Setup Instructions:
1. Download the dataset from the link above.
2. Unzip the file (if necessary).
3. **Rename the file** to: `traffic_data.csv`
4. Place it in the root folder of this project.

---

## 🚀 How to Run Locally

### 1. Clone the Repository
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/AI_NIDS_Project.git](https://github.com/YOUR_GITHUB_USERNAME/AI_NIDS_Project.git)
cd AI_NIDS_Project

```

### 2. Create the Virtual Environment (venv)

This isolates the project so it doesn't conflict with other Python apps.

**Windows:**

```bash
python -m venv venv

```

### 3. Activate the Environment

You must do this every time you open the project.

**Windows:**

```bash
.\venv\Scripts\activate

```

*(You will know it worked if you see `(venv)` at the start of your terminal line).*

### 4. Install Dependencies

This installs all required libraries (Streamlit, Pandas, etc.) and automatically handles caching.

```bash
pip install -r requirements.txt

```

> **Note:** The `__pycache__` folder will be created automatically by Python when you run this command. You do not need to install it manually.

### 5. Start the Project

Run the dashboard using Streamlit:

```bash
streamlit run app.py

```

---

## 📸 Screenshots

### Main Dashboard

*(screenshots/dashboard_1.png ,screenshots/dashboard_2.png )*

### Detection Alert

*(screenshots/alert.png)*

---

## 🛠️ Features

* **Production Mode:** Automatically detects if `traffic_data.csv` is present.
* **Smart Parsing:** Converts Wireshark exports to ML features automatically.
* **Simulation Mode:** Generates synthetic traffic if no data is found.
* **Interactive Interface:** Visualize traffic and test packet parameters.

---

## 📂 Project Structure

* `app.py`: Main Streamlit dashboard.
* `data_loader.py`: Data processing and Wireshark conversion.
* `model_engine.py`: Random Forest training logic.
* `requirements.txt`: Python dependencies.