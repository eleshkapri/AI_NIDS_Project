import streamlit as st
import seaborn as sns
import matplotlib.pyplot as plt
import data_loader as dl  # <--- This is the line that was missing!
from model_engine import NIDSModel

# --- 1. CONFIGURATION ---
st.set_page_config(page_title="AI-NIDS Dashboard", layout="wide")

# Initialize Session State for Model persistence
if 'nids_model' not in st.session_state:
    st.session_state['nids_model'] = NIDSModel()

# --- 2. HEADER ---
st.title("🛡️ AI-Based Network Intrusion Detection System")
st.markdown("""
This system uses a **Random Forest Classifier** to detect network anomalies.
It is currently compatible with **CIC-IDS2017** feature sets or internal simulation.
""")

# --- 3. DATA LOADING ---
# Toggle between Simulation and Production here

# Filepath for Real Data
data_file = "traffic_data.csv" 

# Try to load real data
loaded_data = dl.load_cicids2017(data_file)

if isinstance(loaded_data, str): 
    # If load_cicids2017 returns a string, it's an error message
    st.error(loaded_data)
    st.warning("Falling back to Simulation Mode...")
    df = dl.generate_synthetic_data()
elif loaded_data is None:
    st.error(f"File '{data_file}' not found. Please check the filename.")
    st.warning("Falling back to Simulation Mode...")
    df = dl.generate_synthetic_data()
else:
    st.success("✅ Real CIC-IDS2017 Data Loaded Successfully!")
    df = loaded_data

# --- 4. SIDEBAR ---
st.sidebar.header("Control Panel")
st.sidebar.info(f"System Status: Active\nData Points: {len(df)}")

if st.sidebar.button("Train Model Now"):
    with st.spinner("Training Random Forest Model..."):
        acc = st.session_state['nids_model'].train(df)
    st.sidebar.success(f"Training Complete! Accuracy: {acc:.2%}")

# --- 5. DASHBOARD VISUALIZATION ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("Traffic Class Distribution")
    fig, ax = plt.subplots()
    sns.countplot(x='Class', data=df, ax=ax, palette="viridis")
    ax.set_xticklabels(['Benign', 'Malicious'])
    st.pyplot(fig)

with col2:
    st.subheader("Feature Correlation Matrix")
    # Select only numeric columns for correlation to avoid errors
    numeric_df = df.select_dtypes(include=['float64', 'int64', 'int32'])
    fig2, ax2 = plt.subplots()
    sns.heatmap(numeric_df.corr(), annot=True, cmap='coolwarm', ax=ax2, fmt=".2f")
    st.pyplot(fig2)

# --- 6. LIVE SIMULATION INTERFACE ---
st.markdown("---")
st.header("🚦 Live Traffic Simulator")
st.write("Input packet parameters below to test the detection engine.")

# Input fields
c1, c2, c3 = st.columns(3)
p_dur = c1.number_input("Packet Duration", min_value=0.0, value=50.0)
src_bytes = c2.number_input("Source Bytes", min_value=0.0, value=200.0)
dst_bytes = c3.number_input("Dest Bytes", min_value=0.0, value=200.0)

c4, c5 = st.columns(2)
flag_rst = c4.selectbox("Flag Reset (RST)", [0, 1])
proto = c5.selectbox("Protocol", [0, 1, 2], format_func=lambda x: {0:"TCP", 1:"UDP", 2:"ICMP"}[x])

# Prediction Logic
if st.button("Analyze Packet"):
    if st.session_state['nids_model'].is_trained:
        input_vector = [p_dur, src_bytes, dst_bytes, flag_rst, proto]
        
        prediction = st.session_state['nids_model'].predict_packet(input_vector)
        
        if prediction == 1:
            st.error("🚨 ALERT: Malicious Traffic Detected!")
        else:
            st.success("✅ Traffic is Benign.")
    else:
        st.warning("⚠️ Please train the model in the sidebar first.")