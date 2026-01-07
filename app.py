import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Try importing Groq
try:
    from groq import Groq
except ImportError:
    st.error("Groq library not found. Please run: pip install groq")
    st.stop()

# --- PAGE SETUP ---
st.set_page_config(page_title="AI-NIDS Project", layout="wide")

# Custom CSS
st.markdown("""
<style>
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
    }
    .success-box {
        padding: 20px;
        background-color: #1b4d3e;
        color: white;
        border-radius: 5px;
        text-align: center;
        margin-bottom: 20px;
    }
    .danger-box {
        padding: 20px;
        background-color: #4d1b1b;
        color: white;
        border-radius: 5px;
        text-align: center;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

st.title("AI-Based Network Intrusion Detection System")

# --- CONFIGURATION ---
DATASETS = {
    "Demo Traffic (traffic_data.csv)": "traffic_data.csv",
    "Real DDoS Data (Friday-WorkingHours...)": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
}

# --- SIDEBAR ---
st.sidebar.header("1. Settings")
groq_api_key = st.sidebar.text_input("Groq API Key (starts with gsk_)", type="password")
st.sidebar.caption("[Get a free key here](https://console.groq.com/keys)")

st.sidebar.header("2. Dataset Selection")
selected_dataset_name = st.sidebar.selectbox("Choose Dataset", list(DATASETS.keys()))
current_file = DATASETS[selected_dataset_name]

st.sidebar.header("3. Model Training")

# --- DATA LOADING ---
@st.cache_data
def load_data(filepath):
    try:
        # Load data (limit rows for speed)
        df = pd.read_csv(filepath, nrows=10000)
        
        # Clean Column Names
        df.columns = df.columns.str.strip()
        
        # Normalize Target Column
        if 'Label' in df.columns:
            df.rename(columns={'Label': 'Class'}, inplace=True)
        
        # Auto-Fix if 'Class' is missing
        if 'Class' not in df.columns:
            if 'Protocol' in df.columns:
                df['Class'] = df['Protocol'].apply(lambda x: 'Normal' if x == 'TCP' else 'Suspicious')
            else:
                df['Class'] = np.random.choice(['Normal', 'Suspicious'], size=len(df))
        
        # Clean Infinite/Null values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        return df
    except FileNotFoundError:
        st.error(f"File not found: {filepath}. Please ensure it is in the project folder.")
        return None

df = load_data(current_file)

# --- SESSION STATE ---
if 'model' not in st.session_state:
    st.session_state['model'] = None
if 'accuracy' not in st.session_state:
    st.session_state['accuracy'] = 0.0
if 'selected_packet' not in st.session_state:
    st.session_state['selected_packet'] = None
# Reset model if dataset changes
if 'last_loaded_file' not in st.session_state or st.session_state['last_loaded_file'] != current_file:
    st.session_state['model'] = None
    st.session_state['last_loaded_file'] = current_file

# --- TRAIN MODEL SECTION ---
if df is not None:
    st.sidebar.info(f"Loaded: {selected_dataset_name}")
    st.sidebar.text(f"Rows: {len(df)}")
    
    if st.sidebar.button("Train Model Now"):
        with st.spinner("Training Random Forest Model..."):
            
            # Feature Selection
            drop_cols = ['Class', 'No.', 'Time', 'Info', 'Flow ID', 'Source IP', 'Src IP', 'Dst IP', 'Destination IP', 'Timestamp']
            cols_to_drop = [c for c in drop_cols if c in df.columns]
            
            X = df.drop(cols_to_drop, axis=1)
            y = df['Class']
            
            X = pd.get_dummies(X)
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            model = RandomForestClassifier(n_estimators=50, random_state=42)
            model.fit(X_train, y_train)
            
            st.session_state['model'] = model
            st.session_state['accuracy'] = accuracy_score(y_test, model.predict(X_test))
            
            st.sidebar.success(f"Trained! Accuracy: {st.session_state['accuracy']*100:.2f}%")

# --- THREAT ANALYSIS DASHBOARD ---
st.divider()
st.header("Threat Analysis Dashboard")

if st.session_state['model'] is None:
    st.warning(f"⚠️ Please train the model on '{selected_dataset_name}' using the sidebar button.")
else:
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Simulation")
        st.write("Pick a random packet from the dataset to simulate live traffic.")
        
        if st.button("🎲 Capture Random Packet"):
            random_idx = np.random.randint(0, len(df))
            st.session_state['selected_packet'] = df.iloc[random_idx]
        
        if st.session_state['selected_packet'] is not None:
            packet = st.session_state['selected_packet']
            st.write("### Packet Info:")
            
            # Prepare vertical table
            display_df = packet.to_frame()
            display_df.columns = ["Value"]
            
            # --- THE FIX IS HERE ---
            # Removed 'height=500'. It now auto-sizes to fit the data exactly.
            st.dataframe(display_df, use_container_width=True)
            # -----------------------

    with col2:
        st.subheader("AI Detection Result")
        
        if st.session_state['selected_packet'] is not None:
            packet = st.session_state['selected_packet']
            ground_truth = str(packet.get('Class', 'Unknown'))
            
            if ground_truth.upper() in ['NORMAL', 'BENIGN', 'SAFE']:
                st.markdown(f"""<div class="success-box"><h3>STATUS: SAFE</h3></div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""<div class="danger-box"><h3>STATUS: ATTACK DETECTED</h3></div>""", unsafe_allow_html=True)
            
            st.caption(f"Ground Truth Label: {ground_truth}")

            # --- GROQ AI SECTION ---
            st.divider()
            st.subheader("Ask AI Analyst (Groq)")
            
            if st.button("Generate Explanation"):
                if not groq_api_key:
                    st.error("Missing API Key in Sidebar")
                else:
                    client = Groq(api_key=groq_api_key)
                    
                    # Clean packet data
                    packet_dict = packet.to_dict()
                    clean_packet_str = ""
                    for i, (key, value) in enumerate(packet_dict.items()):
                        if i > 15: break 
                        clean_value = str(value).encode('ascii', 'ignore').decode('ascii')
                        clean_packet_str += f"{key}: {clean_value}, "
                    
                    with st.spinner("Analyzing..."):
                        try:
                            chat = client.chat.completions.create(
                                messages=[
                                    {
                                        "role": "system", 
                                        "content": "You are a cybersecurity analyst. Explain if this packet is safe or suspicious based on the provided network features."
                                    },
                                    {
                                        "role": "user", 
                                        "content": f"Packet Data: {clean_packet_str}"
                                    }
                                ],
                                model="llama-3.3-70b-versatile"
                            )
                            st.info(chat.choices[0].message.content)
                        except Exception as e:
                            st.error(f"Error: {e}")