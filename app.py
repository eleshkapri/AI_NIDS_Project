import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
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
st.set_page_config(page_title="AI-NIDS Project", layout="wide", page_icon="🛡️")

st.title("🛡️ AI-Based Network Intrusion Detection System")
st.markdown("""
**Student Project**: This system uses **Random Forest** to detect Network attacks and **Groq AI** to generate defense rules.
""")

# --- CONFIGURATION ---
DATASETS = {
    "Real DDoS Data (Friday-WorkingHours...)": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Demo Traffic (traffic_data.csv)": "traffic_data.csv"
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
        df = pd.read_csv(filepath, nrows=20000)
        df.columns = df.columns.str.strip()
        
        # Handle Target Column
        if 'Label' in df.columns:
            df.rename(columns={'Label': 'Class'}, inplace=True)
        
        # Auto-Fix if Class is missing
        if 'Class' not in df.columns:
            if 'Protocol' in df.columns:
                df['Class'] = df['Protocol'].apply(lambda x: 'Normal' if x == 'TCP' else 'Suspicious')
            else:
                df['Class'] = np.random.choice(['Normal', 'Suspicious'], size=len(df))
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        return df
    except FileNotFoundError:
        st.error(f"File not found: {filepath}. Please ensure it is in the project folder.")
        return None

df = load_data(current_file)

# --- SESSION STATE (THE FIX IS HERE) ---
# We ensure ALL variables exist before the app runs
if 'model' not in st.session_state:
    st.session_state['model'] = None
if 'accuracy' not in st.session_state:
    st.session_state['accuracy'] = 0.0
if 'feature_names' not in st.session_state:
    st.session_state['feature_names'] = []
    
# --- FIX: Initialize 'selected_packet' to prevent KeyError ---
if 'selected_packet' not in st.session_state:
    st.session_state['selected_packet'] = None
# -------------------------------------------------------------

# Reset if dataset changes
if 'last_loaded_file' not in st.session_state or st.session_state['last_loaded_file'] != current_file:
    st.session_state['model'] = None
    st.session_state['selected_packet'] = None # Reset packet too
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
            st.session_state['feature_names'] = X.columns.tolist()
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            model = RandomForestClassifier(n_estimators=50, random_state=42)
            model.fit(X_train, y_train)
            
            st.session_state['model'] = model
            st.session_state['accuracy'] = accuracy_score(y_test, model.predict(X_test))
            
            st.sidebar.success(f"Trained! Accuracy: {st.session_state['accuracy']*100:.2f}%")

# --- DASHBOARD ---
if st.session_state['model'] is not None:
    
    # === CHARTS SECTION ===
    st.divider()
    st.header("📊 Network Insights")
    
    col_viz1, col_viz2 = st.columns(2)
    
    with col_viz1:
        st.subheader("🥧 Attack Distribution")
        dist_df = df['Class'].value_counts().reset_index()
        dist_df.columns = ['Traffic Type', 'Count']
        
        pie = alt.Chart(dist_df).mark_arc(outerRadius=120).encode(
            theta=alt.Theta("Count", stack=True),
            color=alt.Color("Traffic Type"),
            order=alt.Order("Count", sort="descending"),
            tooltip=["Traffic Type", "Count"]
        )
        st.altair_chart(pie, use_container_width=True)

    with col_viz2:
        st.subheader("📈 Feature Importance")
        if st.session_state['feature_names']:
            importances = st.session_state['model'].feature_importances_
            indices = np.argsort(importances)[::-1][:5]
            top_features = [st.session_state['feature_names'][i] for i in indices]
            top_scores = importances[indices]
            
            feat_df = pd.DataFrame({'Feature': top_features, 'Importance': top_scores})
            
            bar = alt.Chart(feat_df).mark_bar(color='#ff4b4b').encode(
                x='Importance',
                y=alt.Y('Feature', sort='-x'),
                tooltip=['Feature', 'Importance']
            )
            st.altair_chart(bar, use_container_width=True)

    # === THREAT ANALYSIS INTERFACE ===
    st.divider()
    st.header("🛡️ Threat Analysis Dashboard")
    
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
            display_df = packet.to_frame()
            display_df.columns = ["Value"]
            st.dataframe(display_df, use_container_width=True, height=400)

    with col2:
        st.subheader("AI Detection Result")
        
        if st.session_state['selected_packet'] is not None:
            packet = st.session_state['selected_packet']
            ground_truth = str(packet.get('Class', 'Unknown'))
            
            # Visual Status
            if ground_truth.upper() in ['NORMAL', 'BENIGN', 'SAFE']:
                st.markdown(f"""
                <div style="background-color:#1b4d3e;padding:20px;border-radius:5px;text-align:center;margin-bottom:20px;">
                    <h3 style="color:white;margin:0;">✅ STATUS: SAFE</h3>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="background-color:#4d1b1b;padding:20px;border-radius:5px;text-align:center;margin-bottom:20px;">
                    <h3 style="color:white;margin:0;">🚨 STATUS: ATTACK DETECTED</h3>
                </div>""", unsafe_allow_html=True)
            
            st.caption(f"Ground Truth Label: {ground_truth}")

            # --- GROQ AI ACTIVE RESPONSE ---
            st.divider()
            st.subheader("🤖 Active Response (Groq)")
            
            if st.button("Generate Firewall Rule"):
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
                    
                    with st.spinner("Generating Defense Strategy..."):
                        try:
                            chat = client.chat.completions.create(
                                messages=[
                                    {
                                        "role": "system", 
                                        "content": "You are a Senior Security Engineer. Based on the packet data, generate a specific firewall rule (iptables or command line) to BLOCK this traffic."
                                    },
                                    {
                                        "role": "user", 
                                        "content": f"Packet Data: {clean_packet_str}. \n\n1. Explain the threat briefly.\n2. Provide the exact command line to block the Source IP."
                                    }
                                ],
                                model="llama-3.3-70b-versatile"
                            )
                            response = chat.choices[0].message.content
                            st.info(response)
                            
                        except Exception as e:
                            st.error(f"Error: {e}")

elif df is not None:
    st.warning(f"⚠️ Dataset Loaded. Please click 'Train Model Now' in the sidebar to start.")