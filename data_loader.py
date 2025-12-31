import pandas as pd
import numpy as np

# --- MAPPING CONFIGURATION ---
MAPPING_OPTIONS = {
    'Packet_Duration': ['Flow Duration', ' Flow Duration', 'duration'],
    'Src_Bytes': ['Total Length of Fwd Packets', ' Total Length of Fwd Packets', 'src_bytes'],
    'Dst_Bytes': ['Total Length of Bwd Packets', ' Total Length of Bwd Packets', 'dst_bytes'],
    'Flag_Reset': ['RST Flag Count', ' RST Flag Count', 'rst_count'],
    'Protocol_Type': ['Protocol', ' Protocol', 'proto'],
    'Class': ['Label', ' Label', 'class']
}

def generate_synthetic_data(n_samples=1000):
    np.random.seed(42)
    data = {
        'Packet_Duration': np.random.exponential(scale=100, size=n_samples),
        'Src_Bytes': np.random.normal(loc=500, scale=200, size=n_samples),
        'Dst_Bytes': np.random.normal(loc=500, scale=200, size=n_samples),
        'Flag_Reset': np.random.choice([0, 1], size=n_samples, p=[0.9, 0.1]),
        'Protocol_Type': np.random.choice([0, 1, 2], size=n_samples) 
    }
    df = pd.DataFrame(data)
    df['Class'] = 0 
    anomalies = (df['Src_Bytes'] > 800) | (df['Packet_Duration'] < 10) | (df['Flag_Reset'] == 1)
    df.loc[anomalies, 'Class'] = 1 
    return df

def find_column(df, possible_names):
    for name in possible_names:
        if name in df.columns:
            return name
    return None

def load_cicids2017(filepath, n_samples=5000): 
    try:
        # Memory Safe Read
        df = pd.read_csv(filepath, nrows=50000)
        df.columns = df.columns.str.strip() 

        # --- 1. DETECT WIRESHARK FORMAT ---
        if 'No.' in df.columns and 'Info' in df.columns and 'Length' in df.columns:
            print("⚠️ Wireshark format detected! Converting to AI format...")
            new_df = pd.DataFrame()
            
            # Extract Features
            new_df['Src_Bytes'] = df['Length']
            new_df['Protocol_Type'] = df['Protocol'].apply(
                lambda x: 0 if 'TCP' in str(x) else (1 if 'UDP' in str(x) else 2)
            )
            new_df['Packet_Duration'] = np.random.exponential(scale=50, size=len(df))
            new_df['Dst_Bytes'] = np.random.normal(loc=200, scale=100, size=len(df))
            new_df['Flag_Reset'] = 0 
            
            # Label the existing data as Benign (0)
            new_df['Class'] = 0
            
            # Inject Synthetic Attacks (30%)
            n_attacks = int(len(new_df) * 0.3)
            attack_data = {
                'Src_Bytes': np.random.normal(loc=5000, scale=1000, size=n_attacks), 
                'Protocol_Type': np.random.choice([0, 1], size=n_attacks),
                'Packet_Duration': np.random.exponential(scale=10, size=n_attacks), 
                'Dst_Bytes': np.random.normal(loc=0, scale=10, size=n_attacks),     
                'Flag_Reset': np.random.choice([0, 1], size=n_attacks, p=[0.5, 0.5]), 
                'Class': 1 
            }
            attacks = pd.DataFrame(attack_data)
            new_df = pd.concat([new_df, attacks], ignore_index=True)
            
            # --- CRITICAL FIX: ENFORCE COLUMN ORDER ---
            # This aligns the data exactly with app.py input vector
            correct_order = ['Packet_Duration', 'Src_Bytes', 'Dst_Bytes', 'Flag_Reset', 'Protocol_Type', 'Class']
            new_df = new_df[correct_order]

            # Sample and Return
            new_df = new_df.replace([np.inf, -np.inf], np.nan).dropna()
            if len(new_df) > n_samples:
                new_df = new_df.sample(n=n_samples, random_state=42)
            
            return new_df

        # --- 2. STANDARD CIC-IDS2017 FORMAT ---
        actual_mapping = {}
        missing_cols = []

        for target_name, candidates in MAPPING_OPTIONS.items():
            clean_candidates = [c.strip() for c in candidates]
            found_col = find_column(df, clean_candidates)
            if found_col:
                actual_mapping[found_col] = target_name
            else:
                missing_cols.append(target_name)

        if missing_cols:
            found_headers = list(df.columns)[:5] 
            return f"❌ FORMAT ERROR: Expected {missing_cols}, but found {found_headers}..."

        df = df.rename(columns=actual_mapping)
        
        # FIX ORDER HERE TOO
        correct_order = ['Packet_Duration', 'Src_Bytes', 'Dst_Bytes', 'Flag_Reset', 'Protocol_Type', 'Class']
        # Only keep columns that exist (in case one is missing in real data)
        available_cols = [c for c in correct_order if c in df.columns]
        df = df[available_cols]

        if df['Class'].dtype == 'object':
             df['Class'] = df['Class'].apply(lambda x: 0 if str(x).upper() == 'BENIGN' else 1)
        
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        if len(df) > n_samples:
            df = df.sample(n=n_samples, random_state=42)
            
        return df

    except FileNotFoundError:
        return None
    except Exception as e:
        return f"An error occurred: {e}"