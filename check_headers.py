import pandas as pd

try:
    # Read just the first row to get headers
    df = pd.read_csv("traffic_data.csv", nrows=1)
    print("\n--- YOUR CSV HEADERS ARE: ---")
    print(list(df.columns))
    print("-----------------------------\n")
except FileNotFoundError:
    print("Error: traffic_data.csv not found.")