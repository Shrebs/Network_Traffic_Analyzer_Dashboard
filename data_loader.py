import pandas as pd
import numpy as np

def load_csv(filepath):
    """Load CSV file"""
    df = pd.read_csv(filepath)
    print(df.head(10))
    return df

def normalize_columns(df):
    """Fix column names"""
    df.columns = df.columns.str.strip().str.lower()
    
    df = df.rename(columns={
        "time": "time",
        "source": "source",
        "destination": "destination",
        "protocol": "protocol",
        "length": "length"
    })
    
    # Convert length to numeric
    df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)
    
    # Remove unnecessary columns
    if "no." in df.columns:
        df = df.drop(columns=["no."])
    
    print("\n✅ After cleaning column names:")
    print(df.head(10))
    print(df.columns)
    
    return df

def save_cleaned_csv(df, output_path="NTA_Dataset_Cleaned.csv"):
    """Save cleaned dataset"""
    df.to_csv(output_path, index=False)
    print(f"\nCleaned file saved as '{output_path}'")
    return output_path
