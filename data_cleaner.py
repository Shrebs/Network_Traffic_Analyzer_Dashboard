import pandas as pd
import numpy as np

def handle_missing_values(df):
    """Handle both numerical and categorical missing values"""
    for col in df.columns:
        if df[col].dtype in ['int64', 'float64']:
            df[col] = pd.to_numeric(df[col], errors='coerce')
            df[col] = df[col].fillna(df[col].mean())
        else:
            mode_val = df[col].mode()
            if len(mode_val) > 0:
                df[col] = df[col].fillna(mode_val[0])
    
    return df

def remove_duplicates(df):
    """Remove duplicate rows"""
    df.drop_duplicates(inplace=True)
    return df

def clean_text_columns(df):
    """Clean text columns (generic)"""
    for col in df.select_dtypes(include=['object']).columns:
        if col not in ['protocol', 'no.']:
            df[col] = df[col].astype(str)
            df[col] = df[col].str.strip()
            df[col] = df[col].str.replace(r'[^A-Za-z0-9\s]', '', regex=True)
            df[col] = df[col].str.lower()
    
    # Replace invalid values
    df.replace(['nan', 'unknown', 'n/a'], np.nan, inplace=True)
    
    return df

def fill_missing_with_neighbors(df):
    """Fill missing values using neighboring rows"""
    if 'destination' in df.columns:
        df['destination'] = df['destination'].ffill()  # forward fill
    if 'info' in df.columns:
        df['info'] = df['info'].bfill()                # backward fill
    
    return df

def full_cleaning_pipeline(df):
    """Run all cleaning steps"""
    df = handle_missing_values(df)
    df = remove_duplicates(df)
    df = clean_text_columns(df)
    df = fill_missing_with_neighbors(df)
    
    print("\n✅ Cleaned Dataset Sample:")
    print(df.head(10))
    
    return df
  
