import pandas as pd
import os

def test_dataset():
    csv_path = 'data/dataset_phishing.csv'
    
    if not os.path.exists(csv_path):
        print(f"❌ Dataset file not found: {csv_path}")
        print("Please make sure:")
        print("1. Your dataset file is named 'dataset_phishing.csv'")
        print("2. It's located in the 'data' folder")
        return
    
    try:
        df = pd.read_csv(csv_path)
        print("✅ Dataset loaded successfully!")
        print(f"Shape: {df.shape} (rows: {df.shape[0]}, columns: {df.shape[1]})")
        print(f"Columns: {df.columns.tolist()}")
        print("\nFirst 3 rows:")
        print(df.head(3))
        print(f"\nLabel column value counts:")
        # Try to find label column
        label_cols = [col for col in df.columns if 'label' in col.lower() or 'status' in col.lower() or 'class' in col.lower()]
        if label_cols:
            print(df[label_cols[0]].value_counts())
        else:
            print("No obvious label column found. Available columns:", df.columns.tolist())
            
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")

if __name__ == "__main__":
    test_dataset()