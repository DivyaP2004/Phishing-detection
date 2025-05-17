import os
import json
import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import accuracy_score

# ==========================
# Paths to Test
# ==========================
email_json = "phishing_emails_dummy.json"
url_json = "phishing_websites_openphish.json"
threatfox_json = "real_time_threats_threatfox.json"

email_csv = "preprocessed_phishing_emails.csv"
url_csv = "preprocessed_openphish_urls.csv"
threatfox_csv = "preprocessed_threatfox_data.csv"

model_file = "xgboost_phishing_model.pkl"
test_csv = "PhiUSIIL_Phishing_URL_Dataset.csv"  # Should contain 'URL' and 'label'

# ==========================
# Helper Functions
# ==========================

def test_file_exists(filepath):
    print(f"🔍 Checking file: {filepath}")
    assert os.path.exists(filepath), f"❌ File not found: {filepath}"
    print(f"✅ File exists: {filepath}")

def test_json_loadable(filepath):
    print(f"🔍 Validating JSON format: {filepath}")
    with open(filepath, 'r') as f:
        data = json.load(f)
    assert isinstance(data, list) and len(data) > 0, f"❌ Invalid or empty JSON: {filepath}"
    print(f"✅ JSON is valid and contains {len(data)} entries")

def test_csv_structure(filepath, required_columns):
    print(f"🔍 Checking CSV structure: {filepath}")
    df = pd.read_csv(filepath)
    for col in required_columns:
        assert col in df.columns, f"❌ Missing column '{col}' in {filepath}"
    assert len(df) > 0, f"❌ No rows found in: {filepath}"
    print(f"✅ CSV is valid with {len(df)} rows and columns: {', '.join(df.columns)}")

def test_model_prediction(model_path, test_data):
    print(f"🔍 Loading model from {model_path}")
    model = joblib.load(model_path)
    predictions = model.predict(test_data)
    assert predictions.shape[0] == test_data.shape[0], "❌ Mismatch between input and prediction output"
    print(f"✅ Model successfully made predictions on {len(predictions)} samples")

# ==========================
# Main Testing Function
# ==========================

def run_system_tests():
    print("🚀===== STARTING SYSTEM TESTING =====🚀\n")

    try:
        # -------------------------------
        print("📁 DATA COLLECTION TESTS")
        # -------------------------------
        test_file_exists(email_json)
        test_file_exists(url_json)
        test_file_exists(threatfox_json)
        test_json_loadable(email_json)
        test_json_loadable(url_json)
        test_json_loadable(threatfox_json)
        print("✔ Data collection tests passed.\n")

        # -------------------------------
        print("🧹 DATA PREPROCESSING TESTS")
        # -------------------------------
        test_file_exists(email_csv)
        test_file_exists(url_csv)
        test_file_exists(threatfox_csv)
        test_csv_structure(email_csv, ['sender_domain', 'subject_flags', 'body_flags', 'label'])
        test_csv_structure(url_csv, ['url', 'url_length', 'num_dots', 'has_https', 'label'])
        test_csv_structure(threatfox_csv, ['threat_type', 'ioc_type', 'ioc_value'])
        print("✔ Preprocessing tests passed.\n")

        # -------------------------------
        print("🧠 MODEL VALIDATION TESTS")
        # -------------------------------
        test_file_exists(model_file)
        df = pd.read_csv(test_csv)
        assert 'URL' in df.columns and 'label' in df.columns, "❌ Required columns missing in test dataset"
        df = df.dropna()

        # Feature extraction (basic)
        X_test = df['URL'].apply(lambda x: [
            len(x), x.count('.'), x.count('-'), x.count('@'), x.count('/'), x.count('?'), x.count('=')
        ])
        X_test = np.array(X_test.tolist())

        test_model_prediction(model_file, X_test)
        print("✔ Model validation tests passed.\n")

        print("✅ ALL SYSTEM TESTS PASSED SUCCESSFULLY!")

    except AssertionError as e:
        print("\n❌ SYSTEM TEST FAILED:")
        print(str(e))

    print("\n🛑===== SYSTEM TESTING COMPLETED =====🛑")

# ==========================
# Run the test
# ==========================

if __name__ == "__main__":
    run_system_tests()
