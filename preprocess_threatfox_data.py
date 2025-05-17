import json
import csv

input_file = 'real_time_threats_threatfox.json'
output_file = 'preprocessed_threatfox_data.csv'

try:
    with open(input_file, 'r') as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Data is not a list of entries.")

    processed_data = []
    for entry in data:
        threat_type = entry.get("threat_type", "unknown")
        ioc_type = entry.get("ioc_type", "unknown")
        ioc_value = entry.get("ioc_value", "unknown")
        processed_data.append([threat_type, ioc_type, ioc_value])

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["threat_type", "ioc_type", "ioc_value"])  # ✅ Header corrected
        writer.writerows(processed_data)

    print(f"✅ Preprocessing complete! Saved as {output_file}")

except FileNotFoundError:
    print(f"❌ File not found: {input_file}")
except json.JSONDecodeError:
    print(f"❌ Invalid JSON in file: {input_file}")
except Exception as e:
    print(f"❌ Error during preprocessing: {str(e)}")
