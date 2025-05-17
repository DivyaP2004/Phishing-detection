from flask import Flask, render_template, request
import joblib
import numpy as np
import re

app = Flask(__name__)

# Load the model
model = joblib.load("xgboost_phishing_model.pkl")

# Feature extraction function (same as used in training)
def extract_features(input_data):
    return [
        len(input_data),
        input_data.count('.'),
        input_data.count('-'),
        input_data.count('@'),
        input_data.count('/'),
        input_data.count('?'),
        input_data.count('=')
    ]

# Function to determine if input is URL or Email
def classify_input_type(input_data):
    # Simple regex to detect email
    email_pattern = r"[^@]+@[^@]+\.[^@]+"
    if re.fullmatch(email_pattern, input_data):
        return "Email"
    elif input_data.startswith("http://") or input_data.startswith("https://") or '.' in input_data:
        return "URL"
    else:
        return "Unknown"

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction_result = None
    input_type = None
    user_input = ""

    if request.method == 'POST':
        user_input = request.form.get('url_input')
        if user_input:
            input_type = classify_input_type(user_input)
            if input_type in ["URL", "Email"]:
                features = np.array(extract_features(user_input)).reshape(1, -1)
                prediction = model.predict(features)[0]
                prediction_result = "Phishing" if prediction == 1 else "Legitimate"
            else:
                prediction_result = "Invalid input format"

    return render_template('index.html', prediction=prediction_result, input_type=input_type, user_input=user_input)

if __name__ == "__main__":
    app.run(debug=True)
