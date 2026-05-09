import pickle
import pandas as pd
from features import extract_features

# Load the saved model
with open('url_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Test URLs
test_urls = [
    "https://www.google.com",
    "http://paypal-secure-login.verify-account.xyz/update",
    "https://github.com/scikit-learn/scikit-learn",
    "http://192.168.1.1/banking/login@secure",
    "https://www.amazon.com/orders/history",
    "http://free-iphone-winner.click/verify-account-now",
]

print("=" * 60)
print("       URL MALICIOUS DETECTOR - RESULTS")
print("=" * 60)

for url in test_urls:
    features = pd.DataFrame([extract_features(url)])
    prediction = model.predict(features)[0]
    confidence = model.predict_proba(features)[0][prediction] * 100
    label = "MALICIOUS" if prediction == 1 else "SAFE"
    icon = "[!!!]" if prediction == 1 else "[ OK]"
    print(f"{icon} {label} ({confidence:.1f}%)")
    print(f"      {url}")
    print()
