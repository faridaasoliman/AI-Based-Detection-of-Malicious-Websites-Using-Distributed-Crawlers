"""
simulate_distributed.py
-----------------------
Simulates a distributed crawler network with 3 nodes.
Each node independently crawls a batch of URLs and sends
results to a central classifier - without needing a real VM.
"""
import pickle
import pandas as pd
from features import extract_features

# Load model
with open('url_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Simulate 3 distributed crawler nodes, each with their own batch of URLs
nodes = {
    "Node-1 (Crawler A)": [
        "https://www.wikipedia.org",
        "http://login-verify.paypal-update.xyz",
        "https://stackoverflow.com/questions",
    ],
    "Node-2 (Crawler B)": [
        "http://free-gift-card.win/claim-now",
        "https://www.github.com",
        "http://192.168.0.1/admin/banking",
    ],
    "Node-3 (Crawler C)": [
        "https://www.youtube.com/watch?v=abc123",
        "http://secure-account-alert.info/update",
        "https://docs.python.org/3/",
    ],
}

print("=" * 60)
print("  DISTRIBUTED CRAWLER NETWORK SIMULATION")
print("=" * 60)

all_results = []

for node_name, urls in nodes.items():
    print(f"\n[{node_name}] Processing {len(urls)} URLs...")
    print("-" * 50)
    for url in urls:
        features = pd.DataFrame([extract_features(url)])
        prediction = model.predict(features)[0]
        confidence = model.predict_proba(features)[0][prediction] * 100
        label = "MALICIOUS" if prediction == 1 else "SAFE"
        icon = "[!!!]" if prediction == 1 else "[ OK]"
        print(f"  {icon} {label} ({confidence:.1f}%) -> {url}")
        all_results.append({'node': node_name, 'url': url, 'label': label, 'confidence': confidence})

# Central aggregation summary
print("\n" + "=" * 60)
print("  CENTRAL AGGREGATOR SUMMARY")
print("=" * 60)
results_df = pd.DataFrame(all_results)
total = len(results_df)
malicious = len(results_df[results_df['label'] == 'MALICIOUS'])
safe = total - malicious
print(f"  Total URLs scanned : {total}")
print(f"  Safe               : {safe}")
print(f"  Malicious detected : {malicious}")
print(f"  Threat rate        : {malicious/total*100:.1f}%")
print("=" * 60)
