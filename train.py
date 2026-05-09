import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
from features import extract_features

# Load dataset
print("Loading dataset...")
df = pd.read_csv('malicious_phish.csv')

# Use a sample of 50,000 rows for speed
df = df.sample(50000, random_state=42)

# Convert labels to binary: benign = 0, everything else = 1
df['label_bin'] = df['type'].apply(lambda x: 0 if x == 'benign' else 1)

print("Extracting features... (this may take a minute)")
feature_list = [extract_features(u) for u in df['url']]
X = pd.DataFrame(feature_list)
y = df['label_bin']

# Split into training and testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
print("Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\n--- Results ---")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Malicious']))

# Save the model
with open('url_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("\nModel saved to url_model.pkl")
