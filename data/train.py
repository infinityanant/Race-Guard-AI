import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

df = pd.read_csv('data/traffic.csv')
features = ['concurrentCount', 'timeSinceLastRequest', 'requestsPerMinute']

# Train ONLY on normal data — model learns what "safe" looks like
normal_data = df[df['label'] == 0][features]

model = IsolationForest(contamination=0.05, random_state=42)
model.fit(normal_data)

joblib.dump(model, 'data/model.pkl')
print("Model trained and saved -> data/model.pkl")