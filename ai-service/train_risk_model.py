import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

np.random.seed(42)
n = 5000

df = pd.DataFrame({
    'raceWindowMs': np.random.randint(0, 500, n),
    'sharedVariableCount': np.random.randint(1, 10, n),
    'concurrentEndpoints': np.random.randint(1, 20, n),
    'hasAuthentication': np.random.randint(0, 2, n),
    'isFinancialData': np.random.randint(0, 2, n),
    'asyncDepth': np.random.randint(1, 5, n),
    'isPublicEndpoint': np.random.randint(0, 2, n),
})

def calculate_severity(row):
    score = 0
    if row['raceWindowMs'] > 100: score += 3
    if row['isFinancialData'] == 1: score += 3
    if row['hasAuthentication'] == 0: score += 2
    if row['isPublicEndpoint'] == 1: score += 2
    if row['sharedVariableCount'] > 3: score += 2
    if row['asyncDepth'] > 2: score += 1
    if score >= 8: return 'CRITICAL'
    elif score >= 5: return 'HIGH'
    elif score >= 3: return 'MEDIUM'
    else: return 'LOW'

df['severity'] = df.apply(calculate_severity, axis=1)

features = ['raceWindowMs', 'sharedVariableCount', 'concurrentEndpoints',
            'hasAuthentication', 'isFinancialData', 'asyncDepth', 'isPublicEndpoint']

X = df[features]
y = df['severity']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

print(classification_report(y_test, model.predict(X_test)))

os.makedirs('../data', exist_ok=True)
joblib.dump(model, '../data/risk_model.pkl')
print("✅ Risk model saved → data/risk_model.pkl")
