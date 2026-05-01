import pandas as pd
import numpy as np

np.random.seed(42)
n_normal = 1000
n_attack = 200

# Normal traffic: low concurrency, decent time gaps
normal = pd.DataFrame({
    'concurrentCount': np.random.randint(0, 3, n_normal),
    'timeSinceLastRequest': np.random.uniform(500, 5000, n_normal),
    'requestsPerMinute': np.random.uniform(1, 10, n_normal),
})

# Attack traffic: high concurrency, tiny time gaps
attack = pd.DataFrame({
    'concurrentCount': np.random.randint(5, 20, n_attack),
    'timeSinceLastRequest': np.random.uniform(0, 50, n_attack),
    'requestsPerMinute': np.random.uniform(50, 200, n_attack),
})

normal['label'] = 0   # normal
attack['label'] = 1   # attack

df = pd.concat([normal, attack]).sample(frac=1).reset_index(drop=True)
df.to_csv('data/traffic.csv', index=False)
print("Data generated -> data/traffic.csv")