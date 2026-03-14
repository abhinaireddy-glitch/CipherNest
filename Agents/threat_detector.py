import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_threats(data):

    model = IsolationForest(contamination=0.1)

    features = data[['failed_login','packet_size']]

    model.fit(features)

    data['anomaly'] = model.predict(features)

    return data