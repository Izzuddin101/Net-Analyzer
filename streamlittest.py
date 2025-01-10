import streamlit as st
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import joblib

model = joblib.load('C:/Users/cs123/Desktop/Uni/inshAllahMachineLearning/traffic_classifier_model.pkl')
data = pd.read_csv("C:/Users/cs123/Downloads/archive/dataset.csv")

st.title("Protocol Classifier Test using local dataset")
st.write("Dataset provided by Kaggle. Model is trained on RandomForestClassifier")

if st.button("Run"):
    

def ip_to_int(ip_series):
    return ip_series.apply(lambda ip: sum(int(ip_part) * 256 ** i for i, ip_part in enumerate(reversed(ip.split('.')))))

def run_testmodel():
    data['Source.IP'] = ip_to_int(data['Source.IP'])
    data['Destination.IP'] = ip_to_int(data['Destination.IP'])
    
    X = data[['Source.IP', 'Destination.IP', 'Protocol', 'Total.Fwd.Packets', 'Total.Backward.Packets', 
        'Total.Length.of.Fwd.Packets', 'Total.Length.of.Bwd.Packets', 'Flow.Bytes.s', 'Flow.Packets.s',
        'Average.Packet.Size', 'Protocol', 'L7Protocol']]
    y = data['ProtocolName']

    #Split the data: 75% training and 25% testing#
    random_state = np.random.randint(1, 10000)  # Randomly choose a seed between 1 and 10000
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.0005, random_state=random_state, shuffle=True)

    # Verifying the split
    print(f'Training set size: {X_train.shape[0]} samples')
    print(f'Testing set size: {X_test.shape[0]} samples')
    print(f'Random state used: {random_state}')
    
    predictions = model.predict(X_test)
    
    # List all protocols found during testing
    protocols_to_exclude = ['HTTP', 'HTTP_PROXY', 'SSL', 'HTTP_CONNECT', 'GOOGLE']
    traffic_counts = pd.Series(predictions).value_counts()
    traffic_counts_without_excluded = traffic_counts.drop(protocols_to_exclude, errors='ignore')
    print("\nProtocols Found during Testing:")
    for protocol, count in traffic_counts.items():
        print(f"{protocol}: {count}")   
        
    
    
