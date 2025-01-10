import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Load pre-trained RandomForestClassifier model
model = joblib.load('traffic_classifier_model.pkl')

# Define function to extract features from pcap file and classify traffic
def extract_and_classify_traffic(pcap_file):
    packet_data = []
    with open(pcap_file, 'rb') as file:
        file_content = file.read()
        while len(file_content) > 0:
            # Extract IP headers from the pcap file (assuming it contains only IP packets)
            ip_header = file_content[14:34]  # IP header is located from byte 14 to byte 33
            ip_src = '.'.join(map(str, ip_header[12:16]))  # Source IP address
            ip_dst = '.'.join(map(str, ip_header[16:20]))  # Destination IP address
            protocol = ip_header[9]  # Protocol field in the IP header
            total_fwd_packets = len(file_content)  # Total length of the packet (including headers)
            # Classify traffic based on extracted features
            traffic_category = classify_traffic(ip_src, ip_dst, protocol, total_fwd_packets)
            # Append feature data and traffic category
            packet_data.append([ip_src, ip_dst, protocol, total_fwd_packets, traffic_category])
            file_content = file_content[total_fwd_packets:]  # Move to the next packet
    return pd.DataFrame(packet_data, columns=['Source.IP', 'Destination.IP', 'Protocol',
                                              'Total.Fwd.Packets', 'Traffic_Category'])

# Function to classify traffic based on features
def classify_traffic(ip_src, ip_dst, protocol, total_fwd_packets):
    if protocol == 6:  # TCP protocol (you can add more checks for other protocols)
        if total_fwd_packets > 1000:
            return 'WebTraffic'C:/Users/cs123/Downloads/network-traffic-dataset-main/network-traffic-dataset-main/data/reduced/pcaps/pcaps/bottom.pcap
    return 'OtherTraffic'

# File path for pcap file
file_path = "C:/Users/cs123/Downloads/network-traffic-dataset-main/network-traffic-dataset-main/data/reduced/pcaps/pcaps/bottom.pcap"

# Process the pcap file and classify traffic
df_packets = extract_and_classify_traffic(file_path)

if not df_packets.empty:
    # Preprocess IP addresses using label encoding
    ip_encoder = LabelEncoder()
    combined_ips = pd.concat([df_packets['Source.IP'], df_packets['Destination.IP']]).astype(str)
    ip_encoder.fit_transform(combined_ips)
    df_packets['Source.IP'] = ip_encoder.transform(df_packets['Source.IP'])
    df_packets['Destination.IP'] = ip_encoder.transform(df_packets['Destination.IP'])

    # Prepare features (X) for prediction
    X = df_packets[['Source.IP', 'Destination.IP', 'Protocol', 'Total.Fwd.Packets']]

    # Make predictions using the model
    predictions = model.predict(X)

    # Display results
    print("Predicted Traffic Categories:")
    print(predictions)

    # Display a table of captured packets and their features
    print("\nCaptured Packets:")
    print(df_packets)
else:
    print("No packets extracted from the pcap file.")
