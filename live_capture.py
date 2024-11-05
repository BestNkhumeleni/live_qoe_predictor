from scapy.all import sniff
import socket
import threading
import time
from collections import Counter
import pickle
import pandas as pd
import csv

# Function to load a trained model from a .pkl file
def load_model(pkl_file):
    with open(pkl_file, 'rb') as file:
        model = pickle.load(file)
    return model

# Function to load the label encoder from a .pkl file
def load_label_encoder(pkl_file):
    with open(pkl_file, 'rb') as file:
        label_encoder = pickle.load(file)
    return label_encoder

# Function to predict from a CSV input
def predict_from_csv(input_csv):
    # Load the pre-trained models
    resolution_model = load_model('/home/best/Desktop/live_qoe_predictor/resolution_model.pkl')  # Replace with actual file path
    fps_model = load_model('/home/best/Desktop/live_qoe_predictor/fps_model.pkl')  # Replace with actual file path

    # Load the label encoder for resolution
    resolution_label_encoder = load_label_encoder('/home/best/Desktop/live_qoe_predictor/label_encoder_resolution.pkl')  # Replace with actual file path

    # Load and preprocess the new input data for prediction
    input_data = pd.read_csv(input_csv)

    # Extract relevant features for prediction
    input_features = input_data[['bitrate', 'num_bytes', 'num_packets', 'interval', 'packet_size']].mean(axis=0)

    # Load scalers
    fps_scaler = load_model("/home/best/Desktop/live_qoe_predictor/fps_scaler")
    res_scaler = load_model("/home/best/Desktop/live_qoe_predictor/res_scaler")
    
    # Scale the input data
    unseen_features_scaled_fps = fps_scaler.transform([input_features])
    unseen_features_scaled_res = res_scaler.transform([input_features])
    
    # Predict resolution using the pre-trained model
    resolution_prediction_encoded = resolution_model.predict(unseen_features_scaled_res)[0]
    resolution_prediction = resolution_label_encoder.inverse_transform([resolution_prediction_encoded])[0]
    
    print(f"\nPredicted Resolution: {resolution_prediction}")

    # Predict fps using the pre-trained model
    fps_prediction = fps_model.predict(unseen_features_scaled_fps)[0]
    print(f"Predicted FPS: {fps_prediction}")

    # Return the best predictions
    return resolution_prediction, fps_prediction

# Create the CSV file with headers if it does not exist
csv_file = "averages_output.csv"
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['bitrate', 'num_bytes', 'num_packets', 'interval', 'packet_size'])

# Function to get the local IP address of the device
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    finally:
        s.close()
    return ip_address

# Assign the dynamically retrieved IP address to `my_ip`
my_ip = get_local_ip()
print(f"Local IP address: {my_ip}")

# Packet storage and statistics tracking
packets = []
packet_sizes = []
packet_intervals = []
packet_counts = 0
total_size = 0
ip_addresses = []
packet_times = []
start_time = time.time()

# Interval duration in seconds
interval = 30  # You can adjust this value as needed

# Callback function to process each captured packet
def packet_callback(packet):
    global packet_counts, total_size
    try:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            if (src_ip == my_ip) or (dst_ip == my_ip):
                if packet.haslayer("TCP") and (packet["TCP"].dport == 443 or packet["TCP"].sport == 443):
                    packets.append(packet)
                    
                    # Track packet size in bytes
                    packet_size_bytes = len(packet)
                    packet_sizes.append(packet_size_bytes)
                    total_size += packet_size_bytes

                    # Calculate interval between packets
                    current_time = time.time()
                    interval_time = current_time - (packet_times[-1] if packet_times else start_time)
                    packet_intervals.append(interval_time)
                    packet_times.append(current_time)

                    # Increment packet count
                    packet_counts += 1

                    # Collect IP addresses for analysis
                    ip_addresses.append(src_ip if dst_ip == my_ip else dst_ip)

    except IndexError:
        pass  # Ignore packets without a TCP layer

# Function to calculate, print, and save averages for the specified interval
def print_and_save_averages():
    global packet_sizes, packet_intervals, packet_counts, total_size
    while True:
        time.sleep(interval)  # Wait for the interval duration

        # Calculate averages
        if packet_sizes:
            avg_packet_size = sum(packet_sizes) / len(packet_sizes)
        else:
            avg_packet_size = 0

        if packet_intervals:
            avg_packet_interval = (sum(packet_intervals) / len(packet_intervals)) * 1000
        else:
            avg_packet_interval = 0

        avg_packet_count = packet_counts

        # Calculate bitrate using the total size in bytes divided by interval duration
        bitrate_bps = (total_size * 8) / interval

        # Print averages
        print(f"\nAverages for the past {interval} seconds:")
        print(f"Bitrate: {bitrate_bps:.2f} bps")
        print(f"Total Bytes: {total_size} bytes")
        print(f"Number of Packets: {avg_packet_count}")
        print(f"Average Interval Between Packets: {avg_packet_interval:.5f} ms")
        print(f"Average Packet Size: {avg_packet_size:.2f} bytes")

        # Overwrite the averages in the CSV file, keeping the headers
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['bitrate', 'num_bytes', 'num_packets', 'interval', 'packet_size'])
            writer.writerow([bitrate_bps, total_size, avg_packet_count, avg_packet_interval, avg_packet_size])
        
        # predict_from_csv("averages_output.csv")

        # Reset tracking variables for the next interval
        packet_sizes.clear()
        packet_intervals.clear()
        packet_counts = 0
        total_size = 0

# Function to determine the most frequent IP address every interval and perform a reverse DNS lookup
def identify_most_frequent_ip():
    while True:
        time.sleep(interval)  # Wait for the interval duration
        if ip_addresses:
            most_common_ip, _ = Counter(ip_addresses).most_common(1)[0]
            try:
                domain_name = socket.gethostbyaddr(most_common_ip)[0]
                print(f"Most frequent IP: {most_common_ip} belongs to domain: {domain_name}")
            except socket.herror:
                print(f"Could not resolve domain name for IP: {most_common_ip}")
            ip_addresses.clear()  # Clear the list for the next analysis window

# Start packet sniffing in a background thread
def start_sniffing():
    print("Starting packet capture.")
    sniff(prn=packet_callback, store=0)

# Start sniffing, domain identification, and average calculation in separate threads
sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
identify_ip_thread = threading.Thread(target=identify_most_frequent_ip, daemon=True)
print_averages_thread = threading.Thread(target=print_and_save_averages, daemon=True)
sniff_thread.start()
identify_ip_thread.start()
print_averages_thread.start()

# Keep the main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping packet capture.")
