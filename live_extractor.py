from scapy.all import sniff, IP
import time
import matplotlib.pyplot as plt
from threading import Timer

# Initialize variables for bitrate calculation
total_bytes = 0
time_intervals = []
bitrates = []

def reset_bytes():
    global total_bytes, time_intervals, bitrates
    elapsed_time = time.time() - start_time
    bitrate = (total_bytes * 8)  # bits per second
    time_intervals.append(elapsed_time)
    bitrates.append(bitrate)
    total_bytes = 0
    Timer(1, reset_bytes).start()

def packet_callback(packet):
    global total_bytes
    if IP in packet:
        packet_size = len(packet)
        total_bytes += packet_size

def main():
    global start_time
    # Adjust the filter to capture only the traffic to/from the device's IP address
    device_ip = "192.168.1.75"
    filter_str = f"host {device_ip}"
    
    print(f"Starting packet capture on {device_ip}...")
    start_time = time.time()
    Timer(1, reset_bytes).start()
    sniff(filter=filter_str, prn=packet_callback, store=0)
    
    # Plot the bitrate over time
    plt.plot(time_intervals, bitrates)
    plt.xlabel('Time (s)')
    plt.ylabel('Bitrate (bps)')
    plt.title('Bitrate Over Time')
    plt.show()

if __name__ == "__main__":
    main()