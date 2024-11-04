from scapy.all import sniff
import socket
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading
import time
from collections import Counter

# Dynamically get the local device IP address
def get_local_ip():
    # Create a dummy socket to get the device's IP address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting to an arbitrary IP doesn't send packets but assigns an IP to the socket
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
packet_times = []
packets_per_second = []
bitrates = []
ip_addresses = []
most_common_ip = None
start_time = time.time()

# Callback function to process each captured packet
def packet_callback(packet):
    global most_common_ip
    try:
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            if (src_ip == my_ip) or (dst_ip == my_ip):
                ip_to_lookup = src_ip if dst_ip == my_ip else dst_ip
                ip_addresses.append(ip_to_lookup)

                # If we have identified the most common IP, filter the packets to that IP
                if most_common_ip and ip_to_lookup == most_common_ip:
                    if packet.haslayer("TCP") and (packet["TCP"].dport == 443 or packet["TCP"].sport == 443):
                        packets.append(packet)
                        # print(packet)
                        # Convert packet size to megabits (Mb)
                        packet_size_mb = (len(packet) * 8) / 1_000_000
                        packet_sizes.append(packet_size_mb)

                        # Calculate interval between packets
                        current_time = time.time()
                        interval = current_time - (packet_times[-1] if packet_times else start_time)
                        packet_intervals.append(interval)
                        packet_times.append(current_time)

                        # Track packets per second
                        elapsed_seconds = int(current_time - start_time)
                        if len(packets_per_second) <= elapsed_seconds:
                            packets_per_second.append(1)
                        else:
                            packets_per_second[elapsed_seconds] += 1

                        # Track bitrate
                        total_bits = sum([size * 1_000_000 for size in packet_sizes])  # total bits
                        elapsed_time = current_time - start_time
                        bitrate_mbps = total_bits / elapsed_time / 1_000_000 if elapsed_time > 0 else 0
                        bitrates.append(bitrate_mbps)

    except IndexError:
        pass  # Ignore packets without a TCP layer

# Function to determine the most frequent IP address every 10 seconds and filter packets to that IP
def identify_most_frequent_ip():
    global most_common_ip
    while True:
        time.sleep(10)  # Wait for 10 seconds to analyze the IPs
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

# Plotting setup
fig, axs = plt.subplots(4, 1, figsize=(10, 12))
fig.suptitle("Real-Time Packet Statistics")

def update_plot(frame):
    # Synchronize lengths of time-based lists
    min_length = min(len(packet_times), len(packet_sizes), len(packet_intervals), len(bitrates), len(packets_per_second))

    # Clear and update each subplot with synchronized data
    axs[0].clear()
    axs[0].plot(packet_times[:min_length], packet_sizes[:min_length], label="Packet Size")
    axs[0].set_ylabel("Size (Mb)")
    axs[0].set_xlabel("Time (s)")
    axs[0].legend(loc="upper right")
    axs[0].set_title("Packet Size Over Time")

    axs[1].clear()
    axs[1].plot(packet_times[1:min_length], packet_intervals[:min_length-1], label="Interval Between Packets", color="orange")
    axs[1].set_ylabel("Interval (s)")
    axs[1].set_xlabel("Time (s)")
    axs[1].legend(loc="upper right")
    axs[1].set_title("Interval Between Packets Over Time")

    axs[2].clear()
    axs[2].plot(range(min_length), packets_per_second[:min_length], label="Packets per Second", color="green")
    axs[2].set_ylabel("Packets per Second")
    axs[2].set_xlabel("Time (s)")
    axs[2].legend(loc="upper right")
    axs[2].set_title("Packets per Second Over Time")

    axs[3].clear()
    axs[3].plot(packet_times[:min_length], bitrates[:min_length], label="Bitrate", color="red")
    axs[3].set_ylabel("Bitrate (Mbps)")
    axs[3].set_xlabel("Time (s)")
    axs[3].legend(loc="upper right")
    axs[3].set_title("Bitrate Over Time")

    plt.tight_layout(rect=[0, 0, 1, 0.96])

# Animation for live updating
ani = FuncAnimation(fig, update_plot, interval=1000)

# Start sniffing and domain identification in separate threads
sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
identify_ip_thread = threading.Thread(target=identify_most_frequent_ip, daemon=True)
sniff_thread.start()
identify_ip_thread.start()

# Display the plot
plt.show()
