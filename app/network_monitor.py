import scapy.all as scapy
import threading
import time

packet_counts = {}
traffic_data = []

def packet_callback(packet):
    timestamp = int(time.time())
    if timestamp not in packet_counts:
        packet_counts[timestamp] = 0
    packet_counts[timestamp] += 1

    try:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            traffic_data.append({"timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip})

        if packet.haslayer(scapy.DNS):
            domain = packet[scapy.DNSQR].qname.decode()
            traffic_data.append({"timestamp": timestamp, "domain": domain})
    except:
        pass

def start_monitoring():
    try:
        scapy.sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error in network monitoring: {e}")

def get_packet_counts():
    return packet_counts

def get_traffic_data():
    return traffic_data

def start_background_monitoring():
    thread = threading.Thread(target=start_monitoring)
    thread.daemon = True
    thread.start()