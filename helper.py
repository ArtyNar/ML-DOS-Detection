# Imports
from scapy.all import *
import ipaddress

'''
The following function is used for:
1. Opening .pcapng files and converting them to a single .csv file
2. Labeling each file's data (a common practice in supervised learning)
3. Ensuring that there are no null values
'''
def processFile(pcap_file, label, path, type):
    packets = rdpcap(pcap_file)
    with open(path, type) as f:
        previous_time = None
        for packet in packets:
            # Restricting only to packets with IP (exludes ARP, but does not have to!)
            if packet.haslayer('IP'):
                # TCP-related fields
                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    flags = packet['TCP'].flags.value
                    window_size = packet['TCP'].window
                    seq_number = packet['TCP'].seq
                    ack_number = packet['TCP'].ack
                else:
                    src_port, dst_port, flags, window_size, seq_number, ack_number = 0,0,0,0,0,0
                    
                # Ip-related fields
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                proto = packet['IP'].proto
                len = packet['IP'].len
                ttl = packet['IP'].ttl

                # Getting the time delta
                if previous_time is None:
                    time_delta = 0.0
                else:
                    time_delta = packet.time - previous_time
                previous_time = packet.time
                
                # Writing all to the file
                f.write(f"{src_ip},{dst_ip},{src_port},{dst_port},{proto},{len},{flags},{ttl},{window_size},{seq_number},{ack_number},{time_delta},{label}\n")

# Converts dotted IP to numeric
def ip_to_numeric(address):
    try:
        return int(ipaddress.ip_address(address))
    except:
        return address