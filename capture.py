import pyshark
import csv

iface_name = 'Wi-Fi'
filter_string = 'port 443'

capture = pyshark.LiveCapture(
    interface=iface_name,
    #bpf_filter=filter_string
)

capture.sniff(timeout=5, packet_count=20)

if len(capture) > 0:
    with open('packets.csv', 'w', newline='') as csvfile:
        fieldnames = ['source', 'destination', 'source_port', 'destination_port', 'protocol', 'length', 'flags', 'ttl', 'window_size', 'seq_number', 'ack_number']#, 'time_delta']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for packet in capture:
            writer.writerow({'source': packet.layers[1].src, 'destination': packet.layers[1].dst, 'source_port': packet.layers[2].srcport, 'destination_port': packet.layers[2].dstport, 'protocol': packet.layers[1].proto, 'length': packet.layers[1].get_field('len'), 'flags': packet.layers[2].get_field('flags'), 'ttl': packet.layers[1].get_field('ttl'), 'window_size': packet.layers[2].get_field('window_size'), 'seq_number': packet.layers[2].get_field('seq'), 'ack_number': packet.layers[2].get_field('ack')})#, 'time_delta': packet.layers[1].time_delta})
            #print('Source:', packet.layers[1].src, 'Destination:', packet.layers[1].dst, 'Source Port:', packet.layers[1].sport, 'Destination Port:', packet.layers[1].dport, 'Protocol:', packet.layers[1].get_field('protocol'), 'Length:', packet.layers[1].get_field('len'), 'Flags:', packet.layers[1].get_field('flags'), 'TTL:', packet.layers[1].get_field('ttl'), 'Window Size:', packet.layers[1].get_field('window_size'), 'Seq Number:', packet.layers[1].get_field('seq'), 'Ack Number:', packet.layers[1].get_field('ack'), 'Time Delta:', packet.layers[1].time_delta)

