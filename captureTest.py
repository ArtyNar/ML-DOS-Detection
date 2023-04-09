import pyshark

iface_name = 'Wi-Fi'
filter_string = 'port 443'

capture = pyshark.LiveCapture(
    interface=iface_name,
    bpf_filter=filter_string
)

capture.sniff(timeout=5, packet_count=1)

if len(capture) > 0:
    for packet in capture:
        print('Source:', packet.layers[1].src, 'Destination:', packet.layers[1].dst)