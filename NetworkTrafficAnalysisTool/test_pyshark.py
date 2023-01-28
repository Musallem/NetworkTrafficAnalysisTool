import pyshark

capture = pyshark.LiveCapture(interface='WiFi')
capture.sniff(timeout=10)
for packet in capture.sniff_continuously(packet_count=5):
    print('Just arrived:', packet)

