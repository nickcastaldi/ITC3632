from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth

def packet_handler(packet):
    # Sniff for 802.11 Beacon frames
    if packet.haslayer(Dot11Beacon):
        print("[+] Detected 802.11 Beacon frame")
        print("MAC:", packet[Dot11].addr2)

    # Sniff for 802.11 Deauthentication frames produced by the AP
    elif packet.haslayer(Dot11Deauth):
        print("[+] Detected 802.11 Deauthentication frame from AP")
        print("MAC:", packet[Dot11].addr2)

    # Sniff for any 802.11 frames from which one can find the MAC address of a STA
    elif packet.haslayer(Dot11):
        print("[+] Detected 802.11 frame")
        print("MAC:", packet[Dot11].addr2)

sniff(iface="wlan0", prn=packet_handler)
