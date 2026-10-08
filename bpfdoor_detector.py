# bpfdoor_detector.py
import psutil
import socket
import os
import time
import logging
import json
from datetime import datetime

LOG_DIR = "./logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    filename=f"{LOG_DIR}/detection.log",
    level=logging.INFO,
    format='%(message)s'
)

def save_log(event_type, details):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,  
        "details": details
    }
    print(f"[!] {event_type} 탐지됨: {details}")
    logging.info(json.dumps(log_entry))

def check_raw_sockets():
    """
    BPFdoor는 일반 TCP/UDP 포트가 아닌 'PACKET 소켓(Raw Socket)'을 사용합니다.
    /proc/net/packet 파일을 읽어 이를 탐지합니다.
    """
    suspicious_sockets = []
    try:
        with open('/proc/net/packet', 'r') as f:
            lines = f.readlines()[1:] 
            
        for line in lines:
            parts = line.split()
            inode = parts[8] 
            
            pid, name, cmdline = find_pid_by_inode(inode)
            
            if pid:
                suspicious_sockets.append({
                    "pid": pid,
                    "name": name,
                    "cmdline": cmdline,
                    "inode": inode,
                    "reason": "Raw Socket(PACKET) 사용 감지"
                })
    except Exception as e:
        print(f"Error checking raw sockets: {e}")

    return suspicious_sockets

def find_pid_by_inode(target_inode):
    """
    소켓 Inode를 가지고 있는 실제 프로세스(PID)를 찾아냅니다.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            for conn in proc.connections():
                if conn.fd == -1: continue 
                
                proc_fd_path = f"/proc/{proc.info['pid']}/fd"
                if os.path.exists(proc_fd_path):
                    for fd_file in os.listdir(proc_fd_path):
                        try:
                            full_path = os.readlink(f"{proc_fd_path}/{fd_file}")
                            if f"socket:[{target_inode}]" in full_path:
                                return proc.info['pid'], proc.info['name'], " ".join(proc.info['cmdline'])
                        except:
                            continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None, None, None

def check_process_anomaly(pid_list):
    """
    프로세스 이름이 시스템 데몬(udevd, auditd)인데,
    실제 실행 경로가 /tmp, /dev/shm 등이면 탐지합니다.
    """
    anomalies = []
    suspicious_paths = ['/tmp', '/dev/shm', '/var/tmp', '/home/'] 
    
    if not pid_list:
        targets = psutil.process_iter(['pid', 'name', 'exe', 'cmdline'])
    else:
        targets = [psutil.Process(p['pid']) for p in pid_list if psutil.pid_exists(p['pid'])]

    for proc in targets:
        try:
            p_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
            exe_path = p_info['exe'] or ""
            proc_name = p_info['name']
            
            is_suspicious_path = any(path in exe_path for path in suspicious_paths)
            
            is_deleted = "(deleted)" in exe_path
            
            if is_suspicious_path or is_deleted:
                anomalies.append({
                    "pid": p_info['pid'],
                    "name": proc_name,
                    "exe": exe_path,
                    "reason": "시스템 프로세스 위장 의심 (경로 이상 또는 삭제된 바이너리)"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    return anomalies

def check_network_pattern(pid_list):
    """
    BPFdoor가 활성화되면(매직 패킷 수신 후),
    공격자 IP로 'Reverse Shell' 연결을 시도합니다.
    Raw Socket을 가진 프로세스가 외부로 맺은 TCP 연결(ESTABLISHED)이 있는지 확인합니다.
    """
    patterns = []
    
    for item in pid_list:
        pid = item['pid']
        try:
            proc = psutil.Process(pid)
            connections = proc.connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    patterns.append({
                        "pid": pid,
                        "local_port": conn.laddr.port,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "reason": "Raw Socket 보유 프로세스가 외부와 쉘 연결(Reverse Shell) 수립"
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    return patterns

def main():
    print(f"[*] BPFdoor Detection System Started at {datetime.now()}")
    print(f"[*] Logs will be saved to {LOG_DIR}")
    
    while True:
        try:
            raw_socket_procs = check_raw_sockets()
            
            if raw_socket_procs:
                for proc in raw_socket_procs:
                    save_log("RAW_SOCKET_DETECTED", proc)
                
                spoofed_procs = check_process_anomaly(raw_socket_procs)
                for proc in spoofed_procs:
                    save_log("PROCESS_MASQUERADE", proc)
                
                network_activity = check_network_pattern(raw_socket_procs)
                for net in network_activity:
                    save_log("REVERSE_SHELL_DETECTED", net)
            
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\n[*] Stopping Detection System...")
            break
        except Exception as e:
            print(f"[Error] Main Loop: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()