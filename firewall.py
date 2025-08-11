import threading  
import subprocess  
from collections import defaultdict  
from datetime import datetime, timedelta  
from scapy.all import sniff, send, TCP, IP, Raw  
import time  
  
# Constants  
BLOCK_DURATION = 10  # Block duration in minutes  
MESSAGE = "Try harder!"  
  
# Scan tracker for detecting potential scans  
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})  
  
def is_ip_blocked(ip):  
    """Check if an IP is currently blocked using iptables."""  
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)  
    return ip in result.stdout  
  
def unblock_ip(ip):  
    """Unblock a previously blocked IP."""  
    try:  
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])  
    except Exception as e:  
        print(f"Error unblocking {ip}: {e}")  
    else:  
        print(f"Unblocked {ip}")  
  
def block_ip(ip):  
    """Block an IP using iptables."""  
    if is_ip_blocked(ip):  
        print(f"{ip} is already blocked.")  
        return  
    try:  
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])  
    except Exception as e:  
        print(f"Error blocking {ip}: {e}")  
    else:  
        print(f"Blocked {ip}")  
  
def unblock_expired_ips():  
    """Unblock IPs whose block duration has expired."""  
    now = datetime.now()  
    for task in list(sniff_thread.unblock_tasks):  
        if now >= task["unblock_time"]:  
            unblock_ip(task["ip"])  
            sniff_thread.unblock_tasks.remove(task)  
  
def handle_packet(packet):  
    """Handle incoming TCP packets."""  
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected  
        src_ip = packet[IP].src  
        src_port = packet[TCP].sport  
        dest_port = packet[TCP].dport  
  
        print(f"SYN packet from {src_ip}:{src_port} to port {dest_port}")  
  
        # Check and reset the scan tracker if the block duration has passed  
        current_time = datetime.now()  
        if scan_tracker[src_ip]["timestamp"] and current_time - scan_tracker[src_ip]["timestamp"] > timedelta(minutes=BLOCK_DURATION):  
            scan_tracker[src_ip] = {"count": 0, "timestamp": None}  
  
        # Update scan tracker  
        scan_tracker[src_ip]["count"] += 1  
        scan_tracker[src_ip]["timestamp"] = current_time  
  
        # Check if the scan threshold is exceeded  
        if scan_tracker[src_ip]["count"] > 5:  
            print(f"Scan detected from {src_ip}")  
            block_ip(src_ip)  
  
            # Schedule unblock task  
            unblock_time = current_time + timedelta(minutes=BLOCK_DURATION)  
            sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})  
            return  
  
        # Send SYN-ACK packet  
        syn_ack = (  
                IP(src=packet[IP].dst, dst=packet[IP].src)  
                / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, seq=100, flags="SA")  
        )  
        send(syn_ack, verbose=0)  
        print(f"Sent SYN-ACK to {src_ip}")  
  
        # Send custom payload  
        payload_packet = (  
                IP(src=packet[IP].dst, dst=packet[IP].src)  
                / TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, seq=101, ack=packet[TCP].seq + 1, flags="PA")  
                / Raw(load=MESSAGE)  
        )  
        send(payload_packet, verbose=0)  
        print(f"Sent payload with message '{MESSAGE}' to {src_ip}")  
  
  
class SniffThread(threading.Thread):  
    """Thread for sniffing packets and managing unblock tasks."""  
    def __init__(self):  
        super().__init__()  
        self.unblock_tasks = []  
  
    def start_sniffing(self):  
        """Start sniffing packets."""  
        sniff(filter="tcp", prn=handle_packet, store=0)  
  
if __name__ == "__main__":  
    sniff_thread = SniffThread()  
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)  
    sniff_thread_thread.start()  
  
    try:  
        while True:  
            unblock_expired_ips()  
            time.sleep(5)  
    except KeyboardInterrupt:  
        print("Exiting...")
