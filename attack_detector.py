import time
from collections import defaultdict

ip_block_count = defaultdict(int)
time_window = 60  # 1 minute
threshold = 5  # block more than 5 packets in 60 seconds

ip_timestamp = defaultdict(list)

def detect_attack(src_ip):
    current_time = time.time()
    ip_timestamp[src_ip].append(current_time)

    # Remove timestamps older than time window
    ip_timestamp[src_ip] = [t for t in ip_timestamp[src_ip] if current_time - t <= time_window]

    if len(ip_timestamp[src_ip]) > threshold:
        return True
    return False
