total_packets = 0
blocked_packets = 0

def update_stats(action):
    global total_packets, blocked_packets
    total_packets += 1
    if action == "block":
        blocked_packets += 1

def show_dashboard():
    print(f"Total Packets: {total_packets} | Blocked Packets: {blocked_packets}")
