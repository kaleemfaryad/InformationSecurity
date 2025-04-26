from scapy.all import sniff, IP
from packet_filter import extract_packet_info, match_packet
from rules_manager import load_rules
from logger import setup_loggers, log_allowed, log_blocked, log_attack
from attack_detector import detect_attack
import cli_dashboard as dashboard

setup_loggers()
rules = load_rules()

firewall_running = True

def process_packet(packet):
    if not firewall_running:
        return False

    if IP not in packet:
        return

    packet_info = extract_packet_info(packet)
    action = match_packet(packet_info, rules)

    src_ip = packet_info[0]

    dashboard.update_stats(action)

    if action == "block":
        log_blocked(packet_info)
        if detect_attack(src_ip):
            log_attack(f"Possible attack detected from {src_ip}")
    else:
        log_allowed(packet_info)

def start_sniffing():
    global firewall_running
    firewall_running = True
    sniff(filter="ip", prn=process_packet, store=0)

def stop_sniffing():
    global firewall_running
    firewall_running = False
