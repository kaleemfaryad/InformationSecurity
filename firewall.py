from scapy.all import sniff, IP
from packet_filter import extract_packet_info, match_packet
from rules_manager import load_rules
from logger import setup_loggers, log_allowed, log_blocked, log_attack
from attack_detector import detect_attack
import cli_dashboard as dashboard
import logging

setup_loggers()
rules = load_rules()

# Setup debug logger
debug_logger = logging.getLogger('debug')
debug_handler = logging.FileHandler('logs/debug.log')
debug_logger.addHandler(debug_handler)
debug_logger.setLevel(logging.DEBUG)

firewall_running = True

def reload_firewall_rules():
    global rules
    rules = load_rules()
    debug_logger.info("Firewall rules reloaded")

def process_packet(packet):
    if not firewall_running:
        return False

    if IP not in packet:
        return

    packet_info = extract_packet_info(packet)
    action = match_packet(packet_info, rules)

    src_ip = packet_info[0]
    dst_ip = packet_info[1]
    protocol = packet_info[2]
    src_port = packet_info[3]
    dst_port = packet_info[4]

    # Log detailed packet info
    debug_logger.debug(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol}) - Action: {action}")

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
    debug_logger.info("Firewall started sniffing")
    sniff(filter="ip", prn=process_packet, store=0)

def stop_sniffing():
    global firewall_running
    firewall_running = False
    debug_logger.info("Firewall stopped sniffing")
