from packet_filter import extract_packet_info, match_packet
from rules_manager import load_rules
from logger import setup_loggers, log_allowed, log_blocked, log_attack
from attack_detector import detect_attack
import cli_dashboard as dashboard
import logging
import pydivert

setup_loggers()
rules = load_rules()

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
    packet_info = extract_packet_info(packet)
    action = match_packet(packet_info, rules)
    src_ip, dst_ip, protocol, src_port, dst_port = packet_info
    debug_logger.debug(f"Raw packet dest IP: {dst_ip}")
    dashboard.update_stats(action)
    if action == "block":
        log_blocked(packet_info)
        if detect_attack(src_ip):
            log_attack(f"Possible attack detected from {src_ip}")
        return False  
    else:
        log_allowed(packet_info)
        return True  

def start_sniffing():
    global firewall_running
    firewall_running = True
    debug_logger.info("Firewall started sniffing")
    with pydivert.WinDivert("outbound and ip") as w:
        for packet in w:
            if not firewall_running:
                break

            if process_packet(packet):
                w.send(packet)  
            else:
                continue       

def stop_sniffing():
    global firewall_running
    firewall_running = False
    debug_logger.info("Firewall stopped sniffing")
