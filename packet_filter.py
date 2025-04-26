from scapy.all import IP, TCP, UDP, ICMP
import logging

def extract_packet_info(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = ""
    src_port = ""
    dst_port = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    return src_ip, dst_ip, protocol, src_port, dst_port

def match_packet(packet_info, rules):
    src_ip, dst_ip, protocol, src_port, dst_port = packet_info
    
    # First check for specific rules (non-any)
    for rule in rules:
        # Skip rules with 'any' in critical fields
        if rule.get("src_ip") == "any" and rule.get("dest_ip") == "any" and rule.get("dest_port") == "any":
            continue
            
        if rule.get("protocol") and rule["protocol"].upper() != protocol and rule["protocol"] != "Any":
            continue
        if rule.get("src_ip") and rule["src_ip"] != "any" and rule["src_ip"] not in src_ip:
            continue
        if rule.get("dst_ip") and rule["dst_ip"] != "any" and rule["dst_ip"] not in dst_ip:
            continue
        if rule.get("src_port") and rule["src_port"] != "any" and str(rule["src_port"]) != str(src_port):
            continue
        if rule.get("dst_port") and rule["dst_port"] != "any" and str(rule["dst_port"]) != str(dst_port):
            continue
        return rule["action"].lower()
    
    # Then check for general rules (with 'any')
    for rule in rules:
        if rule.get("protocol") and rule["protocol"].upper() != protocol and rule["protocol"] != "Any":
            continue
        if rule.get("src_ip") and rule["src_ip"] != "any" and rule["src_ip"] not in src_ip:
            continue
        if rule.get("dst_ip") and rule["dst_ip"] != "any" and rule["dst_ip"] not in dst_ip:
            continue
        if rule.get("src_port") and rule["src_port"] != "any" and str(rule["src_port"]) != str(src_port):
            continue
        if rule.get("dst_port") and rule["dst_port"] != "any" and str(rule["dst_port"]) != str(dst_port):
            continue
        return rule["action"].lower()

    # Default to allow if no rules match
    return "allow"
