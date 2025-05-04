from scapy.all import IP, TCP, UDP, ICMP
import ipaddress

def extract_packet_info(packet):
    src_ip = packet.src_addr
    dst_ip = packet.dst_addr
    protocol = ""
    src_port = ""
    dst_port = ""

    proto = packet.protocol
    if isinstance(proto, tuple):
        proto = proto[0]  

    print("Raw packet protocol:", proto)

    if proto == 6:  
        protocol = "TCP"
        src_port = getattr(packet, "src_port", "")
        dst_port = getattr(packet, "dst_port", "")
    elif proto == 17: 
        protocol = "UDP"
        src_port = getattr(packet, "src_port", "")
        dst_port = getattr(packet, "dst_port", "")
    elif proto == 1:  
        protocol = "ICMP"

    print(f"Extracted: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")
    return src_ip, dst_ip, protocol, src_port, dst_port



def ip_match(rule_ip, packet_ip):
    """Check if IP matches, supporting exact match, CIDR notation, or 'any'"""
    if rule_ip == "any":
        return True
    
    try:
        if '/' in rule_ip:
            network = ipaddress.ip_network(rule_ip)
            return ipaddress.ip_address(packet_ip) in network
        else:
            return rule_ip == packet_ip
    except ValueError:
        return rule_ip in packet_ip

def port_match(rule_port, packet_port):
    if rule_port == "any":
        return True
    
    rule_port = str(rule_port)
    packet_port = str(packet_port)
    
    if "-" in rule_port:
        try:
            low, high = map(int, rule_port.split("-"))
            return low <= int(packet_port) <= high
        except ValueError:
            return False
    
    return rule_port == packet_port

def match_packet(packet_info, rules):
    src_ip, dst_ip, protocol, src_port, dst_port = packet_info
    
    for rule in rules:
        if "dest_ip" in rule and "dst_ip" not in rule:
            rule["dst_ip"] = rule["dest_ip"]
        if "dest_port" in rule and "dst_port" not in rule:
            rule["dst_port"] = rule["dest_port"]
    
    specific_rules = [rule for rule in rules if 
        rule.get("src_ip", "any") != "any" or 
        rule.get("dst_ip", "any") != "any" or 
        rule.get("src_port", "any") != "any" or 
        rule.get("dst_port", "any") != "any"]
    general_rules = [rule for rule in rules if 
        rule.get("src_ip", "any") == "any" and 
        rule.get("dst_ip", "any") == "any" and 
        rule.get("src_port", "any") == "any" and 
        rule.get("dst_port", "any") == "any"]
    for rule in specific_rules:
        rule_protocol = rule.get("protocol", "Any")
        if rule_protocol != "Any" and rule_protocol.upper() != protocol:
            continue
        if not ip_match(rule.get("src_ip", "any"), src_ip):
            continue
        if not ip_match(rule.get("dst_ip", "any"), dst_ip):
            continue
        if protocol != "ICMP":
            if not port_match(rule.get("src_port", "any"), src_port):
                continue
            if not port_match(rule.get("dst_port", "any"), dst_port):
                continue
        return rule["action"].lower()
    for rule in general_rules:
        rule_protocol = rule.get("protocol", "Any")
        if rule_protocol != "Any" and rule_protocol.upper() != protocol:
            continue
        return rule["action"].lower()
    return "allow"