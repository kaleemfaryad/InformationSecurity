from scapy.all import IP, TCP, UDP, ICMP
import logging
import ipaddress

def extract_packet_info(packet):
    src_ip = packet.src_addr
    dst_ip = packet.dst_addr
    protocol = ""
    src_port = ""
    dst_port = ""

    if packet.protocol == 6:  # TCP
        protocol = "TCP"
        src_port = packet.src_port
        dst_port = packet.dst_port
    elif packet.protocol == 17:  # UDP
        protocol = "UDP"
        src_port = packet.src_port
        dst_port = packet.dst_port
    elif packet.protocol == 1:  # ICMP
        protocol = "ICMP"

    return src_ip, dst_ip, protocol, src_port, dst_port

def ip_match(rule_ip, packet_ip):
    """Check if IP matches, supporting exact match, CIDR notation, or 'any'"""
    if rule_ip == "any":
        return True
    
    try:
        # Try treating the rule as a CIDR network
        if '/' in rule_ip:
            network = ipaddress.ip_network(rule_ip)
            return ipaddress.ip_address(packet_ip) in network
        else:
            # Exact IP match
            return rule_ip == packet_ip
    except ValueError:
        # If invalid IP format, default to string comparison
        return rule_ip in packet_ip

def port_match(rule_port, packet_port):
    """Check if port matches, supporting exact match, ranges, or 'any'"""
    if rule_port == "any":
        return True
    
    # Convert to strings for comparison
    rule_port = str(rule_port)
    packet_port = str(packet_port)
    
    # Check for port range (e.g., "80-90")
    if "-" in rule_port:
        try:
            low, high = map(int, rule_port.split("-"))
            return low <= int(packet_port) <= high
        except ValueError:
            return False
    
    # Exact port match
    return rule_port == packet_port

def match_packet(packet_info, rules):
    src_ip, dst_ip, protocol, src_port, dst_port = packet_info
    
    # First, fix field name inconsistencies in rules
    for rule in rules:
        # Map dest_ip/dest_port to dst_ip/dst_port if needed
        if "dest_ip" in rule and "dst_ip" not in rule:
            rule["dst_ip"] = rule["dest_ip"]
        if "dest_port" in rule and "dst_port" not in rule:
            rule["dst_port"] = rule["dest_port"]
    
    # Prioritize specific rules over general rules
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

    # Check specific rules first
    for rule in specific_rules:
        # Protocol check
        rule_protocol = rule.get("protocol", "Any")
        if rule_protocol != "Any" and rule_protocol.upper() != protocol:
            continue
            
        # IP checks using the helper function
        if not ip_match(rule.get("src_ip", "any"), src_ip):
            continue
        if not ip_match(rule.get("dst_ip", "any"), dst_ip):
            continue
            
        # Port checks (skip for ICMP)
        if protocol != "ICMP":
            if not port_match(rule.get("src_port", "any"), src_port):
                continue
            if not port_match(rule.get("dst_port", "any"), dst_port):
                continue
                
        # If we got here, all conditions matched
        return rule["action"].lower()

    # Check general rules
    for rule in general_rules:
        rule_protocol = rule.get("protocol", "Any")
        if rule_protocol != "Any" and rule_protocol.upper() != protocol:
            continue
        return rule["action"].lower()

    # Default to allow if no rules match
    return "allow"