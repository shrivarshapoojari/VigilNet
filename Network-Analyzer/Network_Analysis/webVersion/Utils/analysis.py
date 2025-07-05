# analyzer.py
from scapy.all import IP, IPv6, TCP, UDP, Ether, Raw, ICMP
import requests

# Cache for IP geolocation
location_cache = {}

def get_location(ip):
    if ip in location_cache:
        return location_cache[ip]
    
    try:
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip == "localhost":
            location = "Private/Local IP"
        else:
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                city = data.get("city", "Unknown")
                country = data.get("country_name", "Unknown")
                lat = data.get("latitude", "N/A")
                lon = data.get("longitude", "N/A")
                location = f"{city}, {country} (Lat: {lat}, Lon: {lon})"
            else:
              location = f"IPAPI Error:Location Not found for {ip}"

    except Exception as e:
        location = f"Location error: {e}"

    location_cache[ip] = location
    return location

def analyze_packet(packet):
    info = {
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "src_mac": None,
        "dst_mac": None,
        "src_location": None,
        "dst_location": None,
        "payload": None
    }

    if Ether in packet:
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # Handle IPv4
    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst
        info["src_location"] = get_location(info["src_ip"])
        info["dst_location"] = get_location(info["dst_ip"])
        if info["protocol"] is None:
            info["protocol"] = packet[IP].proto

    # Handle IPv6
    elif IPv6 in packet:
        info["src_ip"] = packet[IPv6].src
        info["dst_ip"] = packet[IPv6].dst
        info["src_location"] = get_location(info["src_ip"])
        info["dst_location"] = get_location(info["dst_ip"])
        if info["protocol"] is None:
            info["protocol"] =  packet[IPv6].nh  

    if TCP in packet:
        info["src_port"] = packet[TCP].sport
        info["dst_port"] = packet[TCP].dport
        info["protocol"] = "TCP"
    elif UDP in packet:
        info["src_port"] = packet[UDP].sport
        info["dst_port"] = packet[UDP].dport
        info["protocol"] = "UDP"
    elif ICMP in packet:
        info["protocol"] = "ICMP"
        info["src_port"] = f"Type {packet[ICMP].type}"
        info["dst_port"] = f"Code {packet[ICMP].code}"

    if Raw in packet:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='replace')
        except Exception:
            payload = str(packet[Raw].load)

        info["payload"] = payload[:100]  

    return info
