import scapy.all as scapy
import socket
import requests
import json
import netifaces
import ipaddress
import argparse
import sys

VERBOSE = False

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def scan_network(ip_range):
    vprint(f"[+] Iniciando varredura ARP em {ip_range}")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        vprint(f"[+] Dispositivo encontrado: IP={element[1].psrc}, MAC={element[1].hwsrc}")
        device_info = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "brand": get_device_brand(element[1].hwsrc),
            "model": get_device_model(element[1].hwsrc),
            "credentials": get_access_credentials(element[1].psrc),
            "ports": scan_ports(element[1].psrc)
        }
        devices.append(device_info)
    
    return devices

def get_device_brand(mac_address):
    """Consulta a marca do dispositivo pelo MAC usando macvendors.co"""
    vprint(f"    [.] Buscando fabricante para MAC {mac_address}")
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=3)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Brand"
    except Exception as e:
        vprint(f"        [!] Erro ao consultar fabricante: {e}")
        return "Unknown Brand"

def get_device_model(mac_address):
    # Placeholder for MAC address lookup logic
    vprint(f"    [.] Buscando modelo para MAC {mac_address}")
    return "Unknown Model"

def get_access_credentials(ip_address):
    # Placeholder for access credential retrieval logic
    vprint(f"    [.] Tentando obter credenciais de acesso para {ip_address}")
    return {"username": "admin", "password": "admin"}

def scan_ports(ip_address):
    # Lista das portas mais comuns (top 20)
    common_ports = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        139,  # NetBIOS
        143,  # IMAP
        443,  # HTTPS
        445,  # Microsoft-DS
        3389, # RDP
        3306, # MySQL
        8080, # HTTP-alt
        5900, # VNC
        1723, # PPTP
        53,   # DNS
        554,  # RTSP
        179,  # BGP
        5357  # WSDAPI
    ]
    open_ports = []
    vprint(f"    [.] Escaneando portas comuns em {ip_address}")
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            vprint(f"        [+] Porta aberta: {port}")
            open_ports.append(port)
        sock.close()
    return open_ports

def get_default_network():
    gws = netifaces.gateways()
    default_iface = gws['default'][netifaces.AF_INET][1]
    iface_addrs = netifaces.ifaddresses(default_iface)
    ip_info = iface_addrs[netifaces.AF_INET][0]
    ip_addr = ip_info['addr']
    netmask = ip_info['netmask']
    # Calcular o prefixo CIDR
    network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
    vprint(f"[+] Interface padrão: {default_iface}, IP: {ip_addr}, Netmask: {netmask}, Rede: {network}")
    return str(network)

def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso (debug)")
    args = parser.parse_args()
    VERBOSE = args.verbose

    ip_range = get_default_network()
    devices = scan_network(ip_range)
    print(json.dumps(devices, indent=4))

if __name__ == "__main__":
    main()