import scapy.all as scapy
import socket
import requests
import json
import netifaces
import ipaddress

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
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
    # Placeholder for MAC address lookup logic
    return "Unknown Brand"

def get_device_model(mac_address):
    # Placeholder for MAC address lookup logic
    return "Unknown Model"

def get_access_credentials(ip_address):
    # Placeholder for access credential retrieval logic
    return {"username": "admin", "password": "admin"}

def scan_ports(ip_address):
    open_ports = []
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def main():
    # Descobrir a rota default para obter a interface, IP e rede
    def get_default_network():
        gws = netifaces.gateways()
        default_iface = gws['default'][netifaces.AF_INET][1]
        iface_addrs = netifaces.ifaddresses(default_iface)
        ip_info = iface_addrs[netifaces.AF_INET][0]
        ip_addr = ip_info['addr']
        netmask = ip_info['netmask']
        # Calcular o prefixo CIDR
        network = ipaddress.IPv4Network(f"{ip_addr}/{netmask}", strict=False)
        return str(network)

    ip_range = get_default_network()
    devices = scan_network(ip_range)
    print(json.dumps(devices, indent=4))

if __name__ == "__main__":
    main()