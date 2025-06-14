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
        ip = element[1].psrc
        mac = element[1].hwsrc
        vprint(f"[+] Dispositivo encontrado: IP={ip}, MAC={mac}")
        ports = scan_ports(ip)
        device_info = {
            "ip": ip,
            "mac": mac,
            "brand": get_device_brand(mac),
            "ports": ports,
            "model": get_device_model(ip, ports),
            "credentials": get_access_credentials(ip)
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


def get_device_model(ip_address, open_ports):
    """Tenta identificar o modelo do dispositivo via vários serviços."""
    vprint(f"    [.] Tentando identificar modelo em {ip_address} nas portas {open_ports}")
    # Tenta HTTP
    if 80 in open_ports:
        try:
            url = f"http://{ip_address}"
            response = requests.get(url, timeout=2)
            vprint(f"        [HTTP] Status code: {response.status_code}")
            if response.status_code == 200:
                vprint("        [HTTP] Página recebida.")
                vprint(response.text)
                for line in response.text.splitlines():
                    if "model" in line.lower() or "Model" in line:
                        return line.strip()
                if "<title>" in response.text:
                    start = response.text.find("<title>") + 7
                    end = response.text.find("</title>")
                    return response.text[start:end].strip()
        except Exception as e:
            vprint(f"        [!] Erro HTTP: {e}")

    # # Tenta HTTPS
    # if 443 in open_ports:
    #     try:
    #         url = f"https://{ip_address}"
    #         response = requests.get(url, timeout=2, verify=False)
    #         if response.status_code == 200:
    #             vprint("        [HTTPS] Página recebida.")
    #             for line in response.text.splitlines():
    #                 if "model" in line.lower() or "Model" in line:
    #                     return line.strip()
    #             if "<title>" in response.text:
    #                 start = response.text.find("<title>") + 7
    #                 end = response.text.find("</title>")
    #                 return response.text[start:end].strip()
    #     except Exception as e:
    #         vprint(f"        [!] Erro HTTPS: {e}")

    # # Tenta SSH
    # if 22 in open_ports:
    #     try:
    #         import paramiko
    #         ssh = paramiko.Transport((ip_address, 22))
    #         ssh.connect(username="admin", password="admin")
    #         banner = ssh.remote_version
    #         ssh.close()
    #         if banner:
    #             vprint(f"        [SSH] Banner: {banner}")
    #             return banner
    #     except Exception as e:
    #         vprint(f"        [!] Erro SSH: {e}")

    # Tenta Telnet
    if 23 in open_ports:
        try:
            import telnetlib
            tn = telnetlib.Telnet(ip_address, 23, timeout=2)
            banner = tn.read_until(b"\n", timeout=2).decode(errors="ignore")
            tn.close()
            if banner.strip():
                vprint(f"        [Telnet] Banner: {banner.strip()}")
                return banner.strip()
        except Exception as e:
            vprint(f"        [!] Erro Telnet: {e}")

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