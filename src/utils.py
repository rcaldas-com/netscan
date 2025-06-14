def get_local_ip():
    import socket
    return socket.gethostbyname(socket.gethostname())

def scan_network(network):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    return nm.all_hosts()

def get_device_info(host):
    import requests
    try:
        response = requests.get(f'http://{host}/', timeout=1)
        return {
            'ip': host,
            'brand_model': response.headers.get('Server', 'Unknown'),
            'open_ports': get_open_ports(host)
        }
    except requests.RequestException:
        return {'ip': host, 'brand_model': 'Unknown', 'open_ports': []}

def get_open_ports(host):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-p 1-1024')
    return nm[host]['tcp'].keys() if host in nm.all_hosts() else []

def parse_credentials(device_info):
    # Placeholder for parsing logic
    return {
        'username': 'admin',
        'password': 'admin'
    }