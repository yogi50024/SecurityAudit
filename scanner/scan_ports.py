"""
Open Ports Scanner

Checks for open and potentially vulnerable ports on a droplet or host.
"""

import socket

def scan_ports(ip, ports=None):
    if ports is None:
        ports = [22, 80, 443, 3306, 5432, 8080]
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=1):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports
