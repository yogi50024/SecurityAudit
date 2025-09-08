"""
SSH-Based Droplet Scanner

Connects via SSH to each droplet to perform deeper scans, such as package updates, local firewalls, and suspicious processes.
"""

import paramiko
import os

def ssh_scan(ip, user='root', key_path=None, commands=None):
    key_path = key_path or os.path.expanduser("~/.ssh/id_rsa")
    if commands is None:
        commands = [
            "uname -a",
            "sudo ufw status",
            "ps aux",
            "dpkg -l | grep -i security",
        ]
    results = {}
    try:
        key = paramiko.RSAKey.from_private_key_file(key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=user, pkey=key)
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            results[cmd] = stdout.read().decode()
        client.close()
    except Exception as e:
        results["error"] = str(e)
    return results
