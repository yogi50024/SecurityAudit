"""
DigitalOcean API Client Module

Handles communication with the DigitalOcean API to fetch information about droplets, firewalls, and other resources.
"""

import os
import digitalocean

def get_manager():
    token = os.getenv('DIGITALOCEAN_TOKEN')
    return digitalocean.Manager(token=token)

def get_droplet_info():
    manager = get_manager()
    return manager.get_all_droplets()

def get_firewall_rules():
    manager = get_manager()
    return manager.get_all_firewalls()
