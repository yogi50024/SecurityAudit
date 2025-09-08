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
    """
    Fetch all droplets and basic metadata.
    Returns: list of digitalocean.Droplet objects
    """
    manager = get_manager()
    return manager.get_all_droplets()

def get_firewall_rules():
    """
    Fetch all firewalls and their rules.
    Returns: list of digitalocean.Firewall objects
    """
    manager = get_manager()
    return manager.get_all_firewalls()
