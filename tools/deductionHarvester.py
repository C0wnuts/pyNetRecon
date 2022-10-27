#!/usr/bin/env python3

import ipaddress, netifaces
from tools.scanner import Scanner
from utils import *
from scapy.all import *

class DeductionHarvester:

    def harvest(self):
        ipHost      = netifaces.ifaddresses(settings.Config.interface)[netifaces.AF_INET][0]['addr']
        mask        = netifaces.ifaddresses(settings.Config.interface)[netifaces.AF_INET][0]['netmask']
        currentCidr = str(ipaddress.IPv4Network(f"{ipHost}/{mask}", False))

        if currentCidr.endswith("32"):
            color(f"[*] Current CIDR in /32. Convert to /24")
            currentCidr = f"{currentCidr[:-2]}24"

        settings.Config.currentCidr = currentCidr
        addUniqueTolist(settings.Config.cidrList, [currentCidr], settings.Config.verbose)
        color(f"[*] Current CIDR : {currentCidr}")