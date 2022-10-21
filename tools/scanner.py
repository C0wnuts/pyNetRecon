#!/usr/bin/env python3

from scapy.all import Ether, ARP, srp
from utils import *
import nmap

class Scanner:

    def arpScan(ip):
        request    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, unans = srp(request, timeout=2, retry=1, iface=settings.Config.interface)
        result     = []

        for sent, received in ans:
            result.append(received.psrc)

        return result

    def pingSweepScan(targets):
        finalHostList = []
        nm = nmap.PortScanner()
        nm.scan(hosts=targets, arguments=f"-n -sn -e {settings.Config.interface} --exclude {settings.Config.strIpExclusion}")
        hostList = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hostList:
            if "up" == status:
                finalHostList.append(host)

        return finalHostList