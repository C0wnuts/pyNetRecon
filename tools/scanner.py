#!/usr/bin/env python3

from scapy.all import Ether, ARP, srp
from utils import *
import nmap

class Scanner:

    def arpScan(targets):
        if True == settings.Config.verbose:
            color(f"[i] Perform ARP scan on {targets}")
        request    = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
        ans, unans = srp(request, timeout=2, retry=1, iface=settings.Config.interface, verbose=False)
        result     = []

        for sent, received in ans:
            result.append(received.psrc)

        return result

    def pingSweepScan(targets):
        if True == settings.Config.verbose:
            color(f"[i] Perform PingSweep scan on {targets}")
        finalHostList = []
        nm            = nmap.PortScanner()
        nm.scan(hosts=targets, sudo=True, arguments=f"-n -sn -e {settings.Config.interface} --exclude {settings.Config.strIpExclusion}")
        result = getattr(nm,'_scan_result',None)
        if None != result and None != result.get('nmap').get('scaninfo').get('error'):
            error = result.get('nmap').get('scaninfo').get('error')[0].replace("\n","")
            color(f"[!] {error}")
            return;
        hostList = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        for host, status in hostList:
            if "up" == status:
                finalHostList.append(host)

        return (list(set(finalHostList)))