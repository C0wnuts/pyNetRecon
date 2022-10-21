#!/usr/bin/env python3

from tools.scanner import Scanner
from utils import *

class ActiveHarvester:

    def harvest(self):
        color(f"[i] Begin ARP scan on current CIDR")
        hostIpList = []
        arpIpList  = Scanner.arpScan(settings.Config.currentCidr)
        addCidrToDoneList(settings.Config.currentCidr)
        color(f"[*] IP addresses found by ARP scan on {settings.Config.currentCidr} : {len(arpIpList)}")

        # for targets specify in active parameter
        if 0 != len(settings.Config.activeModList):
            color(f"[i] Begin Active scan on {settings.Config.activeModList}")

        for activeTarget in settings.Config.activeModList:
            if activeTarget not in settings.Config.cidrDoneList:
                hostIpList += Scanner.pingSweepScan(activeTarget)
        
        if 0 != len(settings.Config.activeModList):
            color(f"[*] IP addresses found by Active scan : {len(list(set(hostIpList)))}")

        hostIpList += arpIpList
        hostIpList = (list(set(hostIpList)))
        addUniqueTolist(settings.Config.ipList, hostIpList)

    def harvestSingleTarget(self, targets):
        if targets not in settings.Config.cidrDoneList:
            hostList = Scanner.pingSweepScan(targets)
            color(f"[*] IP addresses found by PingSweep scan on {targets} : {len(hostList)}")
            addUniqueTolist(settings.Config.ipList, hostList, settings.Config.verbose, settings.Config.ipListFilename)
