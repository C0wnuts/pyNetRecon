#!/usr/bin/env python3

from tools.scanner import Scanner
from utils import *

class ActiveHarvester:

    def __init__(self):
        self.ipList       = []
        self.cidrList     = []

    def harvestARP(self):
        color(f"[i] Begin ARP scan on current CIDR")
        print(settings.Config.infoFontCol)
        arpIpList   = Scanner.arpScan(settings.Config.currentCidr)
        addCidrToDoneList(settings.Config.currentCidr)
        print(settings.Config.defaultFontCol)
        color(f"[*] IP addresses found by ARP scan on {settings.Config.currentCidr} : {len(arpIpList)}")
        self.ipList = addUniqueTolist(self.ipList, arpIpList, settings.Config.verbose)
        addUniqueTolist(settings.Config.ipList, arpIpList)

    def harvestSingleTarget(self, targets):
        if targets == settings.Config.currentCidr and targets not in settings.Config.cidrDoneList:
            self.harvestARP()
        elif targets not in settings.Config.cidrDoneList:
            color(f"[i] Begin PingSweep scan on {targets}")
            hostList = Scanner.pingSweepScan(targets)
            color(f"[*] IP addresses found by PingSweep scan on {targets} : {len(hostList)}")
            addUniqueTolist(settings.Config.ipList, hostList, settings.Config.verbose, f"{settings.Config.outFileName}_{settings.Config.ipListFilename}")
