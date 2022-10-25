#!/usr/bin/env python3

import queue
from tools.scanner import Scanner
from tools.threads.threadPingSweep import ThreadPingSweep
from utils import *

class ActiveHarvester:

    def __init__(self):
        self.ipList = []

    def harvest(self):
        color(f"[i] Begin ARP scan on current CIDR")
        arpIpList  = Scanner.arpScan(settings.Config.currentCidr)
        addCidrToDoneList(settings.Config.currentCidr)
        color(f"[*] IP addresses found by ARP scan on {settings.Config.currentCidr} : {len(arpIpList)}")
        addUniqueTolist(settings.Config.ipList, arpIpList)

    def harvestPingSweep(self):
        if True == settings.Config.pingsweep and 0 != len(settings.Config.activeModList):
            color(f"[i] Begin PingSweep scan on discovered and specified CIDR")
            targets = (list(set(settings.Config.cidrList + settings.Config.activeModList)))
        elif 0 != len(settings.Config.activeModList):
            color(f"[i] Begin PingSweep scan on specified CIDR only")
            targets = settings.Config.activeModList
        else:
            color(f"[i] Begin PingSweep scan on discovered CIDR")
            targets = settings.Config.cidrList
        
        thQueue = queue.Queue()
        for i in range(settings.Config.thread):
            thread = ThreadPingSweep(thQueue, self.ipList)
            thread.start()
        
        # add each cidr to check to the queue for work            
        for target in targets:
            if target not in settings.Config.cidrDoneList:
                thQueue.put(target)
        # wait for all threads to finish
        thQueue.join()

        self.ipList = (list(set(self.ipList)))

        color(f"[*] New IP Addresses found via PingSweep scan : {len(self.ipList)}")
