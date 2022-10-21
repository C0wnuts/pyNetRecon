#!/usr/bin/env python3

import os, utils
from utils import *
from tools.logging import Logging
from scapy.all import sniff

class PassiveHarvester:
    def __init__(self, interface, ipFileName, cidrFileNamee, hostname):
        self.interface    = interface
        self.ipFileName   = ipFileName
        self.cidrFileName = cidrFileName
        self.ipList       = []

        if os.path.exists(ipFileName):
            ipFile      = open(ipFileName, 'r')
            self.ipList = [line.rstrip() for line in open(ipFileName, 'r')]


    def packetHandler(self, packet):
        ipSrc          = packet[0][1].src
        ipDst          = packet[0][1].dst
        excludedIpList = utils.excludedIpList()

        if ipSrc not in self.ipList and ipSrc not in excludedIpList:
            self.ipList.append(ipSrc)
            Logging.loggingToFile(f"{ipSrc}\n", self.ipFileName)
            return success(f"{ipSrc}")
        if ipDst not in self.ipList and ipDst not in excludedIpList:
            self.ipList.append(ipDst)
            Logging.loggingToFile(f"{ipDst}\n", self.ipFileName)
            return success(f"{ipDst}")

    def harvest(self):
        interface = self.interface
        sniff(filter="ip", prn=self.packetHandler, iface=interface)