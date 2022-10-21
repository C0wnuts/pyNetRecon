#!/usr/bin/env python3

import threading, queue
from tools.threads.threadDnsResolve import ThreadDnsResolve
from utils import *

class DnsHarvester:

    def __init__(self):
        self.ipList = []

    def harvest(self):
        color(f"[i] Begin dns resolution of {len(settings.Config.dnsList)} hostnames")

        thQueue     = queue.Queue()
        for i in range(settings.Config.thread):
            thread = ThreadDnsResolve(thQueue, self.ipList)
            thread.start()

        # add each fqdn to check to the queue for work            
        for fqdn in settings.Config.dnsList:
            thQueue.put(fqdn)
        # wait for all threads to finish
        thQueue.join()

        self.ipList = (list(set(self.ipList)))

        addUniqueTolist(settings.Config.ipList, self.ipList, settings.Config.verbose)
        color(f"[*] IP Addresses found via dns resolution : {len(self.ipList)}")