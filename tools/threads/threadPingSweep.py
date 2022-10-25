import threading
from tools.scanner import Scanner
from utils import *

class ThreadPingSweep(threading.Thread):
    
    def __init__(self, thQueue, ipList):
        threading.Thread.__init__(self, daemon=True)
        self.thQueue = thQueue
        self.ipList  = ipList

    def run(self):
        while True:
            target = self.thQueue.get()
            try:
                hostList = Scanner.pingSweepScan(target)
                if None != hostList:
                    color(f"[*] IP addresses found by PingSweep scan on {target} : {len(hostList)}")
                    ipListResults = addUniqueTolist(settings.Config.ipList, hostList, settings.Config.verbose, settings.Config.ipListFilename)
                    for host in ipListResults[1]:
                        self.ipList.append(host)
            except:
                pass
            
            # indicate that the lookup is complete
            self.thQueue.task_done()