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
                if hostList is not None:
                    ipListResults = addUniqueTolist(settings.Config.ipList, hostList, settings.Config.verbose, settings.Config.ipListFilename)[1]
                    for host in ipListResults:
                        self.ipList.append(host)
                    color(f"[*] IP addresses found by PingSweep scan on {target} : {len(ipListResults)}")
            except:
                pass

            # indicate that the lookup is complete
            self.thQueue.task_done()