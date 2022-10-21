import threading
import dns.resolver

class ThreadDnsResolve(threading.Thread):
    
    def __init__(self, thQueue, ipList):
        threading.Thread.__init__(self, daemon=True)
        self.thQueue = thQueue
        self.ipList  = ipList

    def run(self):
        while True:
            fqdn     = self.thQueue.get()
            resolver = dns.resolver.Resolver()
            try:
                answers = resolver.resolve(qname=fqdn)
                rrset   = [rr.address for rr in answers.rrset]
                for rset in rrset:
                    self.ipList.append(rset)
            except:
                pass
            
            # indicate that the lookup is complete
            self.thQueue.task_done()