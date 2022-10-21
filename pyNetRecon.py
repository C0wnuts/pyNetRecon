#!/usr/bin/env python3
#
# PYNETRECON
#
# V 1.1
#
# Copyright (C) 2022 C0wnuts. All rights reserved.
#
#
# Description:
#   Python tool designed to quickly enumerate information needed to perform pentests on a local network. 
#   It retrieves and aggregates information from several sources such as: the LDAP directory, the current CIDR or manually provided.
#
# Author:
#   C0wnuts (@kevin_racca)

import optparse, threading, sys
from utils import *
from tools.deductionHarvester import DeductionHarvester
from tools.domainHarvester import DomainHarvester
from tools.activeHarvester import ActiveHarvester
from tools.dnsHarvester import DnsHarvester
from tools.logging import Logging

parser = optparse.OptionParser(usage='python3 %prog -I eth0 -d domain.local -u user -p p@ssw0rd -a -A 192.168.1.1/24,172.16.1.1/16 -s -D 192.168.1.20 -o myDom -t 50', version=settings.__version__, prog=sys.argv[0])
parser.add_option('-I','--interface',  action="store",       help="Network interface to use.", dest="Interface", metavar="eth0", default=None)
parser.add_option('-D','--dns-ip',     action="store",       help="Ip address of the dns server to use.", dest="DnsServer", metavar="10.32.1.3", default=None)
parser.add_option('-t','--threads',    action="store",       help="Number of threads for dns resolution (default 30).", dest="Thread", default=30, type=int)
parser.add_option('-X','--exclusion',  action="store",       help="List of IP addresses to be excluded from IP address harvesting.", dest="Exclusion", default=None)
parser.add_option('-o','--outputdir',  action="store",       help="base output directory name.", dest="OutputDir", default="")
parser.add_option('-d','--domain',     action="store",       help="Domain to be targeted to collect information about the IP addresses of workstations and servers.", dest="Domain", metavar="domain.local", default=None)
parser.add_option('-u','--user',       action="store",       help="Username of the domain user to log in to the domain.", dest="Username", default=None)
parser.add_option('-p','--password',   action="store",       help="Password of the domain user to log in to the domain.", dest="Password", default=None)
parser.add_option('-H','--hashes',     action="store",       help="Hashes LM:NTLM of the domain user to log in to the domain.", dest="Hashes", default=None)
parser.add_option('-i','--dc-ip',      action="store",       help="Ip address of the domain controller to collect information.", dest="KdcHost", metavar="10.1.2.3", default=None)
parser.add_option('-s','--ldaps',      action="store_true",  help="Active LDAP over SSL to encrypt communications.", dest="Ldaps", default=False)
parser.add_option('-a','--active-only',action="store_true",  help="Gather active users only on domain.", dest="ActiveOnly", default=False)
parser.add_option('-A','--active',     action="store",       help="Active mode. This option allows you to enable active IP address harvesting by entering CIDRs.", dest="Active", default=None)
parser.add_option('-S','--pingsweep',  action="store_true",  help="Enable pingsweep mode. This option allows you to enable pingsweep scan for IP address harvesting on discovered CIDR.", dest="Pingsweep", default=False)
parser.add_option('-P','--passive',    action="store_true",  help="Enable passive mode. This option allows you to enable passive IP address harvesting. NOT IMPLEMENTED", dest="Passive", default=False)
parser.add_option('-v','--verbose',    action="store_true",  help="Increase verbosity.", dest="Verbose", default=False)
options, args = parser.parse_args()

settings.init()

if not os.geteuid() == 0:
    color("[!] pyNetRecon must be run as root.")
    sys.exit(-1)
elif options.Interface == None:
    color("[!] Interface is missing: -I mandatory option is missing.")
    parser.print_help()
    exit(-1)

settings.Config.populate(options)

def harvest(harvesterCls):
    harvester = harvesterCls()
    harvester.harvest()
    return harvester

def harvestSingleTarget(harvesterCls, target):
    harvester = harvesterCls()
    harvester.harvestSingleTarget(target)
    return harvester

def main():
    try:
        loging = Logging()
        
        harvest(DeductionHarvester)
        if None != settings.Config.domain:
            harvest(DomainHarvester)

        harvest(ActiveHarvester)

        if [] != settings.Config.dnsList:
            harvest(DnsHarvester)

        loging.logArrayToFile(settings.Config.cidrList, settings.Config.cidrListFilename)
        loging.logArrayToFile(settings.Config.userList, settings.Config.userListFilename)
        loging.logArrayToFile(settings.Config.dcList,   settings.Config.dcListFilename)
        loging.logArrayToFile(settings.Config.dnsList,  settings.Config.dnsListFilename)
        loging.logArrayToFile(settings.Config.ipList,   settings.Config.ipListFilename)

        if False != settings.Config.pingsweep:
            threads = []

            for cidr in settings.Config.cidrList:
                threads.append(threading.Thread(target=harvestSingleTarget, args=(ActiveHarvester, cidr)))

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

        color(f"[i] Scan complete. Enjoy !")

    except KeyboardInterrupt:
        sys.exit("Exiting...")

if __name__ == "__main__":
    main()