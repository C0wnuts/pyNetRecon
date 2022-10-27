#!/usr/bin/env python3

import utils, os, sys, netifaces, socket
from utils import *
from dns import resolver
from datetime import datetime

__version__ = 'pyNetRecon 1.2'

class Settings:
    def __init__(self):
        self.pyNetReconPath   = os.path.dirname(__file__)
        self.now              = datetime.now().strftime("%Y-%d-%m,%H_%M_%S")
        self.defaultFontCol   = "\x1b[39m"
        self.successFontCol   = "\x1b[32m"
        self.errorFontCol     = "\x1b[31m"
        self.infoFontCol      = "\x1b[36m"
        self.outputFolder     = "output"
        self.ipListFilename   = "ipList.txt"
        self.dcListFilename   = "dcList.txt"
        self.dnsListFilename  = "hostList.txt"
        self.cidrListFilename = "cidrList.txt"
        self.userListFilename = "userList.txt"
        self.trusListFilename = "trustList.txt"
        self.currentCidr      = ""
        self.strIpExclusion   = ""
        self.isMacAddrValid   = True
        self.ipList           = []
        self.cidrList         = []
        self.cidrDoneList     = []
        self.userList         = []
        self.dcList           = []
        self.dnsList          = []
        self.trustList        = []

        utils.createFoler(self.outputFolder)

    def populate(self, options):
        self.banner()
        self.errorHandler(options)
        self.interface     = options.Interface
        self.isInterfaceUp()
        self.isInterfaceHaveMac()
        self.activeMod     = options.Active
        self.pingsweep     = options.Pingsweep
        self.thread        = options.Thread
        self.setOutDirName(options.OutputDir)
        self.activeModList = (list(set(utils.normalizeList(self.activeMod))))
        self.setIpExclusion(options.Exclusion)
        self.printExecutionParameters()
        self.hostname      = socket.gethostname()
        self.domain        = options.Domain
        self.kdcHost       = options.KdcHost
        self.username      = options.Username
        self.password      = options.Password
        self.verbose       = options.Verbose
        self.activeOnly    = options.ActiveOnly
        self.ldaps         = options.Ldaps
        self.customDns     = options.DnsServer
        self.setDnsResolver()
        self.lmhash        = ""
        self.nthash        = ""
        self.setHashes(options.Hashes)
        self.setPassword()

    def isInterfaceUp(self):
        try:
            netifaces.ifaddresses(self.interface)
        except Exception as e:
            utils.color(f"[!] Interface {self.interface} does not exists or down : {e}")
            sys.exit(1)

    def isInterfaceHaveMac(self):
        try:
            netifaces.ifaddresses(self.interface)[netifaces.AF_LINK]
        except Exception as e:
            self.isMacAddrValid = False

    def setOutDirName(self, outputDir):
        if "" != outputDir:
            outputDir = f"{outputDir}_"
        self.outputDir = utils.sanityzeFileName(f"{outputDir}{self.now}")

    def setPassword(self):
        if self.password is None and "" != self.nthash:
            self.password = f"{self.lmhash}:{self.nthash}"

    def setHashes(self, hashes):
        if hashes is not None:
            self.lmhash, self.nthash = hashes.split(":")
        if "" == self.lmhash and "" != self.nthash:
            self.lmhash = "aad3b435b51404eeaad3b435b51404ee"

    def setDnsResolver(self):
        self.dnsResolver = resolver.Resolver()
        self.dnsResolver.lifetime = 2
        if self.customDns is not None:
            self.dnsResolver.nameservers = [self.customDns]

    def setIpExclusion(self, ipList):
        selfIp         = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        self.exclusion = ["224.0.0.251", "224.0.0.252", "127.0.0.1", selfIp]
        if ipList is not None:
            self.exclusion = self.exclusion + utils.normalizeList(ipList)
        for excludedIp in self.exclusion:
            self.strIpExclusion += f"{excludedIp},"
        self.strIpExclusion = self.strIpExclusion.rstrip(",")

    def printExecutionParameters(self):
        if False == self.isMacAddrValid:
            utils.color(f"[i] Selected interface   : {self.interface}; No Valid MAC address found, ARP scan will be skipped")
        else:
            utils.color(f"[i] Selected interface   : {self.interface}")
        utils.color(f"[i] Excluded addresses   : {self.exclusion}")
        mods       = "[i] Harvesting modes     : Default"

        if self.activeMod is not None:
            mods = f"{mods}, Active \n [i] Active Harvesting on : {self.activeModList}"

        utils.color(mods)
        utils.color(f"DNS and pingsweep threads : {str(self.thread)}")
        utils.color("##################### Let's recon #####################\n")

    def errorHandler(self, options):
        if options.Domain is not None and options.Username is None:
            utils.color(f"[!] Username is missing : -u mandatory option is missing")
            sys.exit(0)
        if options.Domain is None and options.Username is not None:
            utils.color(f"[!] Domain is missing : -d mandatory option is missing")
            sys.exit(0)
        self.paramConfusionCheck(options)
    
    def paramConfusionCheck(self, options):
        if options.Active is not None and options.Active.startswith("-"):
            utils.color(f"[!] Provide valid value to -A mandatory option. Current value : {options.Active}")
            sys.exit(1)
        if options.KdcHost is not None and options.KdcHost.startswith("-"):
            utils.color(f"[!] Provide valid value to -i mandatory option. Current value : {options.KdcHost}")
            sys.exit(1)
        if options.DnsServer is not None and options.DnsServer.startswith("-"):
            utils.color(f"[!] Provide valid value to -D mandatory option. Current value : {options.DnsServer}")
            sys.exit(1)

    def banner(self):
        utils.color("#######################################################")
        print("                                                        ")
        print("    ___       _  __    __  ___                  ,--..o  ")
        print("   / _ \\__ __/ |/ /__ / /_/ _ \\___ _______  ___ \\   /`. ")
        print("  / ___/ // /    / -_) __/ , _/ -_) __/ _ \\/ _ \\ \\./   \\")
        print(" /_/   \\_, /_/|_/\\__/\\__/_/|_|\\__/\\__/\\___/_//_/  `----'")
        print("      /___/                                      ||     ")
        print("                                                        ")
        utils.color("#######################################################")


def init():
    global Config
    Config = Settings()