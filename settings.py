#!/usr/bin/env python3

import utils, os, sys, netifaces, socket
from utils import *

__version__ = 'pyNetRecon 1.0'

class Settings:
    def __init__(self):
        self.pyNetReconPath   = os.path.dirname(__file__)
        self.defaultFontCol   = "\x1b[39m"
        self.successFontCol   = "\x1b[32m"
        self.errorFontCol     = "\x1b[31m"
        self.infoFontCol      = "\x1b[36m"
        self.ipListFilename   = "pyNetRecon-ipList.txt"
        self.dcListFilename   = "pyNetRecon-dcList.txt"
        self.dnsListFilename  = "pyNetRecon-computerList.txt"
        self.cidrListFilename = "pyNetRecon-cidrList.txt"
        self.userListFilename = "pyNetRecon-userList.txt"
        self.currentCidr      = ""
        self.strIpExclusion   = ""
        self.ipList           = []
        self.cidrList         = []
        self.cidrDoneList     = []
        self.userList         = []
        self.dcList           = []
        self.dnsList          = []

    def populate(self, options):
        self.interface     = options.Interface
        self.passiveMod    = options.Passive
        self.activeMod     = options.Active
        self.pingsweep     = options.Pingsweep
        self.outFileName   = options.OutputFileName
        self.activeModList = utils.normalizeList(self.activeMod)
        self.errorHandler(options)
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
        self.lmhash        = ""
        self.nthash        = ""
        self.setHashes(options.Hashes)
        self.setPassword()


    def setPassword(self):
        if None == self.password and "" != self.nthash:
            self.password = f"{lmhash}:{nthash}"

    def setHashes(self, hashes):
        if None != hashes:
            self.lmhash, self.nthash = hashes.split(":")
        if "" == self.lmhash and "" != self.nthash:
            self.lmhash = "aad3b435b51404eeaad3b435b51404ee"

    def setIpExclusion(self, ipList):
        selfIp = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        self.exclusion = ["224.0.0.251", "224.0.0.252", "127.0.0.1", selfIp]
        if None != ipList:
            self.exclusion = self.exclusion + utils.normalizeList(ipList)
        for excludedIp in self.exclusion:
            self.strIpExclusion += f"{excludedIp},"
        self.strIpExclusion = self.strIpExclusion.rstrip(",")

    def printExecutionParameters(self):
        self.banner()
        
        utils.color(f"[i] Selected interface   : {self.interface}")
        utils.color(f"[i] Excluded addresses   : {self.exclusion}")
        mods       = "[i] Harvesting modes     : Default"

        if True == self.passiveMod:
            mods = f"{mods}, Passive"
        if None != self.activeMod:
            mods = f"{mods}, Active \n [i] Active Harvesting on : {self.activeModList}"

        utils.color(mods)
        utils.color("#################### Let's recon #####################\n")


    def banner(self):
        print("                                                        ")
        print("    ___       _  __    __  ___                  ,--..o  ")
        print("   / _ \\__ __/ |/ /__ / /_/ _ \\___ _______  ___ \\   /`. ")
        print("  / ___/ // /    / -_) __/ , _/ -_) __/ _ \\/ _ \\ \\./   \\")
        print(" /_/   \\_, /_/|_/\\__/\\__/_/|_|\\__/\\__/\\___/_//_/  `----'")
        print("      /___/                                      ||     ")
        print("                                                        ")
        utils.color("#######################################################")


    def errorHandler(self, options):
        if None != options.Domain and None == options.Username:
            utils.color(f"[!] Username is missing : -u mandatory option is missing")
            sys.exit(0)
        if None == options.Domain and None != options.Username:
            utils.color(f"[!] Domain is missing : -d mandatory option is missing")
            sys.exit(0)

def init():
    global Config
    Config = Settings()