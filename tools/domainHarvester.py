#!/usr/bin/env python3

import sys
from ldap3 import Connection, Server, NTLM, ALL
from utils import *

class DomainHarvester:
    
    def __init__(self):
        self.cidrList = []

    def processSubnet(self, itemList):
        nameList = []
        for item in itemList:
            try:
                nameList.append(item.name.values[0])
            except Exception as e:
                continue
        
        self.cidrList  = addUniqueTolist(settings.Config.cidrList, nameList, settings.Config.verbose)[1]

    def processUser(self, itemList):
        sAMAccountList = []
        for item in itemList:
            sAMAccountName = ''
            try:
                sAMAccountName = item.sAMAccountName.values[0]
                if sAMAccountName.endswith('$') is False:
                    sAMAccountList.append(sAMAccountName)
            except Exception as e:
                continue
        addUniqueTolist(settings.Config.userList, sAMAccountList, settings.Config.verbose)

    def processComputer(self, itemList):
        distinguishedList = []
        dcList            = []
        for item in itemList:
            try:
                dNSHostName = getattr(item,'dNSHostName')
                if 0 != len(dNSHostName):
                    hostname = dNSHostName.values[0]
                else:
                    hostname = f"{item.cn.values[0]}.{settings.Config.domain}"
                distinguishedList.append(hostname)
                
                # Check if item is a domain controller
                if "Domain Controller" in item.distinguishedName.values[0]:
                    dcList.append(hostname)
            except Exception as e:
                continue
        
        addUniqueTolist(settings.Config.dnsList, distinguishedList, settings.Config.verbose)
        addUniqueTolist(settings.Config.dcList, dcList)
    
    def ProcessTrust(self, itemList):
        distinguishedNameList = []
        for item in itemList:
            try:
                distinguishedNameList.append(item.distinguishedName.values[0].split(',',1)[0].replace('CN=',''))
            except Exception as e:
                continue
            
            addUniqueTolist(settings.Config.trustList, distinguishedNameList, settings.Config.verbose)
    
    def getDCServIp(self, domain, username, password, kdcHost, proto, errMsg):
        kdcList        = []
        loginFailNum   = 0
        credentialFail = False

        if kdcHost is None:
            try:
                answers = settings.Config.dnsResolver.resolve(qname=domain)
                rrset   = [rr.address for rr in answers.rrset]
                for rset in rrset:
                    kdcList.append(rset)
                
                if 0 == len(kdcList):
                    color(f"[!] Domain controller not found on : {domain}\n [!] Try to specify DNS IP via -D mandatory option or directly fill in the domain controller IP address with -i mandatory option")
                    sys.exit(1)
                if True == settings.Config.verbose:
                    color(f"[i] Domain Controllers found : {kdcList}")
                else:
                    color(f"[i] Domain Controllers found : {len(kdcList)}")
            except Exception as e:
                color(f"[!] Domain controller not found on : {domain}\n [!] Try to specify DNS IP via -D mandatory option or directly fill in the domain controller IP address with -i mandatory option")
                sys.exit(1)
        else:
            kdcList.append(kdcHost)

        for kdc in kdcList:
            if True == settings.Config.verbose:
                color(f"[i] Trying to connect to: {kdc}")
            if True == settings.Config.ldaps:
                serv = Server(str(kdc), get_info=ALL, use_ssl = True, connect_timeout=10)
            else:
                serv = Server(str(kdc), get_info=ALL, connect_timeout=10)
            
            ldapConnection = Connection(serv, user=f"{domain}\\{username}", password=f"{password}", authentication=NTLM)
            try:
                if not ldapConnection.bind():
                    color("[!] Fail to connect to domain : bad credentials")
                    credentialFail = True
                    sys.exit(1)
                else:
                    color(f"[i] Connection bound on : {kdc}")
                    return serv, ldapConnection
            except Exception as e:
                color(f"[!] Fail to connect to {kdc} via {proto} : {e}")
                loginFailNum += 1
        
        if True == credentialFail:
            sys.exit(1)
        
        if loginFailNum == len(kdcList):
            color(f"[!] Fail to connect to domain via {proto}. {errMsg}")
            sys.exit(1)


    def harvest(self):
        domain   = settings.Config.domain
        username = settings.Config.username
        password = settings.Config.password
        kdcHost  = settings.Config.kdcHost
        proto    = "ldap"
        errMsg = "Retry with LDAPS protocol (with -s parameter)"
        if True == settings.Config.ldaps:
            proto  = "ldaps"
            errMsg = "Retry with LDAP protocol (without -s parameter)"

        color(f"[i] Begin Domain scan on {domain}")
        if True == settings.Config.verbose:
            color(f"[i] Protocol used: {proto}")

        serv, ldapConnection = self.getDCServIp(domain, username, password, kdcHost, proto, errMsg)
        baseDN               = serv.info.other['defaultNamingContext'][0]
        USER_ATTR            = ['sAMAccountName']
        SITE_ATTR            = ['distinguishedName']
        SUBNETS_ATTR         = ['name']
        COMPUT_ATTR          = ['cn','dNSHostName', 'distinguishedName']

        #Site List : 
        ldapConnection.extend.standard.paged_search('CN=Configuration,%s' % (baseDN), '(objectClass=site)', attributes=SITE_ATTR, paged_size=500, generator=False)
        sitesList = ldapConnection.entries
        color(f"[*] Domain sites found : {len(sitesList)}")

        #Subnet List : 
        subnetsList = []
        for site in sitesList:
            site_dn      = site['distinguishedName']
            ldapConnection.extend.standard.paged_search('CN=Sites,CN=Configuration,%s' % (baseDN), '(siteObject=%s)' % site_dn, attributes=SUBNETS_ATTR, paged_size=500, generator=False)
            subnetsList  += ldapConnection.entries
        if 0 < len(subnetsList):
            self.processSubnet(subnetsList)
            color(f"[*] Domain subnets found : {len(self.cidrList)}")

        #User List
        if True == settings.Config.activeOnly:
            ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=USER_ATTR, paged_size=500, generator=False)
        else:
            ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectCategory=person)(objectClass=user))', attributes=USER_ATTR, paged_size=500, generator=False)
        userList = ldapConnection.entries
        self.processUser(userList)
        color(f"[*] Domain users found : {len(settings.Config.userList)}")

        #Computer List
        ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectClass=computer)(objectClass=user))', attributes=COMPUT_ATTR, paged_size=500, generator=False)
        computerList = ldapConnection.entries
        self.processComputer(computerList)
        color(f"[*] Domain controllers found : {len(settings.Config.dcList)}")
        color(f"[*] Domain computers found : {len(settings.Config.dnsList)}")

        #Trusts List
        ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(objectClass=trustedDomain)', attributes=SITE_ATTR, paged_size=500, generator=False)
        trustList = ldapConnection.entries
        self.ProcessTrust(trustList)
        color(f"[*] Domain trusts found : {len(settings.Config.trustList)}")