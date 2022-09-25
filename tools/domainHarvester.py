#!/usr/bin/env python3

import ldap3
from ldap3 import Connection, Server, NTLM, ALL
from utils import *
import socket, sys


class DomainHarvester:
    
    def __init__(self):
        self.ipList       = []
        self.cidrList     = []

    def processRecord(self, itemList):
        for item in itemList:
            finalValue        = ''
            isDc              = False
            distinguishedName = ''

            try:
                if 'sAMAccountName' in item:
                    finalValue = str(item['sAMAccountName'])
                    if finalValue.endswith('$') is False:
                        # User Account
                        if '' != finalValue:
                            addUniqueTolist(settings.Config.userList, [finalValue], settings.Config.verbose)
                
                if 'dNSHostName' in item:
                    if 0 == len(item['dNSHostName']):
                        hostname = f"{item['cn']}.{settings.Config.domain}"
                    else:
                        hostname = str(item['dNSHostName'])
                    # dns hostname
                    addUniqueTolist(settings.Config.dnsList, [hostname], settings.Config.verbose)
                    # Ip Address
                    finalValue = socket.gethostbyname(str(hostname))
                    if '' != finalValue:
                        addUniqueTolist(settings.Config.ipList, [finalValue], settings.Config.verbose)
                        self.ipList = addUniqueTolist(self.ipList, [finalValue])

                if 'name' in item:
                    # Subnets
                    finalValue = str(item['name'])
                    if '' != finalValue:
                        addUniqueTolist(settings.Config.cidrList, [finalValue], settings.Config.verbose)
                        self.cidrList = addUniqueTolist(self.cidrList, [finalValue])

                if 'distinguishedName' in item:
                    # Check if item is a domain controller
                    distinguishedName = str(item['distinguishedName'])
                    if "Domain Controller" in distinguishedName:
                        isDc = True

                if True == isDc:
                    addUniqueTolist(settings.Config.dcList, [hostname])
            except Exception as e:
                continue


    def searchResEntry_to_dict(self, results):
        data = {}
        for attr in results['attributes']:
            key = str(attr['type'])
            value = str(attr['vals'][0])
            data[key] = value
        return data

    def harvest(self):
        domain   = settings.Config.domain
        username = settings.Config.username
        password = settings.Config.password
        target   = settings.Config.kdcHost
        kdcHost  = settings.Config.kdcHost

        domainParts = domain.split('.')
        baseDN      = ''
        for i in domainParts:
            baseDN += 'dc=%s,' % i
        # Remove last ','
        baseDN      = baseDN[:-1]

        color(f"[i] Begin Domain scan on {domain}")

        if None == kdcHost:
            try:
                kdcHost                 = socket.gethostbyname(domain)
                settings.Config.kdcHost = kdcHost
                target                  = kdcHost
                color(f"[i] Domain Controller found : {target}")
            except:
                color(f"[!] Domain controller not found on : {domain}\n [!] Fill in domain controller IP address with -i mandatory option")
                sys.exit(-1)    

        if kdcHost is not None:
            target = kdcHost
        else:
            target = domain



        if True == settings.Config.ldaps:
            serv = Server(target, get_info=ALL, use_ssl = True)
        else:
            serv = Server(target, get_info=ALL)

        ldapConnection = Connection(serv, user=f"{domain}\\{username}", password=f"{password}", authentication=NTLM)

        try:
            if not ldapConnection.bind():
                color("[!] Fail to connect to domain : bad credentials")
                sys.exit(1)
        except Exception as e:
            color(f"[!] Fail to connect to domain via ldaps : {e}")
            sys.exit(1)
        

        baseDN       = serv.info.other['defaultNamingContext'][0]
        MINIMAL_ATTR = ['sAMAccountName']
        SITE_ATTR    = ['distinguishedName', 'name', 'description']
        SUBNETS_ATTR = ['name']
        COMPUT_ATTR  = ['cn','dNSHostName', 'distinguishedName']

        #Site List : 
        ldapConnection.extend.standard.paged_search('CN=Configuration,%s' % (baseDN), '(objectClass=site)', attributes=SITE_ATTR, paged_size=500, generator=False)
        sitesList = ldapConnection.entries
        color(f"[*] Domain sites found : {len(sitesList)}")

        #Subnet List : 
        subnetsList = []
        for site in sitesList:
            site_dn      = site['distinguishedName']
            site_name    = site['name']
            ldapConnection.extend.standard.paged_search('CN=Sites,CN=Configuration,%s' % (baseDN), '(siteObject=%s)' % site_dn, attributes=SUBNETS_ATTR, paged_size=500, generator=False)
            subnetsList  += ldapConnection.entries
        if 0 < len(subnetsList):
            self.processRecord(subnetsList)
            color(f"[*] Domain subnets found : {len(self.cidrList)}")

        #User List
        if True == settings.Config.activeOnly:
            ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=MINIMAL_ATTR, paged_size=500, generator=False)
        else:
            ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectCategory=person)(objectClass=user))', attributes=MINIMAL_ATTR, paged_size=500, generator=False)
        userList = ldapConnection.entries
        self.processRecord(userList)
        color(f"[*] Domain users found : {len(settings.Config.userList)}")

        #Computer List
        ldapConnection.extend.standard.paged_search('%s' % (baseDN), '(&(objectClass=computer)(objectClass=user))', attributes=COMPUT_ATTR, paged_size=500, generator=False)
        computerList = ldapConnection.entries
        self.processRecord(computerList)
        
        color(f"[*] Domain controllers found : {len(settings.Config.dcList)}")
        color(f"[*] Domain computers found : {len(settings.Config.dnsList)}")
        color(f"[*] Domain IP Addresses found (via dns resolution) : {len(self.ipList)}")