#!/usr/bin/env python3

import settings, ipaddress, os, re, unicodedata
from tools.logging import Logging
from utils import *

def color(text):
    if text.startswith('[*]'):
        print(settings.Config.successFontCol,text,settings.Config.defaultFontCol)
    elif text.startswith('[!]'):
        print(settings.Config.errorFontCol,text,settings.Config.defaultFontCol)
    elif text.startswith('[i]') or text.startswith('#'):
        print(settings.Config.infoFontCol,text,settings.Config.defaultFontCol)

def colorSameLine(text):
    if text.startswith('[*]'):
        print(settings.Config.successFontCol,text,settings.Config.defaultFontCol, end="\r")
    elif text.startswith('[!]'):
        print(settings.Config.errorFontCol,text,settings.Config.defaultFontCol, end="\r")
    elif text.startswith('[i]') or text.startswith('#'):
        print(settings.Config.infoFontCol,text,settings.Config.defaultFontCol, end="\r")

def success(text):
    return settings.Config.successFontCol + text + settings.Config.defaultFontCol

def normalizeList(text):
    if None != text:
        itemList = text.split(",")
        return [item.strip() for item in itemList]
    return []

def addCidrToDoneList(cidr):
    settings.Config.cidrDoneList.append(cidr)

def getCidrFromIp(ip):
    return re.sub(r'\d+$', '0/24', ip)

def checkIpInNetwork(ip):
    ipAddr  = ipaddress.ip_address(ip)
    isFound = False 
    for cidr in settings.Config.cidrList:
        networkCidr = ipaddress.ip_network(cidr)
        if ipAddr in networkCidr:
            isFound = True
    if False == isFound:
        settings.Config.cidrList.append(getCidrFromIp(ip))


def createFoler(directory, isOutput = False):
    directory = sanityzeFileName(directory)
    if True == isOutput:
        directory = f"{settings.Config.outputFolder}/{directory}"
    if not os.path.exists(directory):
        os.makedirs(directory)
        return directory

def sanityzeFileName(filename):
    forbidden_chars  = '"*\\/\'.|?:<>'
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()
    filename = ''.join([x if x not in forbidden_chars else '_' for x in cleaned_filename])
    return filename

def addUniqueTolist(itemList, newItemList, isForcedVerbose = False, filename = None):
    for item in newItemList:
        if item not in itemList and item not in settings.Config.exclusion:
            itemList.append(item)
            if bool(re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", str(item))):
                checkIpInNetwork(item)
            if True == isForcedVerbose:
                color(f"[i] new entry : {item}")
            if None != filename:
                logging = Logging()
                logging.loggingToFile(item.strip(), filename)
        elif True == settings.Config.verbose:
            color("[i] Entry skipped : already known")
    return itemList