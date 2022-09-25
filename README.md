# pyNetRecon <img src="https://img.shields.io/badge/Python-3.7+-informational"> <a href="https://twitter.com/intent/follow?screen_name=kevin_racca" title="Follow"><img src="https://img.shields.io/twitter/follow/kevin_racca?label=kevin_racca&style=social"></a>
Python tool designed to quickly enumerate information needed to perform pentests on a local network. It retrieves and aggregates information from several sources such as: the LDAP directory, the current CIDR or manually provided.

**This tool is deliberately not based on the impacket library for reasons of discretion during information gathering**
<br />

## Purpose
This tool makes it possible to recover a lot of information about the attacked internal network in one go.
- From the domain: Recovers the list of users, computers, domain controllers, IPs linked to computers, sub-domains
- From the current network: Recovers the current CIDR and performs an ARP scan on it
- From a pingsweep scan: allows to retrieve the list of computers turned on on the CIDRs discovered during the previous phases or provided manually

<br />

## Changelog
Version 1.0:<br/>
- Domain information gathering via LDAP & LDAPS : domain users, domain computers, DC list, IP associated with hostname of computers
- Domain information gathering on Trusted Domain via providing the DC IP of the other domain
- Information related to the current network: current CIDR & arp scan
- Active information gathering from a list of ip, range or CIDR provided in parameters

<br />

## Future improvements
- Information gathering from domain trusts
- Passive mod to discover machines by monitoring the network
- Share gathering
- Provide targets from file to perform active scan

<br />

## Installation

```bash
git clone https://github.com/C0wnuts/pyNetRecon
cd pyNetRecon
pip3 install -r requirements.txt
```

<br />

## Usage

```python

options:
  -h, --help            show usage
  -I, --interface       set the network interface (required) 
  -X, --exclusion       set exclusion IP list

domain harvesting:
  -d, --domain          domain name, format is full domain name, ex: domain.local
  -u, --user            domain user, ex: administrator
  -p, --password        domain user password, ex: P@ssword!
  -H, --hashes          NTLM hashes, format is LMHASH:NTHASH or :NTHASH
  -s, --ldaps           use LDAP over SSL (can be usefull to bypass NIDS and NIPS)
  -a, --active-only     gather only active users on domain
  -i, --dc-ip           set domain controller IP manually (required if pyNetRecon could not find the DC automatically)

mods:
  -A, --active          manually provide IP, IP range or CIDR list, ex: 192.168.1.1/24,10.20.1.4-10,172.16.1.4
  -S, --pingsweep       enable pingsweep scan on CIDR discovered/manually provided

verbosity:
  -v, --verbose             enable verbose mod
```

```bash
 python3 pyNetRecon.py -I eth0 -d domain.local -i 10.1.2.3 -u user -p p@ssw0rd -a -A 192.168.1.1/24,172.16.1.1/16
```
