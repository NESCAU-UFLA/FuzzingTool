## FuzzingTool
# 
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from ..BaseDictionary import BaseDictionary
from ....exceptions.MainExceptions import MissingParameter

from dns import resolver, query, zone

class DnsZone(BaseDictionary):
    __name__ = "DnsZone"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "DOMAIN"
    __desc__ = "Build the wordlist based on a DNS zone transfer request"
    __type__ = "SubdomainFuzzing"

    def __init__(self, host: str):
        super().__init__()
        if not host:
            raise MissingParameter("target host")
        self.host = host

    def setWordlist(self):
        nameServers = resolver.query(self.host, 'NS')
        nameServersIps = []
        for ns in nameServers:
            records = resolver.query(str(ns), 'A')
            for record in records:
                nameServersIps.append(str(record))
        if not nameServersIps:
            raise Exception("Couldn't find any name servers")
        transferedSubdomains = []
        for ip in nameServersIps:
            try:
                zones = zone.from_xfr(query.xfr(ip.rstrip('.'), self.host))
                transferedSubdomains.extend([str(subdomain) for subdomain in zones])
            except:
                continue
        if not transferedSubdomains:
            raise Exception(f"Couldn't make the zone transfer for any of the {len(nameServersIps)} name servers")
        if '@' in transferedSubdomains:
            transferedSubdomains.remove('@')
        self._wordlist = set(transferedSubdomains)