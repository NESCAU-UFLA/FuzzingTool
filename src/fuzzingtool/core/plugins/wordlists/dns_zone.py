# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import List

from dns import resolver, query, zone

from ...bases.base_plugin import Plugin
from ...bases.base_wordlist import BaseWordlist
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.main_exceptions import MissingParameter, BuildWordlistFails


@plugin_meta
class DnsZone(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "TARGET_HOST",
        'type': str,
    }
    __desc__ = "Build the wordlist based on a DNS zone transfer request"
    __type__ = "SubdomainFuzzing"
    __version__ = "0.2"

    def __init__(self, host: str):
        if not host:
            raise MissingParameter("target host")
        self.host = host
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        name_servers = resolver.resolve(self.host, 'NS')
        name_servers_ips = []
        for ns in name_servers:
            records = resolver.resolve(str(ns), 'A')
            for record in records:
                name_servers_ips.append(str(record))
        if not name_servers_ips:
            raise BuildWordlistFails("Couldn't find any name servers")
        transfered_subdomains = []
        for ip in name_servers_ips:
            transfered_subdomains.extend(self.__do_dns_transfer(ip))
        if not transfered_subdomains:
            raise BuildWordlistFails("Couldn't make the zone transfer for any of the "
                                     f"{len(name_servers_ips)} name servers")
        if '@' in transfered_subdomains:
            transfered_subdomains.remove('@')
        return list(set(transfered_subdomains))

    def __do_dns_transfer(self, ip: str) -> List[str]:
        """Do the DNS Zone Transfer, returning the subdomains

        @type ip: str
        @param ip: The IP from the name server
        @returns List[str]: The list with the subdomains
        """
        try:
            zones = zone.from_xfr(query.xfr(ip.rstrip('.'), self.host))
        except query.TransferError:
            return []
        else:
            return [str(subdomain) for subdomain in zones]
