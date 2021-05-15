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
from ....conn.requests.Request import Request
from ....conn.responses.Response import Response
from ....exceptions.RequestExceptions import RequestException
from ....exceptions.MainExceptions import MissingParameter

from bs4 import BeautifulSoup as bs
import re

class CrtSh(BaseDictionary):
    __name__ = "CrtSh"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "DOMAIN"
    __desc__ = "Build the wordlist based on the content of the site crt.sh"
    __type__ = "SubdomainFuzzing"

    def __init__(self, host: str):
        super().__init__()
        if not host:
            raise MissingParameter("target host")
        self.host = host

    def setWordlist(self):
        requester = Request(
            url=f"https://crt.sh/?q={self.host}",
            method='GET',
            headers={
                'Host': "crt.sh",
                'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
                'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                'Accept-Language': "en-US,en;q=0.5",
                'Accept-Encoding': "gzip, deflate",
                'Connection': "keep-alive",
                'Referer': "https://crt.sh/",
                'Upgrade-Insecure-Requests': "1",
                'TE': "Trailers",
            },
        )
        try:
            response = requester.request("")
        except RequestException as e:
            raise Exception(str(e))
        if 'None found' in response.text:
            raise Exception(f"No certified domains was found for '{self.host}'")
        contentList = [element.string for element in bs(response.text, "lxml")('td')]
        regex = r"([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+"
        for splited in self.host.split('.'):
            regex += r"\."+splited
        regexer = re.compile(regex)
        domainList = sorted(set([element for element in contentList if regexer.match(str(element))]))
        self._wordlist = [domain.split(f'.{self.host}')[0] for domain in domainList]