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

from ..Plugin import Plugin
from ...bases.BaseWordlist import BaseWordlist
from ....conn.requests.Request import Request
from ....exceptions.RequestExceptions import RequestException
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.MainExceptions import MissingParameter

from bs4 import BeautifulSoup as bs
import re
from typing import List

@plugin_meta
class DnsDumpster(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "TARGET_HOST",
        'type': str,
    }
    __desc__ = "Build the wordlist based on the content of the site dnsdumpster.com"
    __type__ = "SubdomainFuzzing"
    __version__ = "0.1"

    def __init__(self, host: str):
        if not host:
            raise MissingParameter("target host")
        self.host = host
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        requester = Request(
            url=f"https://dnsdumpster.com/",
            method='GET',
            headers={
                'Host': "dnsdumpster.com",
                'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
                'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                'Accept-Language': "en-US,en;q=0.5",
                'Accept-Encoding': "gzip, deflate",
                'Connection': "keep-alive",
                'Referer': "https://dnsdumpster.com/",
                'Upgrade-Insecure-Requests': "1",
            },
            isSession=True,
        )
        try:
            response, *_ = requester.request()
        except RequestException as e:
            raise Exception(str(e))
        token = response.cookies['csrftoken']
        requester.setMethod('POST')
        requester.setBody(
            f"csrfmiddlewaretoken={token}&targetip={self.host}&user=free"
        )
        try:
            response, *_ = requester.request()
        except RequestException as e:
            raise Exception(str(e))
        if 'There was an error getting results' in response.text:
            raise Exception(f"No domains was found for '{self.host}'")
        contentList = [element.text for element in bs(response.text, "html.parser").find_all('td', class_='col-md-4')]
        regex = r"([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+"
        for splited in self.host.split('.'):
            regex += r"\."+splited
        regexer = re.compile(regex)
        domainList = sorted(set([element for element in contentList if regexer.match(str(element))]))
        return [domain.split(f'.{self.host}')[0] for domain in domainList]