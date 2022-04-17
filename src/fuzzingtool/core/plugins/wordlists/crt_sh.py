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

import re
from typing import List

from ...bases.base_plugin import Plugin
from ...bases.base_wordlist import BaseWordlist
from ....conn.requesters.requester import Requester
from ....exceptions.request_exceptions import RequestException
from ....decorators.plugin_meta import plugin_meta
from ....utils.consts import FuzzType
from ....exceptions import MissingParameter, BuildWordlistFails

CRTSH_HTTP_HEADER = {
    'Host': "crt.sh",
    'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    'Accept-Language': "en-US,en;q=0.5",
    'Accept-Encoding': "gzip, deflate",
    'Connection': "keep-alive",
    'Referer': "https://crt.sh/",
    'Upgrade-Insecure-Requests': "1",
    'TE': "Trailers",
}


@plugin_meta
class CrtSh(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "TARGET_HOST",
        'type': str,
    }
    __desc__ = "Build the wordlist based on the content of the site crt.sh"
    __type__ = FuzzType.SUBDOMAIN_FUZZING
    __version__ = "0.2"

    def __init__(self, host: str):
        if not host:
            raise MissingParameter("target host")
        self.host = host
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        response_json = self.__get_response_json()
        if not response_json:
            raise BuildWordlistFails(f"No certified domains was found for '{self.host}'")
        domain_list = self.__get_domain_list(response_json)
        return [domain.split(f'.{self.host}')[0]
                for domain in domain_list]

    def __get_response_json(self) -> List[dict]:
        """Get the json response from CrtSh API

        @returns List[dict]: The json response
        """
        global CRTSH_HTTP_HEADER
        requester = Requester(
            url=f"https://crt.sh/?q={self.host}&output=json",
            method='GET',
            headers=CRTSH_HTTP_HEADER,
        )
        try:
            response, *_ = requester.request()
        except RequestException as e:
            raise BuildWordlistFails(str(e))
        return response.json()

    def __get_domain_list(self, response_json: List[dict]) -> List[str]:
        """Get the domain list from the CrtSh API json response

        @type response_json: List[dict]
        @param response_json: The CrtSh API json response
        @returns List[str]: The filtered domain list
        """
        content_list = list(set([element['common_name']
                                 for element in response_json]))
        regex = r"([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+"
        for splited in self.host.split('.'):
            regex += r"\." + splited
        regexer = re.compile(regex)
        return [element
                for element in content_list
                if regexer.match(str(element))]
