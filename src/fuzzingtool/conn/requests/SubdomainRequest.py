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

from .Request import Request
from ..RequestParser import requestParser as parser
from ...utils.http_utils import getHost
from ...utils.consts import SUBDOMAIN_FUZZING
from ...exceptions.RequestExceptions import InvalidHostname

import socket
from requests import Response
from typing import Tuple, Dict

class SubdomainRequest(Request):
    """Class that handle with the requests for subdomain fuzzing"""
    def __init__(self, url: str, **kwargs):
        """Class constructor
        
        @type url: str
        @param url: The target URL
        """
        super().__init__(url, **kwargs)

    def resolveHostname(self, hostname: str) -> str:
        """Resolve the ip for the given hostname

        @type hostname: str
        @param hostname: The hostname of the target
        @returns str: The target IP
        """
        try:
            return socket.gethostbyname(hostname)
        except:
            raise InvalidHostname(f"Can't resolve hostname {hostname}")

    def request(self, payload: str) -> Tuple[Response, float, Dict[str, str]]:
        with self._lock:
            parser.setPayload(payload)
            host = getHost(parser.getUrl(self._url))
        ip = self.resolveHostname(host)
        return (*(super().request(payload)), {'ip': ip})
    
    def _setFuzzingType(self) -> int:
        return SUBDOMAIN_FUZZING