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
from ....utils.http_utils import getPath
from ....conn.requests.Request import Request
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.RequestExceptions import RequestException
from ....exceptions.MainExceptions import MissingParameter

from typing import List

@plugin_meta
class Robots(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "TARGET_URL",
        'type': str,
    }
    __desc__ = "Build the wordlist using the target robots.txt"
    __type__ = "PathFuzzing"
    __version__ = "0.1"

    def __init__(self, url: str):
        if not url:
            raise MissingParameter("target url")
        if not url.endswith('/'):
            url += '/'
        self.url = url
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        requester = Request(
            url=f"{self.url}robots.txt",
            method='GET',
            headers={
                'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
                'Referer': "https://google.com/",
            },
        )
        try:
            response, *_ = requester.request()
        except RequestException as e:
            raise Exception(str(e))
        paths = []
        for line in response.text.split('\n'):
            if (line and not line.startswith('#') and (
                "allow" in line.lower() or
                "disallow" in line.lower() or
                "sitemap" in line.lower()
            )):
                _, path = line.split(': ', 1)
                if '://' in path:
                    path = getPath(path)
                paths.append(path[1:])
        return paths