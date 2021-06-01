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

from ..BaseWordlist import BaseWordlist
from ....conn.RequestParser import getPath
from ....conn.requests.Request import Request
from ....exceptions.RequestExceptions import RequestException
from ....exceptions.MainExceptions import MissingParameter

class Robots(BaseWordlist):
    __name__ = "Robots"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "TARGET_URL"
    __desc__ = "Build the wordlist using the target robots.txt"
    __type__ = "PathFuzzing"

    def __init__(self, url: str):
        if not url:
            raise MissingParameter("target url")
        if not url.endswith('/'):
            url += '/'
        self.url = url
        super().__init__()

    def _build(self):
        requester = Request(
            url=f"{self.url}robots.txt",
            method='GET',
            headers={
                'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
                'Referer': "https://google.com/",
            },
        )
        try:
            response, *_ = requester.request("")
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