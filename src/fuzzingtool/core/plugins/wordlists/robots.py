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

from requests.exceptions import HTTPError

from ...bases.base_plugin import Plugin
from ...bases.base_wordlist import BaseWordlist
from ....utils.http_utils import get_path
from ....conn.requesters.requester import Requester
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.request_exceptions import RequestException
from ....exceptions.main_exceptions import MissingParameter, BuildWordlistFails

ROBOTS_HTTP_HEADER = {
    'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0",
    'Referer': "https://google.com/",
}


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
        global ROBOTS_HTTP_HEADER
        requester = Requester(
            url=f"{self.url}robots.txt",
            method='GET',
            headers=ROBOTS_HTTP_HEADER,
            timeout=5,
        )
        try:
            response, *_ = requester.request()
            response.raise_for_status()
        except (RequestException, HTTPError) as e:
            raise BuildWordlistFails(str(e))
        paths = []
        for line in response.text.split('\n'):
            if (line and not line.startswith('#') and (
                "allow" in line.lower() or
                "disallow" in line.lower() or
                "sitemap" in line.lower()
            )):
                _, path = line.split(': ', 1)
                if '://' in path:
                    path = get_path(path)
                paths.append(path[1:])
        return paths
