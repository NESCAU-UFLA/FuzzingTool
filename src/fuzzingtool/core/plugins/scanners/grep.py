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

from ...bases.base_plugin import Plugin
from ...bases.base_scanner import BaseScanner
from ....objects.result import Result
from ....utils.utils import stringfy_list
from ....decorators.plugin_meta import plugin_meta
from ....decorators.append_args import append_args
from ....exceptions.main_exceptions import MissingParameter, BadArgumentFormat


PREPARED_REGEXES = {
    'email': r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)",
    'links': r"(http|https)://([\w-]+(\.[\w-]+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?",
}


@plugin_meta
class Grep(BaseScanner, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "REGEX",
        'type': list,
        'cli_list_separator': ';',
    }
    __desc__ = ("Grep content based on a regex match into the response body. "
                "You can use these prepared regexes: "
                + stringfy_list(list(PREPARED_REGEXES.keys())))
    __type__ = ""
    __version__ = "0.2"

    """
    Attributes:
        regexers: The regexes objects to grep the content into the response body
    """
    def __init__(self, regexes: list):
        if not regexes:
            raise MissingParameter("regex")
        self.__regexers = []
        for regex in regexes:
            if regex.lower() in PREPARED_REGEXES.keys():
                regex = PREPARED_REGEXES[regex.lower()]
            try:
                self.__regexers.append(re.compile(regex))
            except re.error:
                raise BadArgumentFormat(f"invalid regex: {regex}")

    @append_args
    def inspect_result(self, result: Result) -> None:
        result.custom['found'] = None
        for i in range(len(self.__regexers)):
            result.custom[f'greped_regex_{i}'] = []

    def scan(self, result: Result) -> bool:
        total_greped = 0
        for i, regexer in enumerate(self.__regexers):
            this_greped = list(set([
                r.group() for r in regexer.finditer(result.get_response().text)
            ]))
            total_greped += len(this_greped)
            result.custom[f'greped_regex_{i}'] = this_greped
        result.custom['found'] = total_greped
        return True if total_greped else False
