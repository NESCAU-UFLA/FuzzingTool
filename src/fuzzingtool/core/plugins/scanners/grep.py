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

from ..plugin import Plugin
from ...bases.base_scanner import BaseScanner
from ...result import Result
from ....utils.utils import stringfy_list
from ....interfaces.cli.cli_output import Colors, get_formated_result
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
        result.custom['greped'] = {i: [] for i in range(len(self.__regexers))}

    def scan(self, result: Result) -> bool:
        total_greped = 0
        for i, regexer in enumerate(self.__regexers):
            this_greped = set([
                r.group() for r in regexer.finditer(result.get_response().text)
            ])
            total_greped += len(this_greped)
            result.custom['greped'][i] = this_greped
        result.custom['found'] = total_greped
        return True if total_greped else False

    def cli_callback(self, result: Result) -> str:
        found = f"{Colors.LIGHT_YELLOW}{Colors.BOLD} IDK"
        quantity_found = result.custom['found']
        if quantity_found is not None:
            if quantity_found > 0:
                found_color = f"{Colors.GREEN}{Colors.BOLD}"
            else:
                found_color = f"{Colors.LIGHT_RED}{Colors.BOLD}"
            quantity_found = '{:>4}'.format(str(quantity_found))
            found = f"{found_color}{quantity_found}"
        payload, rtt, length = get_formated_result(
            result.payload, result.rtt, result.length
        )
        return (
            f"{payload} {Colors.GRAY}["
            f"{Colors.LIGHT_GRAY}Found{Colors.RESET} {found}{Colors.RESET} | "
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result.status} | "
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {rtt} | "
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )
