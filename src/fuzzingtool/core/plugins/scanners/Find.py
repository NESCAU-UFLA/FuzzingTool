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
from ...bases.BaseScanner import BaseScanner
from ...Result import Result
from ....interfaces.cli.CliOutput import Colors, getFormatedResult
from ....decorators.plugin_meta import plugin_meta
from ....decorators.append_args import append_args
from ....exceptions.MainExceptions import MissingParameter, BadArgumentFormat

import re

@plugin_meta
class Find(BaseScanner, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "REGEX",
        'type': str,
    }
    __desc__ = "Filter results based on a regex match into the response body"
    __type__ = ""
    __version__ = "0.1"

    """
    Attributes:
        regexer: The regex object to find the content into the response body
    """
    def __init__(self, regex: str):
        if not regex:
            raise MissingParameter("regex")
        try:
            self.__regexer = re.compile(regex)
        except re.error:
            raise BadArgumentFormat("invalid regex")

    @append_args
    def inspectResult(self, result: Result) -> None:
        result.custom['found'] = None

    def scan(self, result: Result) -> bool:
        found = True if self.__regexer.search(result.getResponse().text) else False
        result.custom['found'] = found
        return found
    
    def cliCallback(self, result: Result) -> str:
        found = f"{Colors.LIGHT_YELLOW}{Colors.BOLD}IDK"
        wasFound = result.custom['found']
        if wasFound != None:
            if wasFound:
                found = f"{Colors.GREEN}{Colors.BOLD}YES"
            else:
                found = f"{Colors.LIGHT_RED}{Colors.BOLD}NO "
        payload, RTT, length = getFormatedResult(
            result.payload, result.RTT, result.length
        )
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Regex found{Colors.RESET} {found}{Colors.RESET} | "+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result.status} | "+
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {RTT} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )