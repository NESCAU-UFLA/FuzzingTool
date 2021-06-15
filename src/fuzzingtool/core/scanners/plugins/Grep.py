# Copyright (c) 2021 Vitor Oriel <https://github.com/VitorOriel>
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

from ..BaseScanner import BaseScanner
from ...Result import Result
from ....interfaces.cli.CliOutput import Colors, getFormatedResult
from ....exceptions.MainExceptions import MissingParameter, BadArgumentFormat

import re

class Grep(BaseScanner):
    __name__ = "Grep"
    __author__ = ("Vitor Oriel")
    __params__ = {
        'metavar': "REGEX",
        'type': list,
        'cli_list_separator': ';',
    }
    __desc__ = "Grep content based on a regex match into the response body"
    __type__ = ""

    """
    Attributes:
        regexer: The regex object to find the content into the response body
        found: The dictionary to save the number of matched regexes in result
    """
    def __init__(self, regexes: list):
        if not regexes:
            raise MissingParameter("regex")
        try:
            self.__regexers = [re.compile(regex) for regex in regexes]
        except re.error:
            raise BadArgumentFormat("invalid regex")
        self.__found = {}

    def inspectResult(self, result: Result, *args):
        result.custom['greped'] = {i: [] for i in range(len(self.__regexers))}

    def scan(self, result: Result):
        totalGreped = 0
        for i, regexer in enumerate(self.__regexers):
            thisGreped = set(regexer.findall(result.getResponse().text))
            totalGreped += len(thisGreped)
            result.custom['greped'][i] = thisGreped
        self.__found[result.index] = totalGreped
        return True if totalGreped else False
    
    def cliCallback(self, result: Result):
        found = f"{Colors.LIGHT_YELLOW}{Colors.BOLD} IDK"
        if result.index in self.__found:
            quantityFound = self.__found[result.index]
            if quantityFound > 0:
                foundColor = f"{Colors.GREEN}{Colors.BOLD}"
            else:
                foundColor = f"{Colors.LIGHT_RED}{Colors.BOLD}"
                del self.__found[result.index]
            quantityFound = '{:>4}'.format(str(quantityFound))
            found = f"{foundColor}{quantityFound}"
        payload, RTT, length = getFormatedResult(
            result.payload, result.RTT, result.length
        )
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Found{Colors.RESET} {found}{Colors.RESET} | "+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result.status} | "+
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {RTT} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )