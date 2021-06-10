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

from ..BaseScanner import BaseScanner
from ...Result import Result
from ....interfaces.cli.CliOutput import Colors, getFormatedResult
from ....exceptions.MainExceptions import MissingParameter, BadArgumentFormat

import re

class Grep(BaseScanner):
    __name__ = "Grep"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "REGEX"
    __desc__ = "Grep content based on a regex match into the response body"
    __type__ = ""

    """
    Attributes:
        regexer: The regex object to find the content into the response body
        found: The dictionary to save the number of matched regexes in result
    """
    def __init__(self, regex: str):
        if not regex:
            raise MissingParameter("regex")
        try:
            self.__regexer = re.compile(regex)
        except re.error:
            raise BadArgumentFormat("invalid regex")
        self.__found = {}

    def inspectResult(self, result: Result, *args):
        result._custom['greped'] = []

    def scan(self, result: Result):
        greped = set(self.__regexer.findall(result.getResponse().text))
        self.__found[result.index] = len(greped)
        result._custom['greped'] = greped
        return True if greped else False
    
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