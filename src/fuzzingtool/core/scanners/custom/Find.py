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

from ..default.DataScanner import DataScanner
from ....conn.responses.Response import Response
from ....interfaces.cli.CliOutput import Colors, fixPayloadToOutput
from ....exceptions.MainExceptions import MissingParameter

import re

class Find(DataScanner):
    __name__ = "Find"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "REGEX"
    __desc__ = "Filter results based on a regex match into the response body"
    __type__ = "DataFuzzing"

    """
    Attributes:
        regexer: The regex object to find the content into the response body
        found: The dictionary to save a flag for each matched result,
               saying if the response body match with the regex or not
    """
    def __init__(self, regex: str):
        if not regex:
            raise MissingParameter("regex")
        super().__init__()
        try:
            self.__regexer = re.compile(regex)
        except re.error:
            raise Exception("Invalid regex format")
        self.__found = {}

    def getResult(self, response: Response):
        return super().getResult(response)

    def scan(self, result: dict):
        found = True if self.__regexer.search(result['Body']) else False
        self.__found[result['Request']] = found
        return found
    
    def cliCallback(self, result: dict):
        found = f"{Colors.LIGHT_YELLOW}{Colors.BOLD}IDK"
        if result['Request'] in self.__found:
            if self.__found[result['Request']]:
                found = f"{Colors.GREEN}{Colors.BOLD}YES"
            else:
                found = f"{Colors.LIGHT_RED}{Colors.BOLD}NO "
                del self.__found[result['Request']]
        payload = '{:<30}'.format(fixPayloadToOutput(result['Payload']))
        length = '{:>8}'.format(result['Length'])
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Regex found{Colors.RESET} {found}{Colors.RESET} | "+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result['Status']} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )