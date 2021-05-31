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
from ..Matcher import Matcher
from ...Result import Result
from ....interfaces.cli.CliOutput import Colors, getFormatedResult

class DataScanner(BaseScanner):
    __name__ = "DataScanner"
    __author__ = ("Vitor Oriel C N Borges")

    def getResult(self, response: object, requestIndex: int, payload: str, RTT: float, *args):
        result = super().getResult(response, requestIndex, payload, RTT)
        result._custom['Payload Length'] = len(result.payload)
        result._custom['Body'] = response.text
        return result

    def scan(self, result: dict):
        return True
    
    def cliCallback(self, result: dict):
        payload, RTT, length = getFormatedResult(
            result.payload, result.RTT, result.length
        )
        words = '{:>6}'.format(result.words)
        lines = '{:>5}'.format(result.lines)
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result.status} | "+
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {RTT} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length} | "+
            f"{Colors.LIGHT_GRAY}Words{Colors.RESET} {words} | "+
            f"{Colors.LIGHT_GRAY}Lines{Colors.RESET} {lines}{Colors.GRAY}]{Colors.RESET}"
        )