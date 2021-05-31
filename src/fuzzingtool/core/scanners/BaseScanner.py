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

from .Matcher import Matcher
from ..Result import Result

class BaseScanner(Matcher):
    """Base scanner"""
    def __init__(self):
        super().__init__()

    def updateMatcher(self, matcher: Matcher):
        """Update the self matcher attributes based on another Matcher attributes

        @type matcher: Matcher
        @param matcher: The other matcher to copy the attributes
        """
        super().setAllowedStatus(matcher.getAllowedStatus())
        super().setComparator(matcher.getComparator())

    def getResult(self, response: object, requestIndex: int, payload: str, RTT: float, *args):
        """Get the FuzzingTool Result object
        
        @type response: Response
        @param response: The response given in the reuest
        @returns Result: The FuzzingTool Result object
        """
        return Result(response, requestIndex, payload, RTT)

    def scan(self, result: dict):
        """Scan the result

        @type result: dict
        @param result: The result dict
        @reeturns bool: A match flag
        """
        raise NotImplementedError("scan method should be overrided")

    def cliCallback(self, result: dict):
        """Get the formated message to be used on output

        @type result: dict
        @param result: The result dict
        @returns str: The message
        """
        raise NotImplementedError("getMessage method should be overrided")