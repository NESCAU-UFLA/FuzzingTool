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
from ...conn.responses.Response import Response

class BaseScanner(Matcher):
    """Base scanner"""
    def __init__(self):
        super().__init__()

    def getResult(self, response: Response):
        """Get the response data parsed into a dictionary
        
        @type response: Response
        @param response: The response given in the reuest
        @returns dict: The formated result into a dictionary
        """
        result = {
            'Request': str(response.requestIndex),
            'Url': response.requestUrl,
            'Method': response.requestMethod,
            'Payload': response.requestPayload,
            'Time Taken': response.RTT,
            'Request Time': float('%.6f'%(response.RTT-response.elapsedTime)),
            'Response Time': response.elapsedTime,
            'Status': response.status,
            'Length': response.length,
            'Words': response.quantityOfWords,
            'Lines': response.quantityOfLines,
        }
        return result

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