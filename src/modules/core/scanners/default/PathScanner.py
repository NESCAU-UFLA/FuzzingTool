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
from ....conn.Response import Response
from ....parsers.RequestParser import getPath
from ....IO.OutputHandler import Colors, outputHandler as oh

class PathScanner(BaseScanner):
    __name__ = "PathScanner"
    __author__ = ("Vitor Oriel C N Borges")

    def getResult(self, response: Response):
        result = super().getResult(response)
        response = response.getResponse()
        result['Payload'] = getPath(response.request.url)
        result['Redirected'] = ''
        if '301' in str(response.history) or '302' in str(response.history):
            result['Payload'] = getPath(response.history[0].request.url)
            result['Redirected'] = response.url
        return result

    def scan(self, result: dict):
        return True
    
    def getMessage(self, result: dict):
        status = result['Status']
        statusColor = ''
        redirected = ''
        if self._matchStatus(status):
            if status == 200:
                statusColor = f'{Colors.BOLD}{Colors.GREEN}'
            else:
                statusColor = f'{Colors.BOLD}{Colors.LIGHT_YELLOW}'
            redirected = result['Redirected']
            if redirected:
                redirected = f" | {Colors.LIGHT_GRAY}Redirected{Colors.RESET} {Colors.LIGHT_YELLOW}{redirected}"
        payload = '{:<30}'.format(oh.fixPayloadToOutput(result['Payload']))
        length = '{:>8}'.format(result['Length'])
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {statusColor}{status}{Colors.RESET} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}"+
            f"{redirected}{Colors.GRAY}]{Colors.RESET}"
        )