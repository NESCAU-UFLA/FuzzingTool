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

class Reflected(DataScanner):
    __name__ = "Reflected"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = ""
    __desc__ = "Lookup if the payload was reflected in the response body"
    __type__ = "DataFuzzing"

    """
    Attributes:
        reflected: The dictionary to save a flag for each matched result,
                   saying if the payload was reflected or not
    """
    def __init__(self):
        super().__init__()
        self.__reflected = {}

    def getResult(self, response: Response):
        return super().getResult(response)

    def scan(self, result: dict):
        reflected = result['Payload'] in result['Body']
        self.__reflected[result['Request']] = reflected
        return reflected
    
    def cliCallback(self, result: dict):
        reflected = f"{Colors.LIGHT_YELLOW}{Colors.BOLD}IDK"
        if result['Request'] in self.__reflected:
            if self.__reflected[result['Request']]:
                reflected = f"{Colors.GREEN}{Colors.BOLD}YES"
            else:
                reflected = f"{Colors.LIGHT_RED}{Colors.BOLD}NO "
                del self.__reflected[result['Request']]
        payload = '{:<30}'.format(fixPayloadToOutput(result['Payload']))
        length = '{:>8}'.format(result['Length'])
        return (
            f"{payload} {Colors.GRAY}["+
            f"{Colors.LIGHT_GRAY}Reflected{Colors.RESET} {reflected}{Colors.RESET} | "+
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {result['Status']} | "+
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {length}{Colors.GRAY}]{Colors.RESET}"
        )