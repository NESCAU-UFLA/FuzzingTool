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

class VulnValidator:
    """A vulnerability validator

    Attributes:
        urlFuzzing: The URL Fuzzing flag
        defaultComparator: The dictionary with the default entries to be compared with the current request
    """
    def __init__(self, urlFuzzing: bool, length: int = 0, time: float = 0):
        """Class constructor

        @type urlFuzzing: bool
        @param urlFuzzing: The URL Fuzzing flag
        @type length: int
        @param length: The first request length
        @type time: float
        @param time: The first request time taken
        """
        self.__urlFuzzing = urlFuzzing
        self.__defaultComparator = {
            'Length': 300 + length,
            'Time': 5 + time,
        }
    
    def isVulnerable(self, thisResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @returns bool: A vulnerability flag
        """
        if thisResponse['Status'] < 400:
            if self.__urlFuzzing:
                return True
            elif self.__defaultComparator['Length'] < int(thisResponse['Length']):
                return True
        if not self.__urlFuzzing and self.__defaultComparator['Time'] < (thisResponse['Resp Time']+thisResponse['Req Time']):
            return True
        return False