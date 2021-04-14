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

class Matcher:
    """A matcher validator

    Attributes:
        comparator: The dictionary with the default entries to be compared with the current request
        allowedStatus: The dictionary with the allowed status codes (and range)
    """
    def __init__(self):
        self._comparator = {
            'Length': None,
            'Time': None
        }
        self._allowedStatus = {
            'List': [200],
            'Range': [],
        }

    def update(self, matcher):
        """Update the self attributes based on another Matcher attributes

        @type matcher: Matcher
        @param matcher: The other matcher to copy the attributes
        """
        self._comparator = matcher._comparator
        self._allowedStatus = matcher._allowedStatus

    def comparatorIsSet(self):
        """Check if any of the comparators are seted

        @returns bool: if any of the comparators are seted returns True, else False
        """
        return self._comparator['Length'] or self._comparator['Time']

    def setComparator(self, comparator: dict):
        """The default comparator setter

        @type comparator: dict
        @param comparator: The comparator with time and length
        """
        self._comparator = comparator

    def setAllowedStatus(self, allowedStatus: dict):
        """The allowed status setter

        @type allowedStatus: dict
        @param allowedStatus: The allowed status dict
        """
        self._allowedStatus = allowedStatus

    def match(self, result: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type result: dict
        @param result: The actual result dictionary
        @returns bool: A vulnerability flag
        """
        if self._matchStatus(result['Status']):
            if self._comparator['Length']:
                return self._matchLength(int(result['Length']))
            if self._comparator['Time']:
                return self._matchTime(result['Time Taken'])
            return True
        return False
    
    def _matchStatus(self, status: int):
        """Check if the result status match with the allowed status dict

        @type status: int
        @param status: The result status code
        @returns bool: if match returns True else False
        """
        return (status in self._allowedStatus['List']
                or (self._allowedStatus['Range']
                and (self._allowedStatus['Range'][0] <= status
                and status <= self._allowedStatus['Range'][1])))
    
    def _matchLength(self, length: int):
        """Check if the result length match with the comparator dict

        @type length: int
        @param length: The result length
        @returns bool: if match returns True else False
        """
        return self._comparator['Length'] < length
    
    def _matchTime(self, time: float):
        """Check if the result time match with the comparator dict

        @type time: int
        @param time: The result time
        @returns bool: if match returns True else False
        """
        return self._comparator['Time'] < time