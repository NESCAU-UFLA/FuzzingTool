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

from .Result import Result
from ..utils.utils import splitStrToList

class Matcher:
    """A matcher validator

    Attributes:
        comparator: The dictionary with the default entries to be compared with the current request
        allowedStatus: The dictionary with the allowed status codes (and range)
    """
    @staticmethod
    def buildAllowedStatus(allowedStatus: str):
        """Build the matcher attribute for allowed status

        @type allowedStatus: str
        @param allowedStatus: The allowed status codes to match results
        @returns dict: The allowed status code, list and range, parsed into a dict
        """
        def getAllowedStatus(status: str, allowedList: list, allowedRange: list):
            """Get the allowed status code list and range

            @type status: str
            @param status: The status cod given in the terminal
            @type allowedList: list
            @param allowedList: The allowed status codes list
            @type allowedRange: list
            @param allowedRange: The range of allowed status codes
            """
            try:
                if '-' not in status:
                    allowedList.append(int(status))
                else:
                    codeLeft, codeRight = (int(code) for code in status.split('-', 1))
                    if codeRight < codeLeft:
                        codeLeft, codeRight = codeRight, codeLeft
                    allowedRange[:] = [codeLeft, codeRight]
            except:
                raise Exception(f"The match status argument ({status}) must be integer")

        if not allowedStatus:
            isDefault = True
            allowedList = [200]
        else:
            isDefault = False
            allowedList = []
        allowedRange = []
        for status in splitStrToList(allowedStatus):
            getAllowedStatus(status, allowedList, allowedRange)
        return {
            'IsDefault': isDefault,
            'List': allowedList,
            'Range': allowedRange,
        }

    @staticmethod
    def buildComparator(length: int, time: float):
        """Build the matcher attribute for data comparator

        @type length: int
        @param length: The length attribute for match results
        @type time: float
        @param time: The time attribute for match results
        @returns dict: The data comparators parsed into a dict
        """
        return {
            'Length': None if not length else length,
            'Time': None if not time else time,
        }

    def __init__(self,
        allowedStatus: dict = {
            'IsDefault': True,
            'List': [200],
            'Range': [],
        },
        comparator: dict = {
            'Length': None,
            'Time': None,
        },
    ):
        self._allowedStatus = allowedStatus
        self._comparator = comparator

    @classmethod
    def fromString(cls, allowedStatus: str, length: int, time: float):
        return cls(
            Matcher.buildAllowedStatus(allowedStatus),
            Matcher.buildComparator(length, time)
        )

    def getAllowedStatus(self):
        """The allowed status getter

        @returns dict: The allowed status dict
        """
        return self._allowedStatus
    
    def getComparator(self):
        """The data comparator getter

        @returns dict: The data comparator dict
        """
        return self._comparator

    def allowedStatusIsDefault(self):
        """Check if the allowed status is set as default config

        @returns bool: If the allowed status is the default or not
        """
        return self._allowedStatus['IsDefault']

    def comparatorIsSet(self):
        """Check if any of the comparators are seted

        @returns bool: if any of the comparators are seted returns True, else False
        """
        return self._comparator['Length'] or self._comparator['Time']

    def setAllowedStatus(self, allowedStatus: dict):
        """The allowed status setter

        @type allowedStatus: dict
        @param allowedStatus: The allowed status dictionary
        """
        self._allowedStatus = allowedStatus

    def setComparator(self, comparator: dict):
        """The comparator setter

        @type comparator: dict
        @param comparator: The comparator dictionary
        """
        self._comparator = comparator

    def match(self, result: Result):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type result: Result
        @param result: The actual result object
        @returns bool: A match flag
        """
        if self._matchStatus(result.status):
            if self._comparator['Length']:
                return self._matchLength(int(result.length))
            if self._comparator['Time']:
                return self._matchTime(result.RTT)
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