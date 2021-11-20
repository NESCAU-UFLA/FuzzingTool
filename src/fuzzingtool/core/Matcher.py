# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .Result import Result
from ..utils.utils import splitStrToList

from typing import List, Dict, Tuple, Callable

class Matcher:
    """Class to handle with the match validations

    Attributes:
        comparator: The dictionary with the default entries to be compared with the current request
        allowedStatus: The dictionary with the allowed status codes (and range)
    """
    @staticmethod
    def buildAllowedStatus(allowedStatus: str) -> dict:
        """Build the matcher attribute for allowed status

        @type allowedStatus: str
        @param allowedStatus: The allowed status codes to match results
        @returns dict: The allowed status code, list and range, parsed into a dict
        """
        def getAllowedStatus(
            status: str,
            allowedList: List[int],
            allowedRange: List[int]
        ) -> None:
            """Get the allowed status code list and range

            @type status: str
            @param status: The status cod given in the terminal
            @type allowedList: List[int]
            @param allowedList: The allowed status codes list
            @type allowedRange: List[int]
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
    def buildComparator(length: str, time: str) -> dict:
        """Build the matcher attribute for data comparator

        @type length: str
        @param length: The length attribute for match results
        @type time: str
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
        matchFunctions: Tuple[Callable, Callable] = None
    ):
        """Class constructor

        @type allowedStatus: dict
        @param allowedStatus: The allowed status dictionary
        @type comparator: dict
        @param comparator: The dict with comparator data
        @type matchFunctions: Tuple[Callable, Callable]
        @param matchFunctions: The callback functions for the match comparator
        """
        self._allowedStatus = allowedStatus
        if matchFunctions:
            self._comparator = comparator
            self._matchLength, self._matchTime = matchFunctions
        else:
            self.setComparator(comparator)

    @classmethod
    def fromString(cls, allowedStatus: str, length: str, time: str) -> object:
        """Creates a Matcher object com strings

        @type allowedStatus: str
        @param allowedStatus: The allowed status codes
        @type length: str
        @param length: The length to be compared with the response body
        @type time: str
        @param time: The time to be compared with the RTT
        @returns Matcher: A Matcher object
        """
        return cls(
            Matcher.buildAllowedStatus(allowedStatus),
            Matcher.buildComparator(length, time)
        )

    def getAllowedStatus(self) -> dict:
        """The allowed status getter

        @returns dict: The allowed status dict
        """
        return self._allowedStatus
    
    def getComparator(self) -> dict:
        """The data comparator getter

        @returns dict: The data comparator dict
        """
        return self._comparator
    
    def getMatchFunctions(self) -> Tuple[Callable, Callable]:
        """Gets the match functions

        @returns Tuple[Callable, Callable]: The match functions
        """
        return (self._matchLength, self._matchTime)

    def allowedStatusIsDefault(self) -> bool:
        """Check if the allowed status is set as default config

        @returns bool: If the allowed status is the default or not
        """
        return self._allowedStatus['IsDefault']

    def comparatorIsSet(self) -> bool:
        """Check if any of the comparators are seted

        @returns bool: if any of the comparators are seted returns True, else False
        """
        return self._comparator['Length'] or self._comparator['Time']

    def setAllowedStatus(self, allowedStatus: dict) -> None:
        """The allowed status setter

        @type allowedStatus: dict
        @param allowedStatus: The allowed status dictionary
        """
        self._allowedStatus = allowedStatus

    def setComparator(self, comparator: dict) -> None:
        """The comparator setter

        @type comparator: dict
        @param comparator: The comparator dictionary
        """

        def getComparatorAndCallback(comparator: str, key: str) -> Tuple[str, Callable]:
            """Gets the comparator and callback

            @type comparator: str
            @param comparator: The value to be compared
            @type key: str
            @param key: Where it'll be compared (Length or Time)
            @returns Tuple[str, Callable]: The comparator and match callback
            """
            def setMatch(match: Dict[str, Callable], comparator: str) -> Tuple[Callable, str]:
                """Set the match function and new comparator value

                @type match: Dict[str, Callable]
                @param match: The dictionary with available comparations
                @type comparator: str
                @param comparator: The value to be compared
                @returns Tuple[Callable, str]: The callback match function, and the new comparator value
                """
                comparator = str(comparator)
                for key, value in match.items():
                    if key in comparator:
                        return (value, comparator.split(key, 1)[1])
                raise IndexError

            matchDict = {
                '>=': lambda toCompare: toCompare >= self._comparator[key],
                '<=': lambda toCompare: toCompare <= self._comparator[key],
                '>': lambda toCompare: toCompare > self._comparator[key],
                '<': lambda toCompare: toCompare < self._comparator[key],
                '==': lambda toCompare: toCompare == self._comparator[key],
                '!=': lambda toCompare: toCompare != self._comparator[key],
            }
            try:
                matchCallback, comparator = setMatch(matchDict, comparator)
            except IndexError:
                matchCallback = lambda toCompare: self._comparator[key] < toCompare
            return (comparator, matchCallback)

        if comparator['Length']:
            lengthComparator, self._matchLength = getComparatorAndCallback(comparator['Length'], 'Length')
            try:
                lengthComparator = int(lengthComparator)
            except:
                raise Exception(f"The length comparator must be an integer, not '{lengthComparator}'!")
            comparator['Length'] = lengthComparator
        if comparator['Time']:
            timeComparator, self._matchTime = getComparatorAndCallback(comparator['Time'], 'Time')
            try:
                timeComparator = float(timeComparator)
            except:
                raise Exception(f"The time comparator must be a number, not '{timeComparator}'!")
            comparator['Time'] = timeComparator
        self._comparator = comparator

    def match(self, result: Result) -> bool:
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type result: Result
        @param result: The actual result object
        @returns bool: A match flag
        """
        if self._matchStatus(result.status):
            if not self._comparator['Length'] is None:
                return self._matchLength(int(result.length))
            if not self._comparator['Time'] is None:
                return self._matchTime(result.RTT)
            return True
        return False
    
    def _matchStatus(self, status: int) -> bool:
        """Check if the result status match with the allowed status dict

        @type status: int
        @param status: The result status code
        @returns bool: if match returns True else False
        """
        return (status in self._allowedStatus['List']
                or (self._allowedStatus['Range']
                and (self._allowedStatus['Range'][0] <= status
                and status <= self._allowedStatus['Range'][1])))
    
    def _matchLength(self, length: int) -> bool:
        """Check if the result length match with the comparator dict

        @type length: int
        @param length: The result length
        @returns bool: if match returns True else False
        """
        pass
    
    def _matchTime(self, time: float) -> bool:
        """Check if the result time match with the comparator dict

        @type time: int
        @param time: The result time
        @returns bool: if match returns True else False
        """
        pass