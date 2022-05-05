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

from typing import List

from .bases.base_validator import BaseValidator
from ..objects.result import Result
from ..exceptions import BadArgumentType


class Filter(BaseValidator):
    """Class responsible to filter the results by exclusion rules

    Attributes:
        status_codes: The list with excluded status codes
        regexer: The regex object to exclude by regex
    """
    def __init__(self, status_code: str = None, regex: str = None):
        """Class constructor

        @type status_code: str
        @param status_code: The status code string for filtering
        @type regex: str
        @param regex: The regular expression for filtering
        """
        self._status_codes = [] if not status_code else self.__build_status_codes(status_code)
        super().__init__(regex)

    def check(self, result: Result) -> bool:
        """Checks if the filter configs matches with the result attributes

        @type result: Result
        @param result: The FuzzingTool result object
        @returns bool: A filter flag
        """
        if result.history.status in self._status_codes:
            return False
        if (self._regexer is not None and
                self._regexer.search(result.history.response.text)):
            return False
        return True

    def __build_status_codes(self, status_code: str) -> List[int]:
        """Build the status codes list

        @type status_code: str
        @param status_code: The status code string
        @returns List[str]: The list with status codes as integers
        """
        try:
            status_codes = [int(status) for status in status_code.split(',')]
        except ValueError:
            raise BadArgumentType(
                f"The filter status argument ({status_code}) must be integer"
            )
        return status_codes
