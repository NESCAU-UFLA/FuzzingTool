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

import re
from typing import Pattern

from ..objects.result import Result
from ..exceptions import BadArgumentFormat, BadArgumentType


class Filter:
    def __init__(self, status_code: str, regex: str):
        self.status_code = None if not status_code else self.__build_status_code(status_code)
        self.regexer = None if not regex else self.__build_regexer(regex)

    def check(self, result: Result) -> bool:
        if (self.status_code is not None and
                result.history.status == self.status_code):
            return False
        if (self.regexer is not None and
                self.regexer.search(result.history.response.text)):
            return False
        return True

    def __build_status_code(self, status_code: str) -> int:
        try:
            status_code = int(status_code)
        except ValueError:
            raise BadArgumentType(
                f"The filter status argument ({status_code}) must be integer"
            )
        return status_code

    def __build_regexer(self, regex: str) -> Pattern[str]:
        """The regexer builder

        @type regex: str
        @param regex: The regular expression to set
        @returns Pattern[str]: The regex object
        """
        try:
            regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise BadArgumentFormat(f"Invalid regex format {regex}")
        return regexer
