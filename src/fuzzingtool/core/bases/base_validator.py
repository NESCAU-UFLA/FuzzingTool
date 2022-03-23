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

from abc import ABC
import re
from typing import Pattern

from ...exceptions import BadArgumentFormat


class BaseValidator(ABC):
    """Base validator class for both Matcher and Filter

    Attributes:
        regexer: The regex object
    """
    def __init__(self, regex: str):
        """Class constructor

        @type regex: str
        @param regex: The regular expression to be setted
        """
        self._regexer = None if not regex else self.__build_regexer(regex)

    def __build_regexer(self, regex: str) -> Pattern[str]:
        """Build the regexer object

        @type regex: str
        @param regex: The regular expression to be setted
        @returns Pattern[str]: The regex object
        """
        try:
            regexer = re.compile(regex, re.IGNORECASE)
        except re.error:
            raise BadArgumentFormat(f"Invalid regex format {regex} on {type(self).__name__}")
        return regexer
