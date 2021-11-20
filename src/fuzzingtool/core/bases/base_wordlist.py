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

from abc import ABC, abstractmethod
from typing import List


class BaseWordlist(ABC):
    """Base wordlist

    Attributes:
        wordlist: The list with the payloads
    """
    def __init__(self):
        self.__wordlist = []

    def __len__(self) -> int:
        return len(self.__wordlist)

    def get(self) -> List[str]:
        """The wordlist getter

        @returns List[str]: The list with the payloads
        """
        return self.__wordlist

    def build(self) -> None:
        """Builds the wordlist"""
        self.__wordlist = self._build()

    @abstractmethod
    def _build(self) -> List[str]:
        """The wordlist builder

        @returns List[str]: The builded wordlist
        """
        pass
