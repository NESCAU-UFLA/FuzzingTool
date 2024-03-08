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
from threading import Lock

from ...objects.payload import Payload


class BaseWordlist(ABC):
    """Base wordlist

    Attributes:
        wordlist: The list with the payloads
    """
    def __init__(self):
        self.__fuzz_mark = ''
        self.__lock = Lock()

    def __len__(self) -> int:
        return self.__count

    def __next__(self) -> Payload:
        with self.__lock:
            return Payload(self._next(), self.__fuzz_mark)

    def __iter__(self):
        return self

    def set_fuzz_mark(self, fuzz_mark: str) -> None:
        self.__fuzz_mark = fuzz_mark

    def build(self) -> None:
        self._build()
        self.__count = self._count()

    @abstractmethod
    def _build(self) -> None:
        """The wordlist builder

        @returns List[str]: The builded wordlist
        """
        pass

    @abstractmethod
    def _count(self) -> int:
        """Get the quantity of itens on wordlist"""
        pass

    @abstractmethod
    def _next(self) -> str:
        """Get the next payload to process"""
        pass


class BaseListWordlist(BaseWordlist):
    def __init__(self):
        super().__init__()
        self.index = 0
        self.__wordlist = []

    def build(self) -> None:
        self.__wordlist = self._build()
        self.__count = self._count()

    @abstractmethod
    def _build(self) -> List[str]:
        """The wordlist builder

        @returns List[str]: The builded wordlist
        """
        pass

    def _count(self) -> int:
        return len(self.__wordlist)

    def _next(self) -> str:
        if self.index < self.__count:
            item = self.__wordlist[self.index]
            self.index += 1
            return item
        raise StopIteration
