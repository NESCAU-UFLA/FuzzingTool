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

from .Payloader import Payloader

from queue import Queue
from typing import List

class Dictionary:
    """Dictionary object handler

    Attributes:
        wordlist: The wordlist that contains the payloads backup
        payloads: The queue that contains all payloads inside the wordlist
    """
    def __init__(self, wordlist: list):
        """Class constructor

        @type wordlist: list
        @param wordlist: The wordlist with the payloads
        """
        self.__wordlist = wordlist
        self.__payloads = Queue()

    def __next__(self) -> List[str]:
        """Gets the next payload to be processed

        @returns list: The payloads used in the request
        """
        return Payloader.getCustomizedPayload(self.__payloads.get())
    
    def __len__(self) -> int:
        """Gets the wordlist length

        @returns int: The wordlist length
        """
        lengthPrefix = len(Payloader.prefix)
        if lengthPrefix == 0:
            lengthPrefix = 1
        lengthSuffix = len(Payloader.suffix)
        if lengthSuffix == 0:
            lengthSuffix = 1
        lengthEncoders = len(Payloader.encoder)
        if lengthEncoders == 0:
            lengthEncoders = 1
        return (len(self.__wordlist)*lengthSuffix*lengthPrefix*lengthEncoders)

    def isEmpty(self) -> bool:
        """The payloads empty queue flag getter

        @returns bool: The payloads empty queue flag
        """
        return self.__payloads.empty()

    def reload(self) -> None:
        """Reloads the payloads queue with the wordlist content"""
        self.__payloads = Queue()
        for payload in self.__wordlist:
            self.__payloads.put(payload)