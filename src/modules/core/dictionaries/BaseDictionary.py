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

from .Payloader import Payloader

from queue import Queue

class BaseDictionary(Payloader):
    """Base dictionary

    Attributes:
        payloads: The queue that contains all payloads inside the wordlist
        wordlist: The wordlist that contains the payloads backup
    """
    def __init__(self):
        super().__init__()
        self.__payloads = Queue()
        self._wordlist = []

    def __next__(self):
        """Gets the next payload to be processed

        @returns list: The payloads used in the request
        """
        return self._getCustomizedPayload(self.__payloads.get())
    
    def __len__(self):
        """Gets the wordlist length

        @returns int: The wordlist length
        """
        lengthPrefix = len(self._prefix)
        if lengthPrefix == 0:
            lengthPrefix = 1
        lengthSuffix = len(self._suffix)
        if lengthSuffix == 0:
            lengthSuffix = 1
        return (len(self._wordlist)*lengthSuffix*lengthPrefix)

    def isEmpty(self):
        """The payloads empty queue flag getter

        @returns bool: The payloads empty queue flag
        """
        return self.__payloads.empty()

    def reload(self):
        """Reloads the payloads queue with the wordlist content"""
        self.__payloads = Queue()
        for payload in self._wordlist:
            self.__payloads.put(payload)

    def setWordlist(self, sourceParam: str):
        """The wordlist setter

        @type sourceParam: str
        @param sourceParam: The source string of the wordlist
        """
        raise NotImplementedError("setWordlist method should be overrided")