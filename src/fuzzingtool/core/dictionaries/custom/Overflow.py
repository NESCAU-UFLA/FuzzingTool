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

from ..BaseDictionary import BaseDictionary
from ....exceptions.MainExceptions import MissingParameter

class Overflow(BaseDictionary):
    __name__ = "Overflow"
    __author__ = ("Vitor Oriel C N Borges")
    __params__ = "QUANTITY_OF_PAYLOADS,INIT_PAYLOAD:PAYLOAD:END_PAYLOAD"
    __desc__ = "Build the wordlist for stress and buffer overflow purposes"
    __type__ = ""

    def __init__(self, sourceParam: str):
        super().__init__()
        if not sourceParam:
            raise MissingParameter("quantity of payloads")
        if ',' in sourceParam:
            quantityOfPayloads, payload = sourceParam.split(',', 1)
            if ':' in payload:
                try:
                    initPayload, payload, endPayload = payload.split(':', 3)
                except:
                    raise Exception("Invalid quantity of values to unpack (expected initPayload:payload:endPayload)")
            else:
                initPayload, endPayload = '', ''
            quantityOfPayloads = quantityOfPayloads
        else:
            quantityOfPayloads = sourceParam
            initPayload, payload, endPayload = '', '', ''
        try:
            quantityOfPayloads = int(quantityOfPayloads)
        except:
            raise Exception("The quantity of payloads must be integer")
        self.quantityOfPayloads = quantityOfPayloads
        self.initPayload = initPayload
        self.payload = payload
        self.endPayload = endPayload

    def setWordlist(self):
        self._wordlist = [
            f"{self.initPayload}{self.payload*i}{self.endPayload}" for i in range(self.quantityOfPayloads)
        ]