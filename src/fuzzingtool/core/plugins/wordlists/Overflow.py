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

from ..Plugin import Plugin
from ...bases.BaseWordlist import BaseWordlist
from ....decorators.plugin_meta import plugin_meta
from ....exceptions.MainExceptions import MissingParameter, BadArgumentFormat

from typing import List

@plugin_meta
class Overflow(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "QUANTITY_OF_PAYLOADS,INIT_PAYLOAD:PAYLOAD:END_PAYLOAD",
        'type': str,
    }
    __desc__ = "Build the wordlist for stress and buffer overflow purposes"
    __type__ = ""
    __version__ = "0.1"

    def __init__(self, sourceParam: str):
        if not sourceParam:
            raise MissingParameter("quantity of payloads")
        if ',' in sourceParam:
            quantityOfPayloads, payload = sourceParam.split(',', 1)
            if ':' in payload:
                try:
                    initPayload, payload, endPayload = payload.split(':', 3)
                except:
                    raise BadArgumentFormat("invalid quantity of values to unpack (expected initPayload:payload:endPayload)")
            else:
                initPayload, endPayload = '', ''
            quantityOfPayloads = quantityOfPayloads
        else:
            quantityOfPayloads = sourceParam
            initPayload, payload, endPayload = '', '', ''
        try:
            quantityOfPayloads = int(quantityOfPayloads)
        except:
            raise BadArgumentFormat("the quantity of payloads must be integer")
        self.quantityOfPayloads = quantityOfPayloads
        self.initPayload = initPayload
        self.payload = payload
        self.endPayload = endPayload
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        return [
            f"{self.initPayload}{self.payload*i}{self.endPayload}" for i in range(self.quantityOfPayloads)
        ]