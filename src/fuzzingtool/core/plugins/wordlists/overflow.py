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

from ...bases.base_plugin import Plugin
from ...bases.base_wordlist import BaseWordlist
from ....decorators.plugin_meta import plugin_meta
from ....exceptions import MissingParameter, BadArgumentFormat, BadArgumentType


@plugin_meta
class Overflow(BaseWordlist, Plugin):
    __author__ = ("Vitor Oriel",)
    __params__ = {
        'metavar': "QUANTITY_OF_PAYLOADS,INIT_PAYLOAD:PAYLOAD:END_PAYLOAD",
        'type': str,
    }
    __desc__ = "Build the wordlist for stress and buffer overflow purposes"
    __type__ = None
    __version__ = "0.1"

    def __init__(self, source_param: str):
        if not source_param:
            raise MissingParameter("quantity of payloads")
        self.param = source_param
        self.index = 0
        BaseWordlist.__init__(self)

    def _build(self) -> None:
        if ',' in self.param:
            quantity_of_payloads, payload = self.param.split(',', 1)
            if ':' in payload:
                try:
                    init_payload, payload, end_payload = payload.split(':', 3)
                except ValueError:
                    raise BadArgumentFormat(
                        "invalid quantity of values to unpack "
                        "(expected init_payload:payload:end_payload)"
                    )
            else:
                init_payload, end_payload = '', ''
        else:
            quantity_of_payloads = self.param
            init_payload, payload, end_payload = '', '', ''
        try:
            quantity_of_payloads = int(quantity_of_payloads)
        except ValueError:
            raise BadArgumentType("the quantity of payloads must be integer")
        self.init_payload = init_payload
        self.payload = payload
        self.end_payload = end_payload
        self.__count = quantity_of_payloads

    def _next(self) -> str:
        if self.index < self.__count:
            item = f"{self.init_payload}{self.payload*self.index}{self.end_payload}"
            self.index += 1
            return item
        raise StopIteration
