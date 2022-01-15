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
from ....exceptions.main_exceptions import (MissingParameter, BadArgumentFormat,
                                            BadArgumentType)


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

    def __init__(self, source_param: str):
        if not source_param:
            raise MissingParameter("quantity of payloads")
        if ',' in source_param:
            quantity_of_payloads, payload = source_param.split(',', 1)
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
            quantity_of_payloads = source_param
            init_payload, payload, end_payload = '', '', ''
        try:
            quantity_of_payloads = int(quantity_of_payloads)
        except ValueError:
            raise BadArgumentType("the quantity of payloads must be integer")
        self.quantity_of_payloads = quantity_of_payloads
        self.init_payload = init_payload
        self.payload = payload
        self.end_payload = end_payload
        BaseWordlist.__init__(self)

    def _build(self) -> List[str]:
        return [
            f"{self.init_payload}{self.payload*i}{self.end_payload}"
            for i in range(self.quantity_of_payloads)
        ]
