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

from ...bases.base_wordlist import BaseWordlist
from ....utils.utils import split_str_to_list, check_range_list


class ListWordlist(BaseWordlist):
    __author__ = ("Vitor Oriel",)

    def __init__(self, payload_list: str):
        payload_list = payload_list[1:-1]
        self.payload_list = payload_list
        super().__init__()

    def _build(self) -> List[str]:
        builded_list = []
        for payload in split_str_to_list(self.payload_list):
            builded_list.extend(check_range_list(payload))
        return builded_list
