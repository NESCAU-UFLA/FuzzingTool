# Copyright (c) 2021 Vitor Oriel <https://github.com/VitorOriel>
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

from ..BaseWordlist import BaseWordlist
from ....utils.utils import splitStrToList, checkRangeList
from ....exceptions.MainExceptions import MissingParameter

class ListWordlist(BaseWordlist):
    __author__ = ("Vitor Oriel",)

    def __init__(self, payloadList: str):
        payloadList = payloadList[1:len(payloadList)-1]
        if not payloadList:
            raise MissingParameter("list of payloads")
        self.payloadList = payloadList
        super().__init__()

    def _build(self):
        buildedList = []
        for payload in splitStrToList(self.payloadList):
            buildedList.extend(checkRangeList(payload))
        return buildedList