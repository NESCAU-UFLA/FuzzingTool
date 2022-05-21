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

from typing import Tuple

from .payload import Payload
from ..utils.fuzz_mark import FuzzMark


class FuzzWord:
    """Class to represent a Fuzzing Word

    Attributes:
        word: The word that'll be fuzzed or not
        fuzzing_indexes: The fuzzing indexes of the word
        has_fuzzing: A flag to say if the word will be fuzzed or not
    """
    def __init__(self, word: str = FuzzMark.BASE_MARK):
        """Class constructor

        @type word: str
        @param word: The word that'll be fuzzed or not
        """
        self.word = word
        self.fuzz_dict = {
            mark: mark in word for mark in FuzzMark.all_marks
        }
        self.has_fuzzing = any([has_mark for has_mark in self.fuzz_dict.values()])

    def __hash__(self) -> int:
        return hash(self.word)

    def __eq__(self, other: 'FuzzWord') -> bool:
        return hash(self) == hash(other)

    def get_payloaded_word(self, payloads: Tuple[Payload]) -> str:
        """Gets the word with the payload inside

        @type payload: Payload
        @param payload: The payload used in the fuzzing indexes
        @returns str: The word with the payload inside
        """
        if not self.has_fuzzing:
            return self.word
        payloaded_word = self.word
        for payload in payloads:
            fuzz_mark = payload.fuzz_mark
            if self.fuzz_dict[fuzz_mark]:
                payloaded_word = payloaded_word.replace(fuzz_mark, payload.final)
        return payloaded_word
