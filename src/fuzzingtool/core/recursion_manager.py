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

from queue import Queue
from typing import List

from ..objects import Payload, Result


class RecursionManager:
    def __init__(self, max_rlevel: int, wordlist: List[Payload]):
        self.max_rlevel = max_rlevel
        self.wordlist = wordlist
        self.directories_queue = Queue()
        self.payloads_queue = Queue()
    
    def has_recursive_job(self) -> bool:
        return not self.directories_queue.empty()

    def fill_payloads_queue(self) -> None:
        recursive_directory = self.directories_queue.get()
        for wordlist_payload in self.wordlist:
            new_payload = Payload().update(recursive_directory)
            new_payload.final += wordlist_payload
            self.payloads_queue.put(new_payload)

    def check_for_recursion(self, result: Result) -> None:
        parsed_url = result.history.parsed_url
        payload = result._payload
        if parsed_url.is_path and payload.rlevel < self.max_rlevel:
            self.directories_queue.put(Payload().update(payload).with_recursion(parsed_url.path[1:]))
