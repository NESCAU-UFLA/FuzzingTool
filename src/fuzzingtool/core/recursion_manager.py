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
from queue import Queue

from .bases.job_provider import JobProvider
from ..objects import Payload, Result
from ..utils.fuzz_mark import FuzzMark


class RecursionManager(JobProvider):
    """Class responsible to manage the directory recursion

    Attributes:
        max_rlevel: The maximum jobs recursion level
        wordlist: The wordlist with base payloads
        directories_queue: The control queue for directories found
        payloads_queue: The jobs queue for the job manager
    """
    def __init__(self, max_rlevel: int, wordlist: Queue[Tuple[Payload]]):
        """Class constructor

        @type max_rlevel: int
        @param max_rlevel: The maximum jobs recursion level
        @type wordlist: List[str]
        @param wordlist: The wordlist with base payloads
        """
        self.max_rlevel = max_rlevel
        self.wordlist = wordlist
        self.directories_queue = Queue()
        self.payloads_queue = Queue()
        super().__init__()

    def notify(self, result: Result, path: str) -> None:
        """Notify the observer with the new job

        @type result: Result
        @param result: The FuzzingTool result object
        @type path: str
        @param path: The path that enqueued the job
        """
        self._observer.update(f"directory recursion on path {path}", result)

    def has_recursive_job(self) -> bool:
        """Check if has pending recursive job

        @returns bool: A flag to say if has recursive job
        """
        return not self.directories_queue.empty()

    def check_for_recursion(self, result: Result) -> None:
        """Check if a result is eligible for recursion, and enqueue it into the directories queue

        @type result: Result
        @param result: THe FuzzingTool result object
        """
        if result.history.is_path:
            recursive_payload: Payload = result._payloads[FuzzMark.recursion_mark_index]
            if recursive_payload.rlevel < self.max_rlevel:
                path = result.history.parsed_url.path
                self.directories_queue.put(
                    Payload().update(recursive_payload).with_recursion(path[1:])
                )
                self.notify(result, path)

    def fill_payloads_queue(self) -> None:
        """Fill the payloads queue with recursive directory payloads"""
        recursive_directory: Payload = self.directories_queue.get()
        while not self.wordlist.empty():
            payloads_tuple = self.wordlist.get()
            raw_payload = payloads_tuple[FuzzMark.recursion_mark_index].raw
            new_payload = Payload().update(recursive_directory)
            new_payload.raw = raw_payload
            new_payload.final += raw_payload
            self.payloads_queue.put((
                *payloads_tuple[:FuzzMark.recursion_mark_index],
                new_payload,
                *payloads_tuple[(FuzzMark.recursion_mark_index+1):]
            ))
