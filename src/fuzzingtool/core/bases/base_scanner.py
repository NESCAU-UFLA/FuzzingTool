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

from abc import abstractmethod
from queue import Queue
from urllib.parse import urljoin

from .job_provider import JobProvider
from ...objects import Payload, Result, ScannerResult
from ...utils.fuzz_mark import FuzzMark


class BaseScanner(JobProvider):
    """Base scanner (ABC)

    Attributes:
        payloads_queue: The payload queue for new requests
    """
    def __init__(self):
        self.payloads_queue = Queue()
        super().__init__()

    def __str__(self) -> str:
        return type(self).__name__

    def notify(self, result: Result) -> None:
        """Notify the observer with the new job

        @type result: Result
        @param result: The FuzzingTool result object
        """
        self._observer.update(str(self), result)

    @abstractmethod
    def scan(self, result: Result) -> bool:
        """Scan the FuzzingTool result

        @type result: Result
        @param result: The result object
        @reeturns bool: A match flag
        """
        pass

    def process(self, result: Result) -> None:
        """Process the FuzzingTool result from this base scanner.
           Do not override this function. If you need so, override _process method instead

        @type result: Result
        @param result: The result object
        """
        scanner_name = str(self)
        result.scanners_res[scanner_name] = ScannerResult(scanner_name)
        self._process(result)

    def get_self_res(self, result: Result) -> ScannerResult:
        """Get the self Scanner result

        @type result: Result
        @param result: The FuzzingTool result object
        @returns ScannerResult: The self scanner result object
        """
        return result.scanners_res[str(self)]

    def enqueue_path(self, result: Result, path: str) -> None:
        """Enqueue a path into the payload queue for the next job

        @type result: Result
        @param result: The result of the payload
        @type path: str
        @param path: The path that'll be enqueued
        """
        was_empty = self.payloads_queue.empty()
        self.payloads_queue.put(tuple([
            Payload().update(result_payload).with_recursion(
                urljoin(result_payload.final, path)
            )
            if i == FuzzMark.recursion_mark_index
            else result_payload
            for i, result_payload in enumerate(result._payloads)
        ]))
        self.get_self_res(result).enqueued_payloads += 1
        if was_empty:
            self.notify(result)

    def _process(self, result: Result) -> None:
        """Process the FuzzingTool result through child scanner if needed

        @type result: Result
        @param result: The result object
        """
        pass
