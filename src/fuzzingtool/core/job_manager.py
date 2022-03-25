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
from typing import Dict

from .dictionary import Dictionary
from ..objects.payload import Payload


class JobManager:
    """Class responsible to manage the jobs

    Attributes:
        current_job: The current job that's running
        pending_jobs: The pending jobs to run
        total_requests: The total requests that'll be made on fuzzing
        dictionary: The payload dictionary
        job_providers: The job providers that enqueue new payloads for requests
        max_rlevel: The maximum jobs recursion level
    """
    def __init__(self,
                 dictionary: Dictionary,
                 job_providers: Dict[str, Queue],
                 max_rlevel: int):
        """Class constructor

        @type dictionary: Dictionary
        @param dictionary: The dictionary that'll be filled with payloads
        @type job_providers: Dict[str, Queue[Payload]]
        @param job_providers: The job providers, with name and queue
        """
        self.current_job = None
        wordlist_queue = Queue()
        for payload in dictionary.wordlist:
            wordlist_queue.put(Payload(payload))
        self.pending_jobs = Queue()
        self.pending_jobs.put(("wordlist", wordlist_queue))
        self.total_requests = 0
        self.dictionary = dictionary
        self.job_providers = job_providers
        self.max_rlevel = max_rlevel

    def get_job(self) -> None:
        """Gets a new job to run"""
        self.current_job, job_queue = self.pending_jobs.get()
        self.dictionary.fill_from_queue(job_queue, clear=True)
        self.total_requests = len(self.dictionary)

    def has_pending_jobs(self) -> bool:
        """Checks if has pending jobs to run

        @returns bool: The flag to say if has pending jobs to run
        """
        return not self.pending_jobs.empty()

    def has_pending_jobs_from_providers(self) -> bool:
        """Checks if has pending jobs from providers

        @returns bool: The flag to say if has pending jobs from providers
        """
        for job_queue in self.job_providers.values():
            if not job_queue.empty():
                return True
        return False

    def check_for_new_jobs(self) -> None:
        """Check for new jobs from providers
           If has, fill the dictionary with the payloads and enqueue the job
        """
        for job_provider, job_queue in self.job_providers.items():
            new_job = Queue()
            while not job_queue.empty():
                payload: Payload = job_queue.get()
                if payload.rlevel <= self.max_rlevel:
                    new_job.put(payload)
            if not new_job.empty():
                self.pending_jobs.put((job_provider, new_job))
