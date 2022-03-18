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


class JobManager:
    """Class responsible to manage the jobs from controller

    Attributes:
        current_job: The current job that's running
        pending_jobs: The pending jobs to run
        total_requests: The total requests that'll be made on fuzzing
        dictionary: The payload dictionary
        job_providers: The job providers that enqueue new payloads for requests
    """
    def __init__(self,
                 dictionary: Dictionary,
                 job_providers: Dict[str, Queue]):
        self.current_job = None
        self.pending_jobs = Queue()
        self.pending_jobs.put("wordlist")
        self.total_requests = 0
        self.dictionary = dictionary
        self.job_providers = job_providers

    def get_job(self) -> None:
        """Gets a new job to run"""
        self.current_job = self.pending_jobs.get()
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
            if not job_queue.empty():
                self.pending_jobs.put(job_provider)
                self.dictionary.fill_from_queue(job_queue, clear=True)
