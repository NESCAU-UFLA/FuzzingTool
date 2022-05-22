import unittest
from queue import Queue

from src.fuzzingtool.core.job_manager import JobManager
from src.fuzzingtool.core.dictionary import Dictionary
from src.fuzzingtool.objects import Payload, HttpHistory, Result
from src.fuzzingtool.utils.fuzz_mark import FuzzMark
from ..test_utils.response_mock import ResponseMock
from ..test_utils.fuzz_mark_test_case import FuzzMarkTestCase


class TestJobManager(FuzzMarkTestCase):
    def test_update(self):
        test_result = Result(HttpHistory(response=ResponseMock()))
        test_provider = "TestProvider"
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[[Payload("test-payload")]]),
            job_providers={},
            max_rlevel=1,
        )
        job_manager.update(test_provider, test_result)
        self.assertEqual(job_manager.total_jobs, 2)
        self.assertEqual(test_result.job_description, f"Enqueued new job from {test_provider}")

    def test_get_job(self):
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[[Payload("test-payload")]]),
            job_providers={},
            max_rlevel=1,
        )
        job_manager.get_job()
        self.assertEqual(job_manager.current_job_name, "wordlist")
        self.assertEqual(job_manager.total_requests, 1)

    def test_has_pending_jobs(self):
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={},
            max_rlevel=1,
        )
        self.assertEqual(job_manager.has_pending_jobs(), True)
        job_manager.get_job()
        self.assertEqual(job_manager.has_pending_jobs(), False)

    def test_has_pending_jobs_from_providers_without_job(self):
        test_provider_queue = Queue()
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        self.assertEqual(job_manager.has_pending_jobs_from_providers(), False)

    def test_has_pending_jobs_from_providers_with_job(self):
        test_provider_queue = Queue()
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        test_provider_queue.put((Payload("test-payload-job"),))
        self.assertEqual(job_manager.has_pending_jobs_from_providers(), True)

    def test_check_for_new_jobs(self):
        FuzzMark.recursion_mark_index = 0
        test_provider_queue = Queue()
        job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        job_manager.get_job()
        test_provider_queue.put((Payload("test-payload-job"),))
        job_manager.check_for_new_jobs()
        job_manager.get_job()
        self.assertEqual(job_manager.current_job_name, "test_provider")
        self.assertEqual(job_manager.total_requests, 1)
