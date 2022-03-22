import unittest
from queue import Queue

from src.fuzzingtool.core.job_manager import JobManager
from src.fuzzingtool.core.dictionary import Dictionary
from src.fuzzingtool.objects.payload import Payload


class TestJobManager(unittest.TestCase):
    def test_get_job(self):
        test_job_manager = JobManager(
            dictionary=Dictionary(wordlist=["test-payload"]),
            job_providers={},
            max_rlevel=1,
        )
        test_job_manager.get_job()
        self.assertEqual(test_job_manager.current_job, "wordlist")
        self.assertEqual(test_job_manager.total_requests, 1)

    def test_has_pending_jobs(self):
        test_job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={},
            max_rlevel=1,
        )
        self.assertEqual(test_job_manager.has_pending_jobs(), True)
        test_job_manager.get_job()
        self.assertEqual(test_job_manager.has_pending_jobs(), False)

    def test_has_pending_jobs_from_providers_without_job(self):
        test_provider_queue = Queue()
        test_job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        self.assertEqual(test_job_manager.has_pending_jobs_from_providers(), False)

    def test_has_pending_jobs_from_providers_with_job(self):
        test_provider_queue = Queue()
        test_job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        test_provider_queue.put("test-payload-job")
        self.assertEqual(test_job_manager.has_pending_jobs_from_providers(), True)

    def test_check_for_new_jobs(self):
        test_provider_queue = Queue()
        test_job_manager = JobManager(
            dictionary=Dictionary(wordlist=[]),
            job_providers={'test_provider': test_provider_queue},
            max_rlevel=1,
        )
        test_job_manager.get_job()
        test_provider_queue.put(Payload("test-payload-job"))
        test_job_manager.check_for_new_jobs()
        test_job_manager.get_job()
        self.assertEqual(test_job_manager.current_job, "test_provider")
        self.assertEqual(test_job_manager.total_requests, 1)
