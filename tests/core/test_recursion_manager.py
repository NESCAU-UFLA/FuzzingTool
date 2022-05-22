from unittest.mock import Mock, patch
from queue import Queue
from typing import Tuple

from src.fuzzingtool.core.recursion_manager import RecursionManager
from src.fuzzingtool.objects import Payload, Result, HttpHistory
from src.fuzzingtool.utils.fuzz_mark import FuzzMark
from ..test_utils.response_mock import ResponseMock
from ..test_utils.fuzz_mark_test_case import FuzzMarkTestCase


class TestRecursionManager(FuzzMarkTestCase):
    def setUp(self):
        self.base_wordlist = ['test_1', 'test_2']
        self.recursion_manager = RecursionManager(
            max_rlevel=1,
            wordlist=Queue()
        )
        for w in self.base_wordlist:
            self.recursion_manager.wordlist.put((Payload(w),))

    def test_notify(self):
        mock_observer = Mock()
        mock_observer.update = Mock()
        self.recursion_manager.set_observer(mock_observer)
        test_path = "/test_path/"
        test_result = Result(HttpHistory(response=ResponseMock()))
        self.recursion_manager.notify(test_result, test_path)
        mock_observer.update.assert_called_once_with(f"directory recursion on path {test_path}", test_result)

    def test_has_recursive_job(self):
        test_has_recursive_job = self.recursion_manager.has_recursive_job()
        self.assertIsInstance(test_has_recursive_job, bool)
        self.assertEqual(test_has_recursive_job, False)

    @patch("src.fuzzingtool.core.recursion_manager.RecursionManager.notify")
    def test_check_for_recursion_with_recursion(self, mock_notify: Mock):
        FuzzMark.recursion_mark_index = 0
        test_directory = "test_directory/"
        test_result = Result(HttpHistory(response=ResponseMock()))
        test_result.history.url += test_directory
        self.recursion_manager.check_for_recursion(test_result)
        mock_notify.assert_called_once_with(test_result, f"/{test_directory}")
        self.assertEqual(self.recursion_manager.directories_queue.empty(), False)
        enqueued_directory: Payload = self.recursion_manager.directories_queue.get()
        self.assertIsInstance(enqueued_directory, Payload)
        self.assertEqual(enqueued_directory.final, test_directory)

    def test_fill_payloads_queue(self):
        FuzzMark.recursion_mark_index = 0
        test_directory = "test_directory/"
        test_payload = Payload().with_recursion(test_directory)
        self.recursion_manager.directories_queue.put(test_payload)
        self.recursion_manager.fill_payloads_queue()
        i = 0
        while not self.recursion_manager.payloads_queue.empty():
            this_payloads: Tuple[Payload] = self.recursion_manager.payloads_queue.get()
            self.assertEqual(this_payloads[0].final, f"{test_directory}{self.base_wordlist[i]}")
            i += 1
