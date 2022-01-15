import unittest

from src.fuzzingtool.exceptions.request_exceptions import RequestException
from src.fuzzingtool.objects import Error, Payload
from src.fuzzingtool.objects.base_objects import BaseItem


class TestError(unittest.TestCase):
    def setUp(self):
        BaseItem.reset_index()

    def tearDown(self):
        BaseItem.reset_index()

    def test_error(self):
        test_exception_test = "Test Exception Text"
        test_exception = RequestException(test_exception_test)
        test_payload = Payload("test-payload")
        error = Error(test_exception, test_payload)
        self.assertEqual(str(error), test_exception_test)
