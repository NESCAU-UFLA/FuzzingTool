import unittest

from src.fuzzingtool.core.filter import Filter
from src.fuzzingtool.objects.result import Result, HttpHistory
from src.fuzzingtool.exceptions import BadArgumentType, BadArgumentFormat
from ..mock_utils.response_mock import ResponseMock


class TestFilter(unittest.TestCase):
    def test_build_status_codes(self):
        return_expected = [404, 500]
        test_status = "404,500"
        returned_status_code = Filter._Filter__build_status_codes(Filter, test_status)
        self.assertIsInstance(returned_status_code, list)
        self.assertEqual(returned_status_code, return_expected)

    def test_build_status_codes_with_invalid_status_type(self):
        test_status = "404a"
        with self.assertRaises(BadArgumentType) as e:
            Filter._Filter__build_status_codes(Filter, test_status)
        self.assertEqual(str(e.exception), f"The filter status argument ({test_status}) must be integer")

    def test_build_regexer_with_invalid_regex(self):
        test_regex = r"[a-z][A-Z]((?"
        with self.assertRaises(BadArgumentFormat) as e:
            Filter(regex=test_regex)
        self.assertEqual(str(e.exception), f"Invalid regex format {test_regex} on Filter")

    def test_check_with_found_status(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        test_result.history.status = 404
        returned_check_flag = Filter(
            status_code="404",
        ).check(test_result)
        self.assertIsInstance(returned_check_flag, bool)
        self.assertEqual(returned_check_flag, return_expected)

    def test_check_with_found_regex(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_check_flag = Filter(
            regex=r"[a-z][A-Z]",
        ).check(test_result)
        self.assertIsInstance(returned_check_flag, bool)
        self.assertEqual(returned_check_flag, return_expected)

    def test_check_with_not_found(self):
        return_expected = True
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_check_flag = Filter(
            status_code="500",
        ).check(test_result)
        self.assertIsInstance(returned_check_flag, bool)
        self.assertEqual(returned_check_flag, return_expected)
