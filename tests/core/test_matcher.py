import unittest
from unittest.mock import Mock, patch
import operator

from src.fuzzingtool.core.matcher import Matcher
from src.fuzzingtool.objects.result import Result, HttpHistory
from src.fuzzingtool.exceptions import BadArgumentType, BadArgumentFormat
from ..mock_utils.response_mock import ResponseMock


class TestMatcher(unittest.TestCase):
    def test_build_status_code_without_status(self):
        return_expected = {
            'is_default': True,
            'list': [200],
            'range': []
        }
        returned_status_code_dict = Matcher._Matcher__build_status_code(Matcher, None)
        self.assertIsInstance(returned_status_code_dict, dict)
        self.assertDictEqual(returned_status_code_dict, return_expected)

    def test_build_status_code_with_list_and_range(self):
        return_expected = {
            'is_default': False,
            'list': [401, 403],
            'range': [200, 399]
        }
        returned_status_code_dict = Matcher._Matcher__build_status_code(Matcher, "200-399,401,403")
        self.assertIsInstance(returned_status_code_dict, dict)
        self.assertDictEqual(returned_status_code_dict, return_expected)

    def test_build_status_code_with_inverted_range(self):
        return_expected = {
            'is_default': False,
            'list': [],
            'range': [200, 399]
        }
        returned_status_code_dict = Matcher._Matcher__build_status_code(Matcher, "399-200")
        self.assertIsInstance(returned_status_code_dict, dict)
        self.assertDictEqual(returned_status_code_dict, return_expected)

    def test_build_status_code_with_invalid_status_type(self):
        test_status = "200-399a"
        with self.assertRaises(BadArgumentType) as e:
            Matcher._Matcher__build_status_code(Matcher, test_status)
        self.assertEqual(str(e.exception), f"The match status argument ({test_status}) must be integer")

    def test_build_regexer_with_invalid_regex(self):
        test_regex = r"[a-z][A-Z]((?"
        with self.assertRaises(BadArgumentFormat) as e:
            Matcher(regex=test_regex)
        self.assertEqual(str(e.exception), f"Invalid regex format {test_regex} on Matcher")

    def test_get_comparator_and_callback_with_operator_ge(self):
        return_expected = ('25', operator.ge)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '>=25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_with_operator_le(self):
        return_expected = ('25', operator.le)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '<=25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_with_operator_gt(self):
        return_expected = ('25', operator.gt)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '>25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_with_operator_lt(self):
        return_expected = ('25', operator.lt)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '<25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_with_operator_eq(self):
        return_expected = ('25', operator.eq)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '==25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_with_operator_ne(self):
        return_expected = ('25', operator.ne)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '!=25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_comparator_and_callback_without_operator(self):
        return_expected = ('25', operator.gt)
        returned_data = Matcher._Matcher__get_comparator_and_callback(Matcher, '25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_instance_comparator(self):
        return_expected = (25, operator.gt)
        returned_data = Matcher()._Matcher__instance_comparator(int, None, '25')
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_instance_comparator_with_invalid_integer(self):
        test_name = "test_name"
        test_value = "25test"
        with self.assertRaises(BadArgumentType) as e:
            Matcher()._Matcher__instance_comparator(int, test_name, test_value)
        self.assertEqual(str(e.exception), f"The {test_name} comparator must be an integer, not '{test_value}'!")

    def test_instance_comparator_with_invalid_number(self):
        test_name = "test_name"
        test_value = "25test"
        with self.assertRaises(BadArgumentType) as e:
            Matcher()._Matcher__instance_comparator(float, test_name, test_value)
        self.assertEqual(str(e.exception), f"The {test_name} comparator must be a number, not '{test_value}'!")

    def test_build_comparator(self):
        return_expected = {
            'time': 15,
            'size': 1500,
            'words': 50,
            'lines': 100,
        }
        returned_comparator = Matcher(
            time="15",
            size=">1500",
            words="!=50",
            lines="<100"
        )._Matcher__build_comparator(
            time="15",
            size=">1500",
            words="!=50",
            lines="<100"
        )
        self.assertIsInstance(returned_comparator, dict)
        self.assertDictEqual(returned_comparator, return_expected)

    def test_comparator_is_set_with_set(self):
        return_expected = True
        returned_data = Matcher(size='55').comparator_is_set()
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_comparator_is_set_without_set(self):
        return_expected = False
        returned_data = Matcher().comparator_is_set()
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.core.matcher.Matcher._Matcher__build_status_code")
    def test_set_status_code(self, mock_build_status_code: Mock):
        test_status = "200"
        Matcher.set_status_code(Matcher, test_status)
        mock_build_status_code.assert_called_once_with(test_status)

    @patch("src.fuzzingtool.core.matcher.Matcher._Matcher__build_comparator")
    def test_set_comparator(self, mock_build_comparator: Mock):
        test_comparator = ('5', '', '', '')
        Matcher.set_comparator(Matcher, *test_comparator)
        mock_build_comparator.assert_called_once_with(*test_comparator)

    def test_match_with_match(self):
        return_expected = True
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_status_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="401",
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_time_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock(), rtt=3.0))
        returned_match_flag = Matcher(
            status_code="200",
            time=">4"
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_size_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
            size="<10",
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_words_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
            words=">10"
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_lines_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
            lines="!=2"
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_match_regex_without_match(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
            regex="Invalid test regex"
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)

    def test_not_match_with_two_configs(self):
        return_expected = False
        test_result = Result(HttpHistory(response=ResponseMock()))
        returned_match_flag = Matcher(
            status_code="200",
            words=">5",
            lines="==2"
        ).match(test_result)
        self.assertIsInstance(returned_match_flag, bool)
        self.assertEqual(returned_match_flag, return_expected)
