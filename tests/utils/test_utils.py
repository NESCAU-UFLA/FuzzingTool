import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.utils.utils import *
from src.fuzzingtool.utils.utils import _get_letter_range, _get_number_range
from src.fuzzingtool.utils.consts import MAX_PAYLOAD_LENGTH_TO_OUTPUT


class TestUtils(unittest.TestCase):
    def test_split_str_to_list_with_blank_string(self):
        return_expected = []
        test_content = ''
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_without_separator(self):
        return_expected = ["payload"]
        test_content = "payload"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_with_one_separator(self):
        return_expected = ["pay", "load"]
        test_content = "pay,load"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_with_two_separators(self):
        return_expected = ["pay", "load", '']
        test_content = "pay,load,"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_with_one_separator_and_ignorer(self):
        return_expected = ["pay,load"]
        test_content = "pay\\,load"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_with_two_separators_and_ignorer(self):
        return_expected = ["pay,loa", 'd']
        test_content = "pay\\,loa,d"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list_with_one_separator_and_ignorer_with_blank_result(self):
        return_expected = ["pay,loa", 'd', '']
        test_content = "pay\\,loa,d,"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_stringfy_list_with_empty_list(self):
        return_expected = ''
        test_list = []
        returned_data = stringfy_list(test_list)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_stringfy_list_with_filled_list(self):
        return_expected = 'one,two,3'
        test_list = ["one", "two", "3"]
        returned_data = stringfy_list(test_list)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_human_length_with_zero_bytes(self):
        return_expected = (0, "B ")
        test_length = 0
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_human_length_with_float_return(self):
        return_expected = (1.0009765625, "KB")
        test_length = 1025
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_human_length_with_one_tb(self):
        return_expected = (1, "TB")
        test_length = 1099511627776  # Equals to 1 TB
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_rtt_with_milliseconds(self):
        return_expected = (525, "ms")
        test_rtt = 0.525428
        returned_data = get_formatted_rtt(test_rtt)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_rtt_with_seconds(self):
        return_expected = (5.25428, "s ")
        test_rtt = 5.254280
        returned_data = get_formatted_rtt(test_rtt)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_rtt_with_minutes(self):
        return_expected = (2, "m ")
        test_rtt = 120.000000
        returned_data = get_formatted_rtt(test_rtt)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_rtt_with_hour(self):
        return_expected = (1, "h ")
        test_rtt = 3600.000000
        returned_data = get_formatted_rtt(test_rtt)
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_fix_payload_to_output_with_tab(self):
        return_expected = "tes t"
        returned_payload = fix_payload_to_output("tes	t")
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, return_expected)

    def test_fix_payload_to_output_with_large_payload(self):
        return_expected = 'a' * (MAX_PAYLOAD_LENGTH_TO_OUTPUT-3) + '...'
        returned_payload = fix_payload_to_output(('a' * MAX_PAYLOAD_LENGTH_TO_OUTPUT + '!'))
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, return_expected)

    def test_get_letter_range(self):
        return_expected = ['a', 'b', 'c', 'd']
        test_content = ('a', 'd')
        returned_data = _get_letter_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_letter_range_reversed(self):
        return_expected = ['d', 'c', 'b', 'a']
        test_content = ('d', 'a')
        returned_data = _get_letter_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_letter_range_inside_text(self):
        return_expected = ["payAload", "payBload", "payCload", "payDload"]
        test_content = ("payA", "Dload")
        returned_data = _get_letter_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_number_range(self):
        return_expected = ['10', '11', '12', '13', '14', '15']
        test_content = ('10', '15')
        returned_data = _get_number_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_number_range_reversed(self):
        return_expected = ['5', '4', '3', '2', '1', '0']
        test_content = ('5', '0')
        returned_data = _get_number_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_get_number_range_inside_text(self):
        return_expected = [
            "pay0load", "pay1load", "pay2load",
            "pay3load", "pay4load", "pay5load"
        ]
        test_content = ("pay0", "5load")
        returned_data = _get_number_range(*test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_check_range_list_without_range(self):
        return_expected = ["payload"]
        test_content = "payload"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_check_range_list_with_range_ignorer(self):
        return_expected = ["pay-load"]
        test_content = "pay\\-load"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_check_range_list_with_invalid_range(self):
        return_expected = ["pay-"]
        test_content = "pay-"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.utils.utils._get_letter_range")
    def test_check_range_list_with_letter_range(self, mock_get_letter_range: Mock):
        return_expected = ['a', 'b', 'c', 'd']
        test_content = "a-d"
        mock_get_letter_range.return_value = return_expected
        returned_data = check_range_list(test_content)
        mock_get_letter_range.assert_called_once_with('a', 'd')
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.utils.utils._get_letter_range")
    def test_check_range_list_with_letter_range_inside_text(self,
                                                            mock_get_letter_range: Mock):
        return_expected = ["payAload", "payBload", "payCload", "payDload"]
        test_content = "payA-Dload"
        mock_get_letter_range.return_value = return_expected
        returned_data = check_range_list(test_content)
        mock_get_letter_range.assert_called_once_with("payA", "Dload")
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.utils.utils._get_number_range")
    def test_check_range_list_with_number_range(self, mock_get_number_range: Mock):
        return_expected = ['0', '1', '2', '3', '4', '5']
        test_content = "0-5"
        mock_get_number_range.return_value = return_expected
        returned_data = check_range_list(test_content)
        mock_get_number_range.assert_called_once_with('0', '5')
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.utils.utils._get_number_range")
    def test_check_range_list_with_number_range_inside_text(self,
                                                            mock_get_number_range: Mock):
        return_expected = [
            "pay0load", "pay1load", "pay2load",
            "pay3load", "pay4load", "pay5load"
        ]
        test_content = "pay0-5load"
        mock_get_number_range.return_value = return_expected
        returned_data = check_range_list(test_content)
        mock_get_number_range.assert_called_once_with("pay0", "5load")
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
