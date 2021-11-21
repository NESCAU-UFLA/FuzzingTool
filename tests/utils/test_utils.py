import unittest
from unittest.mock import patch

from src.fuzzingtool.utils.utils import *
from src.fuzzingtool.utils.consts import FUZZING_MARK


class TestUtils(unittest.TestCase):
    def test_get_indexes_to_parse(self):
        # Test without mark
        return_expected = []
        test_content = "payload"
        returned_data = get_indexes_to_parse(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with only one mark
        return_expected = [2]
        test_content = f"pa{FUZZING_MARK}yload"
        returned_data = get_indexes_to_parse(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with two marks
        return_expected = [2, 8]
        test_content = f"pa{FUZZING_MARK}yload{FUZZING_MARK}"
        returned_data = get_indexes_to_parse(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_split_str_to_list(self):
        # Test with blank string
        return_expected = []
        test_content = ''
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test string without separator
        return_expected = ["payload"]
        test_content = "payload"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test string with only one separator
        return_expected = ["pay", "load"]
        test_content = "pay,load"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test string with two separators
        return_expected = ["pay", "load", '']
        test_content = "pay,load,"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test string with one separator and ignorer
        return_expected = ["pay,load"]
        test_content = "pay\\,load"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test string with two separators and one ignorer
        return_expected = ["pay,loa", 'd']
        test_content = "pay\\,loa,d"
        returned_data = split_str_to_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_stringfy_list(self):
        # Test with empty list
        return_expected = ''
        test_list = []
        returned_data = stringfy_list(test_list)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
        # Test with not empty list
        return_expected = 'one,two,3'
        test_list = ["one", "two", "3"]
        returned_data = stringfy_list(test_list)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_human_length(self):
        # Test with 0 bytes
        return_expected = (0, "B ")
        test_length = 0
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)
        # Test with 1025 bytes
        return_expected = (1.0009765625, "KB")
        test_length = 1025
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)
        # Test with 1 GB
        return_expected = (1, "GB")
        test_length = 1073741824  # Equals to 1 GB
        returned_data = get_human_length(test_length)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_check_range_list(self):
        # Test without range
        return_expected = ["payload"]
        test_content = "payload"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with ignore range
        return_expected = ["pay-load"]
        test_content = "pay\\-load"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with letter range
        return_expected = ['a', 'b', 'c', 'd']
        test_content = "a-d"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with number range
        return_expected = ['0', '1', '2', '3', '4', '5']
        test_content = "0-5"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with letter range inside text
        return_expected = ["payAload", "payBload", "payCload", "payDload"]
        test_content = "payA-Dload"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
        # Test with number range inside text
        return_expected = [
            "pay0load", "pay1load", "pay2load",
            "pay3load", "pay4load", "pay5load"
        ]
        test_content = "pay0-5load"
        returned_data = check_range_list(test_content)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
