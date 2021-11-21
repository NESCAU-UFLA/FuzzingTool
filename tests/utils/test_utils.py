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