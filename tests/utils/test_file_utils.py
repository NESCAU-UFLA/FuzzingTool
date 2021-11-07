import unittest
from unittest.mock import patch, mock_open

from src.fuzzingtool.utils.file_utils import *

BASE_FILE_CONTENT = "payload\n"

class TestFileUtils(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data=BASE_FILE_CONTENT)
    def test_read_file(self, mock_file):
        file_full_path = "path/to/payload_file.txt"
        return_expected = ["payload"]
        self.assertEqual(open(file_full_path).read(), BASE_FILE_CONTENT)
        mock_file.assert_called_with(file_full_path)
        mock_file.assert_called_once()
        returned_data = read_file(file_full_path)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
    
    def test_read_file_exception(self):
        file_full_path = "path/to/payload_file.txt"
        with self.assertRaises(Exception):
            read_file(file_full_path)

    def test_split_filenames(self):
        filenames = ["__init__.py", "DnsZone.py", "CrtSh.py", "Robots.py"]
        return_expected = ["DnsZone", "CrtSh", "Robots"]
        returned_data = split_filenames(filenames)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)
