import unittest
from unittest.mock import Mock, patch, mock_open

from fuzzingtool.utils.file_utils import read_file

BASE_FILE_CONTENT = "payload\n"
BASE_FILE_COMMENT = "#!"


class TestFileUtils(unittest.TestCase):
    @patch("builtins.open", new_callable=mock_open, read_data=BASE_FILE_CONTENT)
    def test_read_file(self, mock_file: Mock):
        file_full_path = "path/to/payload_file.txt"
        return_expected = ["payload"]
        self.assertEqual(open(file_full_path).read(), BASE_FILE_CONTENT)
        mock_file.assert_called_once_with(file_full_path)
        returned_data = read_file(file_full_path)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    @patch("builtins.open", new_callable=mock_open,
           read_data=BASE_FILE_COMMENT+BASE_FILE_CONTENT)
    def test_read_file_with_comment(self, mock_file: Mock):
        file_full_path = "path/to/payload_file.txt"
        return_expected = []
        self.assertEqual(open(file_full_path).read(), BASE_FILE_COMMENT+BASE_FILE_CONTENT)
        mock_file.assert_called_once_with(file_full_path)
        returned_data = read_file(file_full_path)
        self.assertIsInstance(returned_data, list)
        self.assertEqual(returned_data, return_expected)

    def test_read_file_exception(self):
        file_full_path = "path/to/not_found/payload_file.txt"
        with self.assertRaises(FileNotFoundError):
            read_file(file_full_path)
