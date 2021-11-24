import unittest
from unittest.mock import Mock, patch, mock_open
from datetime import datetime
from pathlib import Path

from fuzzingtool.utils.logger import Logger
from fuzzingtool.utils.consts import OUTPUT_DIRECTORY


class TestLogger(unittest.TestCase):
    def setUp(self):
        self.logger = Logger()
        self.default_datetime = datetime(2021, 1, 1, 0, 0)
        self.test_host = "test-host.com"
        self.test_output = Path(f"{OUTPUT_DIRECTORY}/{self.test_host}/logs/log-{self.default_datetime.strftime('%Y-%m-%d_%H:%M')}.log")

    @patch("fuzzingtool.utils.logger.datetime")
    @patch("builtins.open", new_callable=mock_open)
    def test_setup(self, mock_file: Mock, mock_date: Mock):
        test_datetime_now = self.default_datetime.strftime('%Y/%m/%d %H:%M')
        text_to_write = f"Log for {self.test_host} on {test_datetime_now}\n\n"
        mock_date.now.return_value = self.default_datetime
        returned_data = self.logger.setup(self.test_host)
        mock_file.assert_called_once_with(self.test_output, 'w+')
        mock_file().write.assert_called_once_with(text_to_write)
        self.assertIsInstance(returned_data, Path)
        self.assertEqual(returned_data, self.test_output)

    @patch("fuzzingtool.utils.logger.datetime")
    @patch("builtins.open", new_callable=mock_open)
    def test_write(self, mock_file: Mock, mock_date: Mock):
        test_payload = "wp-admin.php"
        test_exception = f"Couldn't connect to http://{self.test_host}/{test_payload}"
        test_datetime_now = self.default_datetime.strftime("%H:%M:%S")
        text_to_write = f"{test_datetime_now} | {test_exception} using payload: {test_payload}\n"
        mock_date.now.return_value = self.default_datetime
        self.logger.write(test_exception, test_payload)
        mock_file.assert_called_once_with('', 'a')
        mock_file().write.assert_called_once_with(text_to_write)
