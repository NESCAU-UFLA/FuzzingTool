import unittest
from unittest.mock import Mock, patch, mock_open
from datetime import datetime
from pathlib import Path

from src.fuzzingtool.persistence.logger import Logger
from src.fuzzingtool.utils.consts import OUTPUT_DIRECTORY


class TestLogger(unittest.TestCase):
    def setUp(self):
        self.default_datetime = datetime(2021, 1, 1, 0, 0)
        self.test_host = "test-host.com"
        self.test_path = Path(f"{OUTPUT_DIRECTORY}/{self.test_host}")
        self.test_output = Path(f"{self.test_path}/logs/log-{self.default_datetime.strftime('%Y-%m-%d_%H:%M')}.log")

    @patch("src.fuzzingtool.persistence.logger.datetime")
    @patch("builtins.open", new_callable=mock_open)
    def test_setup(self, mock_file: Mock, mock_date: Mock):
        test_datetime_now = self.default_datetime.strftime('%Y/%m/%d %H:%M')
        text_to_write = f"Log for {self.test_host} on {test_datetime_now}\n\n"
        mock_date.now.return_value = self.default_datetime
        returned_data = Logger().setup(self.test_host)
        mock_file.assert_called_once_with(self.test_output, 'w+')
        mock_file().write.assert_called_once_with(text_to_write)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, str(self.test_output))

    @patch("src.fuzzingtool.persistence.logger.datetime")
    def test_setup_with_path_mkdir(self, mock_date: Mock):
        mock_date.now.return_value = self.default_datetime
        Logger().setup(self.test_host)
        self.assertEqual(self.test_path.exists(), True)
        self.assertEqual(self.test_output.is_file(), True)
        self.test_output.unlink()
        Path(f"{self.test_path}/logs").rmdir()
        self.test_path.rmdir()
        self.assertEqual(self.test_path.exists(), False)

    @patch("src.fuzzingtool.persistence.logger.datetime")
    @patch("builtins.open", new_callable=mock_open)
    def test_write(self, mock_file: Mock, mock_date: Mock):
        test_payload = "wp-admin.php"
        test_exception = f"Couldn't connect to http://{self.test_host}/{test_payload}"
        test_datetime_now = self.default_datetime.strftime("%H:%M:%S")
        text_to_write = f"{test_datetime_now} | {test_exception} using payload: {test_payload}\n"
        mock_date.now.return_value = self.default_datetime
        Logger().write(test_exception, test_payload)
        mock_file.assert_called_once_with('', 'a')
        mock_file().write.assert_called_once_with(text_to_write)
