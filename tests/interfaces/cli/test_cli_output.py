import unittest
from unittest.mock import Mock, patch
from datetime import datetime

from src.fuzzingtool.interfaces.cli.cli_output import Colors, CliOutput
from src.fuzzingtool.objects import Payload, Result, HttpHistory
from src.fuzzingtool.utils.consts import FuzzType
from ...mock_utils.response_mock import ResponseMock


class TestCliOutput(unittest.TestCase):
    @patch("src.fuzzingtool.interfaces.cli.cli_output.datetime")
    def test_get_time(self, mock_datetime: Mock):
        test_datetime_now = datetime(2021, 1, 1, 0, 0)
        mock_datetime.now.return_value = test_datetime_now
        expected_time = test_datetime_now.strftime("%H:%M:%S")
        return_expected = (f'{Colors.GRAY}[{Colors.LIGHT_GREEN}{expected_time}'
                           f'{Colors.GRAY}]{Colors.RESET} ')
        returned_time = CliOutput()._CliOutput__get_time()
        self.assertIsInstance(returned_time, str)
        self.assertEqual(returned_time, return_expected)

    def test_get_info(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__info}{test_message}"
        returned_msg = cli_output._CliOutput__get_info(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_warning(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__warning}{test_message}"
        returned_msg = cli_output._CliOutput__get_warning(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_error(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__error}{test_message}"
        returned_msg = cli_output._CliOutput__get_error(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_abort(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__abort}{test_message}"
        returned_msg = cli_output._CliOutput__get_abort(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_worked(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__worked}{test_message}"
        returned_msg = cli_output._CliOutput__get_worked(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_not_worked(self):
        test_message = "test-message"
        cli_output = CliOutput()
        return_expected = f"{cli_output._CliOutput__not_worked}{Colors.LIGHT_GRAY}{test_message}{Colors.RESET}"
        returned_msg = cli_output._CliOutput__get_not_worked(test_message)
        self.assertIsInstance(returned_msg, str)
        self.assertEqual(returned_msg, return_expected)

    def test_get_formatted_payload(self):
        test_result = Result(
            HttpHistory(response=ResponseMock()),
            payload=Payload("test-payload"),
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.payload)

    def test_get_formatted_payload_with_path_fuzz(self):
        test_result = Result(
            HttpHistory(response=ResponseMock()),
            fuzz_type=FuzzType.PATH_FUZZING,
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.history.parsed_url.path)

    def test_get_formatted_payload_with_path_fuzz_without_directory(self):
        test_result = Result(
            HttpHistory(response=ResponseMock()),
            fuzz_type=FuzzType.PATH_FUZZING,
        )
        test_result.history.url = "http://test-url.com"
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.history.url)

    def test_get_formatted_payload_with_subdomain_fuzz(self):
        test_result = Result(
            HttpHistory(response=ResponseMock()),
            fuzz_type=FuzzType.SUBDOMAIN_FUZZING,
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.history.parsed_url.hostname)

    def test_get_formatted_status_with_status_404(self):
        test_status = 404
        expected_color = ''
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    def test_get_formatted_status_with_status_200(self):
        test_status = 200
        expected_color = f"{Colors.BOLD}{Colors.GREEN}"
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    def test_get_formatted_status_with_status_300(self):
        test_status = 300
        expected_color = f"{Colors.BOLD}{Colors.LIGHT_YELLOW}"
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    def test_get_formatted_status_with_status_400(self):
        test_status = 400
        expected_color = f"{Colors.BOLD}{Colors.BLUE}"
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    def test_get_formatted_status_with_status_403(self):
        test_status = 403
        expected_color = f"{Colors.BOLD}{Colors.CYAN}"
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    def test_get_formatted_status_with_status_500(self):
        test_status = 500
        expected_color = f"{Colors.BOLD}{Colors.RED}"
        return_expected = f"{expected_color}{test_status}{Colors.RESET}"
        returned_status = CliOutput()._CliOutput__get_formatted_status(test_status)
        self.assertIsInstance(returned_status, str)
        self.assertEqual(returned_status, return_expected)

    @patch("src.fuzzingtool.interfaces.cli.cli_output.CliOutput._CliOutput__get_formatted_status")
    @patch("src.fuzzingtool.interfaces.cli.cli_output.ResultUtils.get_formatted_result")
    def test_get_formatted_result_items(self, mock_format_result: Mock, mock_format_status: Mock):
        test_result = Result(
            HttpHistory(response=ResponseMock()),
            payload=Payload("test-payload")
        )
        expected_status = "test_status"
        mock_format_status.return_value = expected_status
        return_expected = ('', expected_status, '', '', '', '')
        mock_format_result.return_value = ('', '', '', '', '')
        cli_output = CliOutput()
        returned_items = cli_output._CliOutput__get_formatted_result_items(test_result)
        mock_format_status.assert_called_once_with(test_result.history.status)
        mock_format_result.assert_called_once_with(
            cli_output._CliOutput__get_formatted_payload(test_result),
            test_result.history.rtt,
            test_result.history.body_size,
            test_result.words,
            test_result.lines
        )
        self.assertIsInstance(returned_items, tuple)
        self.assertEqual(returned_items, return_expected)

    @patch("src.fuzzingtool.interfaces.cli.cli_output.CliOutput._CliOutput__get_formatted_result_items")
    def test_get_formatted_result(self, mock_format_items: Mock):
        test_payload = "test_payload"
        test_status_code = "200"
        test_rtt = "300 ms"
        test_length = "50 KB"
        test_words = "50"
        test_lines = "10"
        mock_format_items.return_value = (
            test_payload,
            test_status_code,
            test_rtt,
            test_length,
            test_words,
            test_lines
        )
        test_result = Result(HttpHistory(response=ResponseMock()))
        return_expected = (
            f"{test_payload} {Colors.GRAY}["
            f"{Colors.LIGHT_GRAY}Code{Colors.RESET} {test_status_code} | "
            f"{Colors.LIGHT_GRAY}RTT{Colors.RESET} {test_rtt} | "
            f"{Colors.LIGHT_GRAY}Size{Colors.RESET} {test_length} | "
            f"{Colors.LIGHT_GRAY}Words{Colors.RESET} {test_words} | "
            f"{Colors.LIGHT_GRAY}Lines{Colors.RESET} {test_lines}{Colors.GRAY}]{Colors.RESET}"
            f"{Colors.LIGHT_YELLOW}{test_result.get_description()}{Colors.RESET}"
        )
        returned_data = CliOutput()._CliOutput__get_formatted_result(test_result)
        mock_format_items.assert_called_once_with(test_result)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
