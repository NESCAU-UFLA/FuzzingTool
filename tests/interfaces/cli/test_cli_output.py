import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.interfaces.cli.cli_output import Colors, CliOutput
from src.fuzzingtool.objects import Payload, Result
from src.fuzzingtool.utils.consts import PATH_FUZZING, SUBDOMAIN_FUZZING
from src.fuzzingtool.utils.http_utils import get_host, get_path
from ...mock_utils.response_mock import ResponseMock


class TestCliOutput(unittest.TestCase):
    def test_get_formatted_payload(self):
        test_result = Result(
            response=ResponseMock(),
            payload=Payload("test-payload"),
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.payload)

    def test_get_formatted_payload_with_path_fuzz(self):
        test_result = Result(
            response=ResponseMock(),
            fuzz_type=PATH_FUZZING,
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, get_path(test_result.url))

    @patch("src.fuzzingtool.interfaces.cli.cli_output.get_path")
    def test_get_formatted_payload_with_path_fuzz_and_raise_exception(self, mock_get_path: Mock):
        test_result = Result(
            response=ResponseMock(),
            fuzz_type=PATH_FUZZING,
        )
        mock_get_path.side_effect = ValueError
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, test_result.url)

    def test_get_formatted_payload_with_path_fuzz(self):
        test_result = Result(
            response=ResponseMock(),
            fuzz_type=SUBDOMAIN_FUZZING,
        )
        returned_payload = CliOutput()._CliOutput__get_formatted_payload(test_result)
        self.assertIsInstance(returned_payload, str)
        self.assertEqual(returned_payload, get_host(test_result.url))

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
            response=ResponseMock(),
            payload=Payload("test-payload")
        )
        expected_status = "test_status"
        mock_format_status.return_value = expected_status
        return_expected = ('', expected_status, '', '', '', '')
        mock_format_result.return_value = ('', '', '', '', '')
        cli_output = CliOutput()
        returned_items = cli_output._CliOutput__get_formatted_result_items(test_result)
        mock_format_status.assert_called_once_with(test_result.status)
        mock_format_result.assert_called_once_with(
            cli_output._CliOutput__get_formatted_payload(test_result),
            test_result.rtt,
            test_result.body_size,
            test_result.words,
            test_result.lines
        )
        self.assertIsInstance(returned_items, tuple)
        self.assertEqual(returned_items, return_expected)
