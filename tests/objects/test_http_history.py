import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.objects.http_history import HttpHistory
from src.fuzzingtool.utils.http_utils import UrlParse
from ..mock_utils.response_mock import ResponseMock


class TestHttpHistory(unittest.TestCase):
    def test_http_history(self):
        test_response = ResponseMock()
        test_history = HttpHistory(
            response=test_response,
            rtt=3.0
        )
        self.assertIsInstance(test_history.parsed_url, UrlParse)
        self.assertEqual(test_history.body_size, 25)
        self.assertEqual(test_history.response_time, 2.0)
        self.assertEqual(test_history.request_time, 1.0)
        self.assertEqual(test_history.request, test_response.request)
        self.assertEqual(test_history.response, test_response)

    @patch("src.fuzzingtool.objects.http_history.build_raw_response_header")
    def test_headers(self, mock_build_raw_response_header: Mock):
        test_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.19.0\r\n"
            "Date: Fri, 17 Dec 2021 17:42:14 GMT\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "X-Powered-By: PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1\r\n"
            "\r\n"
        )
        mock_build_raw_response_header.return_value = test_headers
        test_response = ResponseMock()
        test_history = HttpHistory(
            response=test_response,
            rtt=3.0
        )
        self.assertEqual(test_history.raw_headers, test_headers)
        self.assertEqual(test_history.headers_length, 228)
