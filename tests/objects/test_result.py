import unittest
from unittest.mock import Mock, patch
import datetime

from requests import PreparedRequest, Response

from fuzzingtool.objects import Payload, Result
from fuzzingtool.objects.base_objects import BaseItem


def prepare_response_mock():
    mock_request = Mock(spec=PreparedRequest)
    mock_request.method = "GET"
    mock_response = Mock(spec=Response)
    mock_response.url = "https://test-url.com/"
    mock_response.request = mock_request
    mock_response.elapsed = datetime.timedelta(seconds=2.0)
    mock_response.status_code = 200
    mock_response.content = b"My Body Text\nFooter Text\n"
    mock_response.text = "My Body Text\nFooter Text\n"
    return mock_response


class TestResult(unittest.TestCase):
    def setUp(self):
        self.test_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.19.0\r\n"
            "Date: Fri, 17 Dec 2021 17:42:14 GMT\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "X-Powered-By: PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1\r\n"
            "\r\n"
        )
        BaseItem.reset_index()

    def tearDown(self):
        BaseItem.reset_index()

    @patch("fuzzingtool.objects.result.build_raw_response_header")
    def test_result(self, mock_build_raw_response_header: Mock):
        test_response = prepare_response_mock()
        mock_build_raw_response_header.return_value = self.test_headers
        result = Result(
            response=test_response,
            rtt=3.0,
            payload=Payload('test-payload')
        )
        self.assertEqual(result.request_time, 1.0)
        self.assertEqual(result.headers_length, 228)
        self.assertEqual(result.body_length, 25)
        self.assertEqual(result.words, 5)
        self.assertEqual(result.lines, 2)
        self.assertEqual(result.get_response(), test_response)

    @patch("fuzzingtool.objects.result.build_raw_response_header")
    def test_result_iter(self, mock_build_raw_response_header: Mock):
        test_prefix = "test-prefix|"
        payload: Payload = Payload("test-payload").with_prefix(test_prefix)
        mock_build_raw_response_header.return_value = self.test_headers
        Result.save_payload_configs = True
        Result.save_headers = True
        Result.save_body = True
        result = Result(
            response=prepare_response_mock(),
            rtt=3.0,
            payload=payload
        )
        result.custom['test-key'] = "test-value"
        expected_result_dict = {
            'index': 1,
            'url': "https://test-url.com/",
            'method': "GET",
            'rtt': 3.0,
            'request_time': 1.0,
            'response_time': 2.0,
            'status': 200,
            'headers_length': 228,
            'body_length': 25,
            'words': 5,
            'lines': 2,
            'test-key': "test-value",
            'payload': payload.final,
            'payload_raw': payload.raw,
            'payload_prefix': test_prefix,
            'headers': self.test_headers,
            'body': "My Body Text\nFooter Text\n"
        }
        self.assertDictEqual(dict(result), expected_result_dict)
