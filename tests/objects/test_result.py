import unittest
from unittest.mock import Mock
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
    return mock_response


class TestResult(unittest.TestCase):
    def setUp(self):
        BaseItem.reset_index()

    def tearDown(self):
        BaseItem.reset_index()

    def test_result(self):
        test_response = prepare_response_mock()
        result = Result(
            response=test_response,
            rtt=3.0,
            payload=Payload('test-payload')
        )
        self.assertEqual(result.request_time, 1.0)
        self.assertEqual(result.length, 25)
        self.assertEqual(result.words, 5)
        self.assertEqual(result.lines, 2)
        self.assertEqual(result.get_response(), test_response)

    def test_result_iter(self):
        test_prefix = "test-prefix|"
        payload: Payload = Payload("test-payload").with_prefix(test_prefix)
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
            'length': 25,
            'words': 5,
            'lines': 2,
            'test-key': "test-value",
            'payload': payload.final,
            'payload_raw': payload.raw,
            'payload_prefix': test_prefix
        }
        self.assertDictEqual(dict(result), expected_result_dict)
