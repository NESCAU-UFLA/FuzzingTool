import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.objects import Payload, Result, HttpHistory, ScannerResult
from src.fuzzingtool.objects.base_objects import BaseItem
from src.fuzzingtool.utils.result_utils import ResultUtils
from ..mock_utils.response_mock import ResponseMock


class TestResult(unittest.TestCase):
    def setUp(self):
        BaseItem.reset_index()

    def tearDown(self):
        BaseItem.reset_index()

    def test_result(self):
        test_response = ResponseMock()
        result = Result(
            history=HttpHistory(response=test_response, rtt=3.0),
            payload=Payload('test-payload')
        )
        self.assertEqual(result.words, 5)
        self.assertEqual(result.lines, 2)

    def test_get_description(self):
        test_job_description = "Enqueued new job from Test"
        result = Result(
            history=HttpHistory(response=ResponseMock(), rtt=3.0),
            payload=Payload('test-payload')
        )
        result.job_description = test_job_description
        test_scanner = "test-scanner"
        test_enqueued_payloads = 5
        result.scanners_res[test_scanner] = ScannerResult(test_scanner)
        result.scanners_res[test_scanner].data['test_0'] = None
        result.scanners_res[test_scanner].data['test_1'] = "test-value"
        result.scanners_res[test_scanner].enqueued_payloads = test_enqueued_payloads
        return_expected = (
            f"\n|_ {test_job_description}"
            f"\n|_ test_1: test-value"
            f"\n|_ Scanner {test_scanner} enqueued {test_enqueued_payloads} payloads"
        )
        returned_description = result.get_description()
        self.assertIsInstance(returned_description, str)
        self.assertEqual(returned_description, return_expected)

    def test_result_str(self):
        test_response = ResponseMock()
        result = Result(
            history=HttpHistory(response=test_response, rtt=3.0),
            payload=Payload('test-payload')
        )
        payload, rtt, length, words, lines = ResultUtils.get_formatted_result(
            result.payload, result.history.rtt, result.history.body_size,
            result.words, result.lines
        )
        return_expected = (
            f"{payload} ["
            f"Code {result.history.status} | "
            f"RTT {rtt} | "
            f"Size {length} | "
            f"Words {words} | "
            f"Lines {lines}]"
        )
        self.assertEqual(str(result), return_expected)

    def test_result_iter(self):
        test_prefix = "test-prefix|"
        payload: Payload = Payload("test-payload").with_prefix(test_prefix)
        Result.save_payload_configs = True
        Result.save_headers = True
        Result.save_body = True
        result = Result(
            history=HttpHistory(ResponseMock(), 3.0, '127.0.0.1'),
            payload=payload
        )
        test_scanner = "test-scanner"
        result.scanners_res[test_scanner] = ScannerResult(test_scanner)
        result.scanners_res[test_scanner].data['test-key'] = "test-value"
        expected_result_dict = {
            'index': result.index,
            'url': result.history.url,
            'method': result.history.method,
            'rtt': result.history.rtt,
            'request_time': result.history.request_time,
            'response_time': result.history.response_time,
            'status': result.history.status,
            'headers_length': result.history.headers_length,
            'body_size': result.history.body_size,
            'words': result.words,
            'lines': result.lines,
            'ip': result.history.ip,
            'test-key': "test-value",
            'payload': result.payload,
            'payload_raw': payload.raw,
            'payload_prefix': test_prefix,
            'headers': result.history.raw_headers,
            'body': result.history.response.text
        }
        self.assertDictEqual(dict(result), expected_result_dict)
