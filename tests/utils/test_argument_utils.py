import unittest
from unittest.mock import patch, Mock

from src.fuzzingtool.utils.argument_utils import *


class TestArgumentUtils(unittest.TestCase):
    def test_build_target_from_args(self):
        test_url = "http://test-url.com/"
        test_method = "HEAD"
        test_body = "user=test&pass=test"
        return_expected = {
            'url': test_url,
            'method': "HEAD",
            'body': test_body,
            'header': {},
        }
        returned_target = build_target_from_args(test_url, test_method, test_body)
        self.assertIsInstance(returned_target, dict)
        self.assertDictEqual(returned_target, return_expected)

    def test_build_target_from_args_without_method_and_without_body(self):
        test_url = "http://test-url.com/"
        test_method = ''
        test_body = ''
        return_expected = {
            'url': test_url,
            'method': "GET",
            'body': test_body,
            'header': {},
        }
        returned_target = build_target_from_args(test_url, test_method, test_body)
        self.assertIsInstance(returned_target, dict)
        self.assertDictEqual(returned_target, return_expected)

    def test_build_target_from_args_without_method_and_with_body(self):
        test_url = "http://test-url.com/"
        test_method = ''
        test_body = "user=test&pass=test"
        return_expected = {
            'url': test_url,
            'method': "POST",
            'body': test_body,
            'header': {},
        }
        returned_target = build_target_from_args(test_url, test_method, test_body)
        self.assertIsInstance(returned_target, dict)
        self.assertDictEqual(returned_target, return_expected)

    @patch("src.fuzzingtool.utils.argument_utils.read_file")
    def test_build_target_from_raw_http(self, mock_read_file: Mock):
        expected_header = {
            'Host': "test-url.com",
            'User-Agent': "Test User Agent",
            'Cookie': "TESTSESSID=testcookie"
        }
        test_scheme = "https"
        return_expected = {
            'url': f"{test_scheme}://test-url.com/",
            'method': "GET",
            'body': '',
            'header': expected_header,
        }
        test_filename = "test-raw-http.txt"
        mock_read_file.return_value = [
            "GET / HTTP/1.1",
            "Host: test-url.com",
            "User-Agent: Test User Agent",
            "Cookie: TESTSESSID=testcookie"
        ]
        returned_target = build_target_from_raw_http(test_filename, test_scheme)
        self.assertIsInstance(returned_target, dict)
        self.assertDictEqual(returned_target, return_expected)

    @patch("src.fuzzingtool.utils.argument_utils.read_file")
    def test_build_target_from_raw_http_with_body(self, mock_read_file: Mock):
        expected_header = {
            'Host': "test-url.com",
            'User-Agent': "Test User Agent",
            'Cookie': "TESTSESSID=testcookie"
        }
        test_scheme = "https"
        test_body = "user=test&pass=test"
        return_expected = {
            'url': f"{test_scheme}://test-url.com/",
            'method': "POST",
            'body': test_body,
            'header': expected_header,
        }
        test_filename = "test-raw-http.txt"
        mock_read_file.return_value = [
            "POST / HTTP/1.1",
            "Host: test-url.com",
            "User-Agent: Test User Agent",
            "Cookie: TESTSESSID=testcookie",
            '',
            test_body
        ]
        returned_target = build_target_from_raw_http(test_filename, test_scheme)
        self.assertIsInstance(returned_target, dict)
        self.assertDictEqual(returned_target, return_expected)

    def test_build_wordlist(self):
        return_expected = [('DnsZone', ''), ('Robots', 'http://test-url.com/')]
        returned_wordlist = build_wordlist('DnsZone;Robots=http://test-url.com/')
        self.assertIsInstance(returned_wordlist, list)
        self.assertEqual(returned_wordlist, return_expected)

    def test_build_encoder(self):
        return_expected = [[('Plain', '')], [('Url', '5'), ('Hex', '')]]
        returned_encoders = build_encoder('Plain,Url=5@Hex')
        self.assertIsInstance(returned_encoders, list)
        self.assertEqual(returned_encoders, return_expected)

    def test_build_scanner(self):
        return_expected = ('Grep', 'email')
        returned_scanner = build_scanner('Grep=email')
        self.assertIsInstance(returned_scanner, tuple)
        self.assertEqual(returned_scanner, return_expected)

    def test_build_verbose_mode_without_verbose(self):
        return_expected = [False, False]
        returned_verbose = build_verbose_mode(False, False)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_verbose_mode_with_common_verbose(self):
        return_expected = [True, False]
        returned_verbose = build_verbose_mode(True, False)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_verbose_mode_with_detailed_verbose(self):
        return_expected = [True, True]
        returned_verbose = build_verbose_mode(False, True)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_blacklist_status_without_action(self):
        return_expected = ('429', 'stop', '')
        returned_blacklist = build_blacklist_status('429')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)

    def test_build_blacklist_status_with_action(self):
        return_expected = ('429', 'stop', '')
        returned_blacklist = build_blacklist_status('429:stop')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)

    def test_build_blacklist_status_with_action_and_param(self):
        return_expected = ('429', 'wait', '5')
        returned_blacklist = build_blacklist_status('429:wait=5')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)
