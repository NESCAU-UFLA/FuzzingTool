import unittest
from unittest.mock import Mock, patch

import requests

from src.fuzzingtool.conn.requesters.requester import Requester
from src.fuzzingtool.objects.fuzz_word import FuzzWord
from src.fuzzingtool.utils.consts import (FUZZING_MARK, UNKNOWN_FUZZING, HTTP_METHOD_FUZZING,
                                      PATH_FUZZING, DATA_FUZZING)
from src.fuzzingtool.exceptions.request_exceptions import RequestException


class TestRequester(unittest.TestCase):
    def test_get_url(self):
        return_expected = "https://test-url.com/"
        test_url = "https://test-url.com/"
        returned_data = Requester(test_url).get_url()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_set_method(self):
        test_method = "GET"
        requester = Requester("https://test-url.com/")
        requester.set_method(test_method)
        returned_data = requester._Requester__method
        self.assertIsInstance(returned_data, FuzzWord)
        self.assertEqual(returned_data.word, test_method)

    def test_set_body(self):
        test_body = "test=1&other=2"
        return_expected = {
            FuzzWord('test'): FuzzWord('1'),
            FuzzWord('other'): FuzzWord('2')
        }
        requester = Requester("https://test-url.com/")
        requester.set_body(test_body)
        returned_data = requester._Requester__body
        self.assertDictEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.conn.requesters.requester.requests.get")
    def test_test_connection_with_raise_exception(self, mock_get: Mock):
        requester = Requester("https://test-url.com/")
        mock_get.side_effect = requests.exceptions.ProxyError
        with self.assertRaises(RequestException):
            requester.test_connection()
        mock_get.side_effect = requests.exceptions.SSLError
        with self.assertRaises(RequestException):
            requester.test_connection()
        mock_get.side_effect = requests.exceptions.Timeout
        with self.assertRaises(RequestException):
            requester.test_connection()
        mock_get.side_effect = requests.exceptions.InvalidHeader("Cookie: TEST_TEST")
        with self.assertRaises(RequestException):
            requester.test_connection()
        mock_get.side_effect = requests.exceptions.ConnectionError
        with self.assertRaises(RequestException):
            requester.test_connection()
        mock_get.side_effect = requests.exceptions.RequestException
        with self.assertRaises(RequestException):
            requester.test_connection()

    def test_set_fuzzing_type_for_method_fuzzing(self):
        return_expected = HTTP_METHOD_FUZZING
        test_method = FUZZING_MARK
        requester = Requester("https://test-url.com/", method=test_method)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(requester.is_method_fuzzing(), True)

    def test_set_fuzzing_type_for_path_fuzzing(self):
        return_expected = PATH_FUZZING
        test_url = f"https://test-url.com/{FUZZING_MARK}"
        requester = Requester(test_url)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(requester.is_path_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_url_params(self):
        return_expected = DATA_FUZZING
        test_url = f"https://test-url.com/?q={FUZZING_MARK}"
        requester = Requester(test_url)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_body(self):
        return_expected = DATA_FUZZING
        test_body = f"user={FUZZING_MARK}&pass={FUZZING_MARK}"
        requester = Requester("https://test-url.com/", body=test_body)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_headers(self):
        return_expected = DATA_FUZZING
        test_header = {
            'Cookie': f"TESTSESSID={FUZZING_MARK}"
        }
        requester = Requester("https://test-url.com/", headers=test_header)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_unknown_fuzzing(self):
        return_expected = UNKNOWN_FUZZING
        returned_data = Requester("https://test-url.com/")._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)

    def test_setup_url(self):
        expected_url = "https://test-url.com/"
        expected_params = ''
        test_url = "https://test-url.com/"
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        returned_url, returned_params = returned_data
        self.assertIsInstance(returned_url, FuzzWord)
        self.assertIsInstance(returned_params, str)
        self.assertEqual(returned_url.word, expected_url)
        self.assertEqual(returned_params, expected_params)

    def test_setup_url_without_scheme(self):
        expected_url = "http://test-url.com/"
        expected_params = ''
        test_url = "test-url.com/"
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        returned_url, returned_params = returned_data
        self.assertIsInstance(returned_url, FuzzWord)
        self.assertIsInstance(returned_params, str)
        self.assertEqual(returned_url.word, expected_url)
        self.assertEqual(returned_params, expected_params)

    def test_setup_url_without_directory(self):
        expected_url = "http://test-url.com/"
        expected_params = ''
        test_url = "http://test-url.com"
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        returned_url, returned_params = returned_data
        self.assertIsInstance(returned_url, FuzzWord)
        self.assertIsInstance(returned_params, str)
        self.assertEqual(returned_url.word, expected_url)
        self.assertEqual(returned_params, expected_params)

    def test_setup_url_with_params(self):
        expected_url = "http://test-url.com/"
        expected_params = "id=1"
        test_url = "http://test-url.com/?id=1"
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        returned_url, returned_params = returned_data
        self.assertIsInstance(returned_url, FuzzWord)
        self.assertIsInstance(returned_params, str)
        self.assertEqual(returned_url.word, expected_url)
        self.assertEqual(returned_params, expected_params)

    def test_build_data_dict_with_blank_data(self):
        test_data = ''
        return_expected = {}
        returned_data = Requester._Requester__build_data_dict(Requester, test_data)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)

    def test_build_data_dict_with_key_and_without_value(self):
        test_data = 'test'
        return_expected = {
            FuzzWord(test_data): FuzzWord()
        }
        returned_data = Requester._Requester__build_data_dict(Requester, test_data)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(len(returned_data), 1)
        self.assertIsInstance(returned_data['test'], FuzzWord)
        self.assertDictEqual(returned_data, return_expected)

    def test_build_data_dict_with_key_and_value(self):
        test_data = 'test=1'
        return_expected = {
            FuzzWord('test'): FuzzWord('1')
        }
        returned_data = Requester._Requester__build_data_dict(Requester, test_data)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(len(returned_data), 1)
        self.assertIsInstance(returned_data['test'], FuzzWord)
        self.assertDictEqual(returned_data, return_expected)

    def test_build_data_dict_with_multiple_key_and_value(self):
        test_data = 'test=1&othertest=2'
        return_expected = {
            FuzzWord('test'): FuzzWord('1'),
            FuzzWord('othertest'): FuzzWord('2')
        }
        returned_data = Requester._Requester__build_data_dict(Requester, test_data)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(len(returned_data), 2)
        self.assertIsInstance(returned_data['test'], FuzzWord)
        self.assertIsInstance(returned_data['othertest'], FuzzWord)
        self.assertDictEqual(returned_data, return_expected)

    def test_setup_header_with_blank_header(self):
        test_header = {}
        return_expected = {
            'User-Agent': FuzzWord('FuzzingTool Requester Agent'),
            'Accept-Encoding': FuzzWord('gzip, deflate')
        }
        returned_data = Requester._Requester__setup_header(Requester, test_header)
        self.assertIsInstance(returned_data, dict)
        self.assertIsInstance(returned_data['User-Agent'], FuzzWord)
        self.assertIsInstance(returned_data['Accept-Encoding'], FuzzWord)
        self.assertDictEqual(returned_data, return_expected)

    def test_setup_header_with_filled_header(self):
        test_header = {
            'User-Agent': 'Test User Agent',
            'Content-Length': '21'
        }
        return_expected = {
            'User-Agent': FuzzWord('Test User Agent'),
            'Accept-Encoding': FuzzWord('gzip, deflate')
        }
        returned_data = Requester._Requester__setup_header(Requester, test_header)
        self.assertIsInstance(returned_data, dict)
        self.assertIsInstance(returned_data['User-Agent'], FuzzWord)
        self.assertIsInstance(returned_data['Accept-Encoding'], FuzzWord)
        self.assertEqual(('Content-Length' in returned_data.keys()), False)
        self.assertDictEqual(returned_data, return_expected)

    def test_setup_proxy(self):
        test_proxy = "127.0.0.1:443"
        return_expected = {
            'http': f"http://{test_proxy}",
            'https': f"https://{test_proxy}"
        }
        returned_data = Requester._Requester__setup_proxy(Requester, test_proxy)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)

    def test_get_request_parameters(self):
        test_payload = ''
        returned_data = Requester("https://test-url.com/")._Requester__get_request_parameters(test_payload)
        returned_method, returned_url, returned_body, returned_url_params, returned_header = returned_data
        self.assertIsInstance(returned_method, str)
        self.assertIsInstance(returned_url, str)
        self.assertIsInstance(returned_body, dict)
        self.assertIsInstance(returned_url_params, dict)
        self.assertIsInstance(returned_header, dict)
