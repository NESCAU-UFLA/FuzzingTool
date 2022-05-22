from unittest.mock import Mock, patch

import requests

from src.fuzzingtool.conn.requesters.requester import Requester
from src.fuzzingtool.objects.fuzz_word import FuzzWord
from src.fuzzingtool.utils.consts import FuzzType
from src.fuzzingtool.exceptions.request_exceptions import RequestException
from src.fuzzingtool.utils.http_utils import get_parsed_url
from src.fuzzingtool.utils.fuzz_mark import FuzzMark
from ...test_utils.fuzz_mark_test_case import FuzzMarkTestCase
from ...test_utils.response_mock import ResponseMock


class TestRequester(FuzzMarkTestCase):
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

    def test_set_fuzzing_type_for_method_fuzzing(self):
        return_expected = FuzzType.HTTP_METHOD_FUZZING
        test_method = FuzzMark.BASE_MARK
        requester = Requester("https://test-url.com/", method=test_method)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(returned_data, requester.get_fuzzing_type())
        self.assertEqual(requester.is_method_fuzzing(), True)

    def test_set_fuzzing_type_for_path_fuzzing(self):
        return_expected = FuzzType.PATH_FUZZING
        test_url = f"https://test-url.com/{FuzzMark.BASE_MARK}"
        requester = Requester(test_url)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(returned_data, requester.get_fuzzing_type())
        self.assertEqual(requester.is_path_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_url_params(self):
        return_expected = FuzzType.DATA_FUZZING
        test_url = f"https://test-url.com/?q={FuzzMark.BASE_MARK}"
        requester = Requester(test_url)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(returned_data, requester.get_fuzzing_type())
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_body(self):
        return_expected = FuzzType.DATA_FUZZING
        test_body = f"user={FuzzMark.BASE_MARK}&pass={FuzzMark.BASE_MARK}"
        requester = Requester("https://test-url.com/", body=test_body)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(returned_data, requester.get_fuzzing_type())
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_data_fuzzing_on_headers(self):
        return_expected = FuzzType.DATA_FUZZING
        test_header = {
            'Cookie': f"TESTSESSID={FuzzMark.BASE_MARK}"
        }
        requester = Requester("https://test-url.com/", headers=test_header)
        returned_data = requester._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
        self.assertEqual(returned_data, requester.get_fuzzing_type())
        self.assertEqual(requester.is_data_fuzzing(), True)

    def test_set_fuzzing_type_for_unknown_fuzzing(self):
        return_expected = FuzzType.UNKNOWN_FUZZING
        returned_data = Requester("https://test-url.com/")._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)

    def test_constructor_with_cookie(self):
        test_cookie = "COOKIE=TEST"
        requester = Requester("https://test-url.com/", cookie=test_cookie)
        returned_cookie: FuzzWord = requester._Requester__header['Cookie']
        self.assertIsInstance(returned_cookie, FuzzWord)
        self.assertEqual(returned_cookie.word, test_cookie)

    def test_get_url(self):
        return_expected = "https://test-url.com/"
        test_url = "https://test-url.com/"
        returned_data = Requester(test_url).get_url()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_method(self):
        test_method = "GET"
        returned_data = Requester("https://test-url.com/", method=test_method).get_method()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, test_method)

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
        test_url = "https://test-url.com/"
        requester = Requester(test_url)
        mock_get.side_effect = requests.exceptions.ProxyError
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), "Can't connect to the proxy")
        mock_get.side_effect = requests.exceptions.SSLError
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), f"SSL couldn't be validated on {test_url}")
        mock_get.side_effect = requests.exceptions.Timeout
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), f"Connection to {test_url} timed out")
        mock_get.side_effect = requests.exceptions.InvalidHeader("Cookie: TEST_TEST")
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), "Invalid header TEST_TEST")
        mock_get.side_effect = requests.exceptions.ConnectionError
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), f"Failed to establish a connection to {test_url}")
        mock_get.side_effect = requests.exceptions.RequestException
        with self.assertRaises(RequestException) as e:
            requester.test_connection()
        self.assertEqual(str(e.exception), f"Failed to establish a connection to {test_url}")

    @patch("src.fuzzingtool.conn.requesters.requester.Requester._Requester__get_request_parameters")
    @patch("src.fuzzingtool.conn.requesters.requester.time.time")
    @patch("src.fuzzingtool.conn.requesters.requester.Requester._request")
    def test_request(self, mock_request: Mock, mock_time: Mock, mock_get_parameters: Mock):
        expected_response = ResponseMock()
        expected_rtt = 0.0
        return_expected = (expected_response, expected_rtt)
        test_url = "https://test-url.com/"
        test_payload = "test_payload"
        test_proxy = "test-proxy.com:8001"
        test_parameters = ("GET", test_url, {}, {}, {})
        mock_get_parameters.return_value = test_parameters
        mock_time.return_value = expected_rtt
        mock_request.return_value = expected_response
        returned_data = Requester(test_url, proxies=[test_proxy]).request(test_payload)
        mock_get_parameters.assert_called_once_with(test_payload)
        mock_request.assert_called_once_with(*(*test_parameters, {
            'http': f"http://{test_proxy}",
            'https': f"https://{test_proxy}"
        }))
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.conn.requesters.requester.Requester._Requester__get_request_parameters")
    @patch("src.fuzzingtool.conn.requesters.requester.Requester._request")
    def test_request_with_replay_proxy(self, mock_request: Mock, mock_get_parameters: Mock):
        test_url = "https://test-url.com/"
        test_payload = "test_payload"
        test_proxy = "test-proxy.com:8001"
        test_parameters = ("GET", test_url, {}, {}, {})
        mock_get_parameters.return_value = test_parameters
        mock_request.return_value = ResponseMock()
        Requester(test_url, replay_proxy=test_proxy).request(test_payload, replay_proxy=True)
        mock_request.assert_called_once_with(*(*test_parameters, {
            'http': f"http://{test_proxy}",
            'https': f"https://{test_proxy}"
        }))

    @patch("src.fuzzingtool.conn.requesters.requester.Requester._request")
    def test_request_with_raise_exception(self, mock_request: Mock):
        test_url = "https://test-url.com/"
        test_header_key = "test_key"
        test_header_value = "test_value"
        test_proxy = "test-proxy.com:8080"
        requester = Requester(test_url, headers={test_header_key: test_header_value}, proxy=test_proxy)
        mock_request.side_effect = requests.exceptions.ProxyError
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Can't connect to the proxy {test_proxy}")
        mock_request.side_effect = requests.exceptions.TooManyRedirects
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Too many redirects on {test_url}")
        mock_request.side_effect = requests.exceptions.SSLError
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"SSL couldn't be validated on {test_url}")
        mock_request.side_effect = requests.exceptions.Timeout
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Connection to {test_url} timed out")
        mock_request.side_effect = requests.exceptions.InvalidHeader(f"Invalid header key: {test_header_key}")
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Invalid header {test_header_key}: {test_header_value}")
        mock_request.side_effect = requests.exceptions.ConnectionError
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Failed to establish a connection to {test_url}")
        mock_request.side_effect = requests.exceptions.RequestException
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Failed to establish a connection to {test_url}")
        mock_request.side_effect = UnicodeError
        with self.assertRaises(RequestException) as e:
            requester.request()
        self.assertEqual(str(e.exception), f"Invalid hostname {get_parsed_url(test_url).hostname} for HTTP request")
        mock_request.side_effect = ValueError
        with self.assertRaises(RequestException) as e:
            requester.request()
