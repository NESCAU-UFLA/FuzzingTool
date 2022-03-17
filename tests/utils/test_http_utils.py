import unittest

from src.fuzzingtool.utils.http_utils import *
from ..mock_utils.response_mock import ResponseMock


class TestHttpUtils(unittest.TestCase):
    def test_get_url_without_scheme_without_scheme(self):
        return_expected = "test-url.com/"
        test_url = "test-url.com/"
        returned_data = get_url_without_scheme(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_url_without_scheme_with_scheme(self):
        return_expected = "test-url.com/"
        test_url = "https://test-url.com/"
        returned_data = get_url_without_scheme(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_pure_url_without_mark(self):
        return_expected = "https://test-url.com/"
        test_url = "https://test-url.com/"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_pure_url_with_mark(self):
        return_expected = "https://test-url.com/"
        test_url = f"https://test-url.com/{FUZZING_MARK}"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_pure_url_with_mark_and_dot(self):
        return_expected = "https://test-url.com/"
        test_url = f"https://{FUZZING_MARK}.test-url.com/"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_build_raw_response_header(self):
        return_expected = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.19.0\r\n"
            "Date: Fri, 17 Dec 2021 17:42:14 GMT\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n"
            "X-Powered-By: PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1\r\n"
            "\r\n"
        )
        returned_headers = build_raw_response_header(ResponseMock())
        self.assertIsInstance(returned_headers, str)
        self.assertEqual(returned_headers, return_expected)

    def test_urlparse_file(self):
        return_expected = "my_file.php"
        test_url = f"http://test-url.com/test-path/{return_expected}"
        returned_file = get_parsed_url(test_url).file
        self.assertIsInstance(returned_file, str)
        self.assertEqual(returned_file, return_expected)

    def test_urlparse_file_name(self):
        return_expected = "my_file"
        test_url = f"http://test-url.com/test-path/{return_expected}.php"
        returned_file = get_parsed_url(test_url).file_name
        self.assertIsInstance(returned_file, str)
        self.assertEqual(returned_file, return_expected)

    def test_urlparse_file_ext(self):
        return_expected = ".php"
        test_url = f"http://test-url.com/test-path/my_file{return_expected}"
        returned_file = get_parsed_url(test_url).file_ext
        self.assertIsInstance(returned_file, str)
        self.assertEqual(returned_file, return_expected)
