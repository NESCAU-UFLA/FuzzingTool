import unittest
from unittest.mock import Mock, patch

from fuzzingtool.utils.http_utils import *


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

    @patch("fuzzingtool.utils.http_utils.get_url_without_scheme")
    def test_get_path(self, mock_get_url_without_scheme: Mock):
        return_expected = "/"
        test_url = "https://test-url.com/"
        mock_get_url_without_scheme.return_value = "test-url.com/"
        returned_data = get_path(test_url)
        mock_get_url_without_scheme.assert_called_once_with(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    @patch("fuzzingtool.utils.http_utils.get_url_without_scheme")
    def test_get_host_without_root_directory(self, mock_get_url_without_scheme: Mock):
        return_expected = "test-url.com"
        test_url = "https://test-url.com"
        mock_get_url_without_scheme.return_value = "test-url.com"
        returned_data = get_host(test_url)
        mock_get_url_without_scheme.assert_called_once_with(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
 
    @patch("fuzzingtool.utils.http_utils.get_url_without_scheme")
    def test_get_host_with_root_directory(self, mock_get_url_without_scheme: Mock):
        return_expected = "test-url.com"
        test_url = "https://test-url.com/"
        mock_get_url_without_scheme.return_value = "test-url.com/"
        returned_data = get_host(test_url)
        mock_get_url_without_scheme.assert_called_once_with(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
