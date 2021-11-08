import unittest
from unittest.mock import patch

from src.fuzzingtool.utils.http_utils import *


class TestHttpUtils(unittest.TestCase):
    def test_get_url_without_scheme(self):
        return_expected = "test-url.com/"
        #  Testing with scheme
        test_url = "https://test-url.com/"
        returned_data = get_url_without_scheme(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
        #  Testing withour scheme
        test_url = "test-url.com/"
        returned_data = get_url_without_scheme(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_pure_url(self):
        return_expected = "https://test-url.com/"
        #  Testing without FUZZING_MARK
        test_url = "https://test-url.com/"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
        #  Testing with FUZZING_MARK
        test_url = f"https://test-url.com/{FUZZING_MARK}"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
        #  Testing with FUZZING_MARK and dot
        test_url = f"https://{FUZZING_MARK}.test-url.com/"
        returned_data = get_pure_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
    
    @patch("src.fuzzingtool.utils.http_utils.get_url_without_scheme")
    def test_get_path(self, mock_get_url_without_scheme):
        #  Test with root directory on URL
        return_expected = "/"
        test_url = "https://test-url.com/"
        mock_get_url_without_scheme.return_value = "test-url.com/"
        returned_data = get_path(test_url)
        mock_get_url_without_scheme.assert_called_with(test_url)
        mock_get_url_without_scheme.assert_called_once()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.utils.http_utils.get_url_without_scheme")
    def test_get_host(self, mock_get_url_without_scheme):
        return_expected = "test-url.com"
        #  Test with root directory on URL
        test_url = "https://test-url.com/"
        mock_get_url_without_scheme.return_value = "test-url.com/"
        returned_data = get_host(test_url)
        mock_get_url_without_scheme.assert_called_with(test_url)
        mock_get_url_without_scheme.assert_called_once()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
        #  Test without root directory on URL
        test_url = "https://test-url.com"
        mock_get_url_without_scheme.return_value = "test-url.com"
        returned_data = get_host(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
