import unittest
from unittest.mock import Mock, patch

from fuzzingtool.conn.requesters.requester import Requester


class TestRequester(unittest.TestCase):
    def test_setup_url(self):
        test_url = "http://test-url.com/"
        url_expected = "http://test-url.com/"
        url_dict_expected = {
            'content': url_expected,
            'fuzzingIndexes': []
        }
        url_params_expected = ''
        return_expected = (url_dict_expected, url_params_expected)
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_setup_url_without_root_directory(self):
        test_url = "http://test-url.com"
        url_expected = "http://test-url.com/"
        url_dict_expected = {
            'content': url_expected,
            'fuzzingIndexes': []
        }
        url_params_expected = ''
        return_expected = (url_dict_expected, url_params_expected)
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_setup_url_without_scheme(self):
        test_url = "test-url.com/"
        url_expected = "http://test-url.com/"
        url_dict_expected = {
            'content': url_expected,
            'fuzzingIndexes': []
        }
        url_params_expected = ''
        return_expected = (url_dict_expected, url_params_expected)
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_setup_url_with_params(self):
        test_url = "http://test-url.com/?id=1"
        url_expected = "http://test-url.com/"
        url_dict_expected = {
            'content': url_expected,
            'fuzzingIndexes': []
        }
        url_params_expected = "id=1"
        return_expected = (url_dict_expected, url_params_expected)
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_setup_url_with_fuzzing_mark(self):
        test_url = "http://test-url.com/$"
        url_expected = "http://test-url.com/$"
        url_dict_expected = {
            'content': url_expected,
            'fuzzingIndexes': [20]
        }
        url_params_expected = ''
        return_expected = (url_dict_expected, url_params_expected)
        returned_data = Requester._Requester__setup_url(Requester, test_url)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_setup_method(self):
        test_method = "GET"
        return_expected = {
            'content': test_method,
            'fuzzingIndexes': []
        }
        returned_data = Requester._Requester__setup_method(Requester, test_method)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)

    def test_setup_method_with_fuzzing_mark(self):
        test_method = "GET$"
        return_expected = {
            'content': test_method,
            'fuzzingIndexes': [3]
        }
        returned_data = Requester._Requester__setup_method(Requester, test_method)
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)
