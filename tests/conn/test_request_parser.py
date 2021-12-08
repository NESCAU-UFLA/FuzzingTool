import unittest

from fuzzingtool.conn.request_parser import *
from fuzzingtool.objects.fuzz_word import FuzzWord
from fuzzingtool.utils.consts import FUZZING_MARK


class TestRequestParser(unittest.TestCase):
    def test_check_is_subdomain_fuzzing(self):
        return_expected = True
        test_url = f"https://{FUZZING_MARK}.test-url.com/"
        returned_data = check_is_subdomain_fuzzing(test_url)
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_check_is_url_discovery(self):
        return_expected = True
        test_url = FuzzWord(f"https://test-url.com/{FUZZING_MARK}")
        returned_data = check_is_url_discovery(test_url)
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_check_is_not_url_discovery(self):
        return_expected = False
        test_url = FuzzWord(f"https://test-url.com/?q={FUZZING_MARK}")
        returned_data = check_is_url_discovery(test_url)
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_check_is_data_fuzzing_on_url_params(self):
        return_expected = True
        test_url_params = {
            FuzzWord('q'): FuzzWord(FUZZING_MARK)
        }
        returned_data = check_is_data_fuzzing(test_url_params, {}, {})
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)
        test_url_params = {
            FuzzWord(FUZZING_MARK): FuzzWord('1')
        }
        returned_data = check_is_data_fuzzing(test_url_params, {}, {})
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_check_is_data_fuzzing_on_body(self):
        return_expected = True
        test_body = {
            FuzzWord('q'): FuzzWord(FUZZING_MARK)
        }
        returned_data = check_is_data_fuzzing({}, test_body, {})
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)
        test_body = {
            FuzzWord(FUZZING_MARK): FuzzWord('1')
        }
        returned_data = check_is_data_fuzzing({}, test_body, {})
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_check_is_data_fuzzing_on_header(self):
        return_expected = True
        test_header = {
            'Cookie': FuzzWord(f"TESTSESSID={FUZZING_MARK}")
        }
        returned_data = check_is_data_fuzzing({}, {}, test_header)
        self.assertIsInstance(returned_data, bool)
        self.assertEqual(returned_data, return_expected)

    def test_get_method(self):
        return_expected = "testmethod"
        test_method = FuzzWord(FUZZING_MARK)
        parser = RequestParser()
        parser.set_payload(return_expected)
        returned_data = parser.get_method(test_method)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_url(self):
        return_expected = "https://test-url.com/test.php"
        test_url = FuzzWord(f"https://test-url.com/{FUZZING_MARK}")
        parser = RequestParser()
        parser.set_payload("test.php")
        returned_data = parser.get_url(test_url)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_header(self):
        test_payload = "payload"
        return_expected = {
            'Cookie': f"TESTSESSID={test_payload}",
            'User-Agent': "FuzzingTool User Agent"
        }
        test_header = {
            'Cookie': FuzzWord(f"TESTSESSID={FUZZING_MARK}"),
            'User-Agent': FuzzWord("FuzzingTool User Agent")
        }
        parser = RequestParser()
        parser.set_payload(test_payload)
        returned_data = parser.get_header(test_header)
        self.assertIsInstance(returned_data, dict)
        self.assertDictEqual(returned_data, return_expected)

    def test_get_data(self):
        test_payload = "payload"
        return_expected = {
            'login': test_payload,
        }
        test_data = {
            FuzzWord('login'): FuzzWord(FUZZING_MARK),
        }
        parser = RequestParser()
        parser.set_payload(test_payload)
        returned_data = parser.get_data(test_data)
        self.assertIsInstance(returned_data, dict)
        self.assertDictEqual(returned_data, return_expected)
