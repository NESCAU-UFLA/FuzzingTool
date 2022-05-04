import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.fuzz_lib import FuzzLib
from src.fuzzingtool.conn.requesters import Requester, SubdomainRequester
from src.fuzzingtool.utils.consts import PluginCategory, FUZZING_MARK
from src.fuzzingtool.exceptions import FuzzLibException, WordlistCreationError
from src.fuzzingtool.core.defaults.scanners import DataScanner, PathScanner, SubdomainScanner
from src.fuzzingtool.core.plugins.scanners import Reflected
from src.fuzzingtool.core.plugins.encoders import Html
from .mock_utils.wordlist_mock import WordlistMock


class TestFuzzController(unittest.TestCase):
    def test_init_requester_with_common_requester(self):
        test_url = "http://test-url.com/"
        test_fuzz_lib = FuzzLib(url=test_url)
        test_fuzz_lib._init_requester()
        self.assertIsInstance(test_fuzz_lib.requester, Requester)

    def test_init_requester_with_subdomain_requester(self):
        test_url = f"http://{FUZZING_MARK}.test-url.com/"
        test_fuzz_lib = FuzzLib(url=test_url)
        test_fuzz_lib._init_requester()
        self.assertIsInstance(test_fuzz_lib.requester, SubdomainRequester)

    @patch("src.fuzzingtool.fuzz_lib.AB.build_target_from_raw_http")
    def test_init_requester_with_raw_http(
        self,
        mock_build_target_from_raw_http: Mock
    ):
        return_target = {
            'url': "http://test-url.com/",
            'method': 'GET',
            'body': '',
            'header': {
                'test-key': "test-value"
            }
        }
        test_raw_filename = "/home/test/test_raw.txt"
        mock_build_target_from_raw_http.return_value = return_target
        test_fuzz_lib = FuzzLib(raw_http=test_raw_filename)
        test_fuzz_lib._init_requester()
        mock_build_target_from_raw_http.assert_called_once_with(test_raw_filename, None)
        self.assertIsInstance(test_fuzz_lib.requester, Requester)

    def test_init_requester_with_raise_exception(self):
        with self.assertRaises(FuzzLibException) as e:
            FuzzLib(wordlist="test")._init_requester()
        self.assertEqual(str(e.exception), "A target is needed to make the fuzzing")

    @patch("src.fuzzingtool.fuzz_lib.Matcher.set_status_code")
    def test_init_matcher(self, mock_set_status_code: Mock):
        test_fuzz_lib = FuzzLib(url=f"http://test-url.com/{FUZZING_MARK}")
        test_fuzz_lib._init_requester()
        test_fuzz_lib._init_matcher()
        mock_set_status_code.assert_called_once_with("200-399,401,403")

    def test_get_default_scanner_with_path_scanner(self):
        test_fuzz_lib = FuzzLib(url=f"http://test-url.com/{FUZZING_MARK}")
        test_fuzz_lib._init_requester()
        returned_scanner = test_fuzz_lib._FuzzLib__get_default_scanner()
        self.assertIsInstance(returned_scanner, PathScanner)

    def test_get_default_scanner_with_subdomain_scanner(self):
        test_fuzz_lib = FuzzLib(url=f"http://{FUZZING_MARK}.test-url.com/")
        test_fuzz_lib._init_requester()
        returned_scanner = test_fuzz_lib._FuzzLib__get_default_scanner()
        self.assertIsInstance(returned_scanner, SubdomainScanner)

    def test_get_default_scanner_with_data_scanner(self):
        test_fuzz_lib = FuzzLib(url=f"http://test-url.com/", data=f"a={FUZZING_MARK}")
        test_fuzz_lib._init_requester()
        returned_scanner = test_fuzz_lib._FuzzLib__get_default_scanner()
        self.assertIsInstance(returned_scanner, DataScanner)

    @patch("src.fuzzingtool.fuzz_lib.PluginFactory.object_creator")
    def test_init_scanners_with_plugin_scanner(self, mock_object_creator: Mock):
        mock_object_creator.return_value = Reflected()
        test_fuzz_lib = FuzzLib(url=f"http://test-url.com/", scanner="Reflected")
        test_fuzz_lib._init_requester()
        test_fuzz_lib._init_scanners()
        mock_object_creator.assert_called_once_with(PluginCategory.scanner, "Reflected", '')

    @patch("src.fuzzingtool.fuzz_lib.FuzzLib._FuzzLib__get_default_scanner")
    def test_init_scanners_with_default_scanner(self, mock_get_default_scanner: Mock):
        FuzzLib(url=f"http://test-url.com/{FUZZING_MARK}")._init_scanners()
        mock_get_default_scanner.assert_called_once()

    @patch("src.fuzzingtool.fuzz_lib.PluginFactory.object_creator")
    def test_build_encoders_with_encoders(self, mock_object_creator: Mock):
        expected_encoder = Html()
        return_expected = ([expected_encoder], [])
        mock_object_creator.return_value = expected_encoder
        returned_encoders = FuzzLib(encoder="Html")._FuzzLib__build_encoders()
        mock_object_creator.assert_called_once_with(PluginCategory.encoder, "Html", '')
        self.assertEqual(returned_encoders, return_expected)

    @patch("src.fuzzingtool.fuzz_lib.PluginFactory.object_creator")
    def test_build_encoders_with_chain_encoders(self, mock_object_creator: Mock):
        expected_encoder = Html()
        return_expected = ([], [[expected_encoder, expected_encoder]])
        mock_object_creator.return_value = expected_encoder
        returned_encoders = FuzzLib(encoder="Html@Html")._FuzzLib__build_encoders()
        mock_object_creator.assert_called_with(PluginCategory.encoder, "Html", '')
        self.assertEqual(returned_encoders, return_expected)

    @patch("src.fuzzingtool.fuzz_lib.Payloader.encoder.set_regex")
    @patch("src.fuzzingtool.fuzz_lib.PluginFactory.object_creator")
    def test_build_encoders_with_encode_only(self,
                                             mock_object_creator: Mock,
                                             mock_set_regex: Mock):
        test_encode_only = "<|>|;"
        mock_object_creator.return_value = Html()
        FuzzLib(encoder="Html", encode_only=test_encode_only)._FuzzLib__build_encoders()
        mock_set_regex.assert_called_once_with(test_encode_only)

    @patch("src.fuzzingtool.fuzz_lib.Payloader.set_prefix")
    def test_configure_payloader_with_prefix(self, mock_set_prefix: Mock):
        FuzzLib(prefix="test,test2")._FuzzLib__configure_payloader()
        mock_set_prefix.assert_called_once_with(["test", "test2"])

    @patch("src.fuzzingtool.fuzz_lib.Payloader.set_suffix")
    def test_configure_payloader_with_suffix(self, mock_set_suffix: Mock):
        FuzzLib(suffix="test,test2")._FuzzLib__configure_payloader()
        mock_set_suffix.assert_called_once_with(["test", "test2"])

    @patch("src.fuzzingtool.fuzz_lib.Payloader.set_lowercase")
    def test_configure_payloader_with_lowercase(self, mock_set_lowercase: Mock):
        FuzzLib(lower=True)._FuzzLib__configure_payloader()
        mock_set_lowercase.assert_called_once()

    @patch("src.fuzzingtool.fuzz_lib.Payloader.set_uppercase")
    def test_configure_payloader_with_uppercase(self, mock_set_uppercase: Mock):
        FuzzLib(upper=True)._FuzzLib__configure_payloader()
        mock_set_uppercase.assert_called_once()

    @patch("src.fuzzingtool.fuzz_lib.Payloader.set_capitalize")
    def test_configure_payloader_with_capitalize(self, mock_set_capitalize: Mock):
        FuzzLib(capitalize=True)._FuzzLib__configure_payloader()
        mock_set_capitalize.assert_called_once()

    @patch("src.fuzzingtool.fuzz_lib.FuzzLib._FuzzLib__build_encoders")
    @patch("src.fuzzingtool.fuzz_lib.Payloader.encoder.set_encoders")
    def test_configure_payloader_with_encoders(self,
                                               mock_set_encoders: Mock,
                                               mock_build_encoders: Mock):
        build_encoders_return = ([Html()], [])
        mock_build_encoders.return_value = build_encoders_return
        FuzzLib(encoder="Html")._FuzzLib__configure_payloader()
        mock_set_encoders.assert_called_once_with(build_encoders_return)

    @patch("src.fuzzingtool.fuzz_lib.WordlistFactory.creator")
    def test_build_wordlist(self, mock_creator: Mock):
        test_wordlist = WordlistMock('1')
        mock_creator.return_value = test_wordlist
        returned_wordlist = FuzzLib(
            url="http://test-url.com/", wordlist="test=1"
        )._FuzzLib__build_wordlist([("test", '1')])
        mock_creator.assert_called_once_with("test", '1', None)
        self.assertIsInstance(returned_wordlist, list)
        self.assertEqual(returned_wordlist, test_wordlist._build())

    @patch("src.fuzzingtool.fuzz_lib.WordlistFactory.creator")
    def test_build_wordlist_with_blank_wordlist(self, mock_creator: Mock):
        mock_creator.side_effect = WordlistCreationError()
        test_fuzz_lib = FuzzLib(url="http://test-url.com/", wordlist="test")
        with self.assertRaises(FuzzLibException) as e:
            test_fuzz_lib._FuzzLib__build_wordlist([("test", '')])
        self.assertEqual(str(e.exception), "The wordlist is empty")

    @patch("src.fuzzingtool.fuzz_lib.FuzzLib._FuzzLib__build_wordlist")
    def test_init_dictionary(self, mock_build_wordlist: Mock):
        mock_build_wordlist.return_value = ["test", "test", "test2"]
        test_fuzz_lib = FuzzLib(wordlist="test", unique=True)
        test_fuzz_lib._init_dictionary()
        self.assertEqual(test_fuzz_lib.dict_metadata["removed"], 1)
        self.assertEqual(test_fuzz_lib.dict_metadata["len"], 2)
