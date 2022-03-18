import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.api.fuzz_controller import FuzzController
from src.fuzzingtool.conn.requesters import Requester, SubdomainRequester
from src.fuzzingtool.utils.consts import FUZZING_MARK
from src.fuzzingtool.exceptions.main_exceptions import FuzzControllerException, WordlistCreationError
from src.fuzzingtool.core.defaults.scanners import DataScanner, PathScanner, SubdomainScanner
from src.fuzzingtool.core.plugins.scanners import Reflected
from src.fuzzingtool.core.plugins.encoders import Html
from ..mock_utils.wordlist_mock import WordlistMock


class TestFuzzController(unittest.TestCase):
    def test_init_requester_with_common_requester(self):
        test_url = "http://test-url.com/"
        test_fuzz_controller = FuzzController(url=test_url)
        test_fuzz_controller._init_requester()
        self.assertIsInstance(test_fuzz_controller.requester, Requester)

    def test_init_requester_with_subdomain_requester(self):
        test_url = f"http://{FUZZING_MARK}.test-url.com/"
        test_fuzz_controller = FuzzController(url=test_url)
        test_fuzz_controller._init_requester()
        self.assertIsInstance(test_fuzz_controller.requester, SubdomainRequester)

    @patch("src.fuzzingtool.api.fuzz_controller.AB.build_target_from_raw_http")
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
        test_fuzz_controller = FuzzController(raw_http=test_raw_filename)
        test_fuzz_controller._init_requester()
        mock_build_target_from_raw_http.assert_called_once_with(test_raw_filename, None)
        self.assertIsInstance(test_fuzz_controller.requester, Requester)

    def test_init_requester_with_raise_exception(self):
        with self.assertRaises(FuzzControllerException) as e:
            FuzzController(wordlist="test")._init_requester()
        self.assertEqual(str(e.exception), "A target is needed to make the fuzzing")

    @patch("src.fuzzingtool.api.fuzz_controller.Matcher.set_allowed_status")
    def test_init_matcher(self, mock_set_allowed_status: Mock):
        test_fuzz_controller = FuzzController(url=f"http://test-url.com/{FUZZING_MARK}")
        test_fuzz_controller._init_requester()
        test_fuzz_controller._init_matcher()
        mock_set_allowed_status.assert_called_once_with("200-399,401,403")

    def test_get_default_scanner_with_path_scanner(self):
        test_fuzz_controller = FuzzController(url=f"http://test-url.com/{FUZZING_MARK}")
        test_fuzz_controller._init_requester()
        returned_scanner = test_fuzz_controller._FuzzController__get_default_scanner()
        self.assertIsInstance(returned_scanner, PathScanner)

    def test_get_default_scanner_with_subdomain_scanner(self):
        test_fuzz_controller = FuzzController(url=f"http://{FUZZING_MARK}.test-url.com/")
        test_fuzz_controller._init_requester()
        returned_scanner = test_fuzz_controller._FuzzController__get_default_scanner()
        self.assertIsInstance(returned_scanner, SubdomainScanner)

    def test_get_default_scanner_with_data_scanner(self):
        test_fuzz_controller = FuzzController(url=f"http://test-url.com/", data=f"a={FUZZING_MARK}")
        test_fuzz_controller._init_requester()
        returned_scanner = test_fuzz_controller._FuzzController__get_default_scanner()
        self.assertIsInstance(returned_scanner, DataScanner)

    @patch("src.fuzzingtool.api.fuzz_controller.PluginFactory.object_creator")
    def test_init_scanner_with_plugin_scanner(self, mock_object_creator: Mock):
        mock_object_creator.return_value = Reflected()
        test_fuzz_controller = FuzzController(url=f"http://test-url.com/", scanner="Reflected")
        test_fuzz_controller._init_requester()
        test_fuzz_controller._init_scanner()
        mock_object_creator.assert_called_once_with("Reflected", "scanners", '')

    @patch("src.fuzzingtool.api.fuzz_controller.FuzzController._FuzzController__get_default_scanner")
    def test_init_scanner_with_default_scanner(self, mock_get_default_scanner: Mock):
        FuzzController(url=f"http://test-url.com/{FUZZING_MARK}")._init_scanner()
        mock_get_default_scanner.assert_called_once()

    def test_build_encoders_with_no_encoder(self):
        return_expected = None
        returned_encoder = FuzzController()._FuzzController__build_encoders()
        self.assertEqual(returned_encoder, return_expected)

    @patch("src.fuzzingtool.api.fuzz_controller.PluginFactory.object_creator")
    def test_build_encoders_with_encoders(self, mock_object_creator: Mock):
        expected_encoder = Html()
        return_expected = ([expected_encoder], [])
        mock_object_creator.return_value = expected_encoder
        returned_encoders = FuzzController(encoder="Html")._FuzzController__build_encoders()
        mock_object_creator.assert_called_once_with("Html", "encoders", '')
        self.assertEqual(returned_encoders, return_expected)

    @patch("src.fuzzingtool.api.fuzz_controller.PluginFactory.object_creator")
    def test_build_encoders_with_chain_encoders(self, mock_object_creator: Mock):
        expected_encoder = Html()
        return_expected = ([], [[expected_encoder, expected_encoder]])
        mock_object_creator.return_value = expected_encoder
        returned_encoders = FuzzController(encoder="Html@Html")._FuzzController__build_encoders()
        mock_object_creator.assert_called_with("Html", "encoders", '')
        self.assertEqual(returned_encoders, return_expected)

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.encoder.set_regex")
    @patch("src.fuzzingtool.api.fuzz_controller.PluginFactory.object_creator")
    def test_build_encoders_with_encode_only(self,
                                             mock_object_creator: Mock,
                                             mock_set_regex: Mock):
        test_encode_only = "<|>|;"
        mock_object_creator.return_value = Html()
        FuzzController(encoder="Html", encode_only=test_encode_only)._FuzzController__build_encoders()
        mock_set_regex.assert_called_once_with(test_encode_only)

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.set_prefix")
    def test_configure_payloader_with_prefix(self, mock_set_prefix: Mock):
        FuzzController(prefix="test,test2")._FuzzController__configure_payloader()
        mock_set_prefix.assert_called_once_with(["test", "test2"])

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.set_suffix")
    def test_configure_payloader_with_suffix(self, mock_set_suffix: Mock):
        FuzzController(suffix="test,test2")._FuzzController__configure_payloader()
        mock_set_suffix.assert_called_once_with(["test", "test2"])

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.set_lowercase")
    def test_configure_payloader_with_lowercase(self, mock_set_lowercase: Mock):
        FuzzController(lower=True)._FuzzController__configure_payloader()
        mock_set_lowercase.assert_called_once()

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.set_uppercase")
    def test_configure_payloader_with_uppercase(self, mock_set_uppercase: Mock):
        FuzzController(upper=True)._FuzzController__configure_payloader()
        mock_set_uppercase.assert_called_once()

    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.set_capitalize")
    def test_configure_payloader_with_capitalize(self, mock_set_capitalize: Mock):
        FuzzController(capitalize=True)._FuzzController__configure_payloader()
        mock_set_capitalize.assert_called_once()

    @patch("src.fuzzingtool.api.fuzz_controller.FuzzController._FuzzController__build_encoders")
    @patch("src.fuzzingtool.api.fuzz_controller.Payloader.encoder.set_encoders")
    def test_configure_payloader_with_encoders(self,
                                               mock_set_encoders: Mock,
                                               mock_build_encoders: Mock):
        build_encoders_return = ([Html()], [])
        mock_build_encoders.return_value = build_encoders_return
        FuzzController(encoder="Html")._FuzzController__configure_payloader()
        mock_set_encoders.assert_called_once_with(build_encoders_return)

    @patch("src.fuzzingtool.api.fuzz_controller.WordlistFactory.creator")
    def test_build_wordlist(self, mock_creator: Mock):
        test_wordlist = WordlistMock('1')
        mock_creator.return_value = test_wordlist
        returned_wordlist = FuzzController(
            url="http://test-url.com/", wordlist="test=1"
        )._FuzzController__build_wordlist([("test", '1')])
        mock_creator.assert_called_once_with("test", '1', None)
        self.assertIsInstance(returned_wordlist, list)
        self.assertEqual(returned_wordlist, test_wordlist._build())

    @patch("src.fuzzingtool.api.fuzz_controller.WordlistFactory.creator")
    def test_build_wordlist_with_blank_wordlist(self, mock_creator: Mock):
        mock_creator.side_effect = WordlistCreationError()
        test_fuzz_controller = FuzzController(url="http://test-url.com/", wordlist="test")
        with self.assertRaises(FuzzControllerException) as e:
            test_fuzz_controller._FuzzController__build_wordlist([("test", '')])
        self.assertEqual(str(e.exception), "The wordlist is empty")

    @patch("src.fuzzingtool.api.fuzz_controller.FuzzController._FuzzController__build_wordlist")
    def test_init_dictionary(self, mock_build_wordlist: Mock):
        mock_build_wordlist.return_value = ["test", "test", "test2"]
        test_fuzz_controller = FuzzController(wordlist="test", unique=True)
        test_fuzz_controller._init_dictionary()
        self.assertEqual(test_fuzz_controller.dict_metadata["removed"], 1)
        self.assertEqual(test_fuzz_controller.dict_metadata["len"], 2)
