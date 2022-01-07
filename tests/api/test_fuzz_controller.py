import unittest
from unittest.mock import Mock, patch

from src.fuzzingtool.api.fuzz_controller import FuzzController
from src.fuzzingtool.conn.requesters import Requester, SubdomainRequester
from src.fuzzingtool.utils.consts import FUZZING_MARK
from src.fuzzingtool.exceptions.main_exceptions import FuzzControllerException


class TestFuzzController(unittest.TestCase):
    @patch("src.fuzzingtool.api.fuzz_controller.RequesterFactory.creator")
    def test_init_requester_with_common_requester(self, mock_requester_creator: Mock):
        test_url = "http://test-url.com/"
        mock_requester_creator.return_value = Requester(url=test_url)
        test_fuzz_controller = FuzzController(url=test_url)
        test_fuzz_controller._init_requester()
        mock_requester_creator.assert_called_once_with(
            'Requester',
            url=test_url,
            methods=['GET'],
            body=None,
            headers={},
            follow_redirects=False,
            proxy=None,
            proxies=[],
            timeout=None,
            cookie=None,
        )
        self.assertIsInstance(test_fuzz_controller.requester, Requester)

    @patch("src.fuzzingtool.api.fuzz_controller.RequesterFactory.creator")
    def test_init_requester_with_subdomain_requester(self, mock_requester_creator: Mock):
        test_url = f"http://{FUZZING_MARK}.test-url.com/"
        mock_requester_creator.return_value = SubdomainRequester(url=test_url)
        test_fuzz_controller = FuzzController(url=test_url)
        test_fuzz_controller._init_requester()
        mock_requester_creator.assert_called_once_with(
            'SubdomainRequester',
            url=test_url,
            methods=['GET'],
            body=None,
            headers={},
            follow_redirects=False,
            proxy=None,
            proxies=[],
            timeout=None,
            cookie=None,
        )
        self.assertIsInstance(test_fuzz_controller.requester, SubdomainRequester)

    @patch("src.fuzzingtool.api.fuzz_controller.RequesterFactory.creator")
    @patch("src.fuzzingtool.api.fuzz_controller.AB.build_target_from_raw_http")
    def test_init_requester_with_raw_http(
        self,
        mock_build_target_from_raw_http: Mock,
        mock_requester_creator: Mock
    ):
        return_target = {
            'url': "http://test-url.com/",
            'methods': ['GET'],
            'body': '',
            'header': {
                'test-key': "test-value"
            }
        }
        test_raw_filename = "/home/test/test_raw.txt"
        mock_requester_creator.return_value = Requester(url=return_target['url'])
        mock_build_target_from_raw_http.return_value = return_target
        test_fuzz_controller = FuzzController(raw_http=test_raw_filename)
        test_fuzz_controller._init_requester()
        mock_build_target_from_raw_http.assert_called_once_with(test_raw_filename, None)
        mock_requester_creator.assert_called_once_with(
            'Requester',
            url=return_target['url'],
            methods=return_target['methods'],
            body=return_target['body'],
            headers=return_target['header'],
            follow_redirects=False,
            proxy=None,
            proxies=[],
            timeout=None,
            cookie=None,
        )
        self.assertIsInstance(test_fuzz_controller.requester, Requester)

    def test_init_requester_with_raise_exception(self):
        with self.assertRaises(FuzzControllerException) as e:
            FuzzController(wordlist="test")._init_requester()
        self.assertEqual(str(e.exception), "A target is needed to make the fuzzing")
