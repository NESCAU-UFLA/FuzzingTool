import unittest
from unittest.mock import Mock, patch

from fuzzingtool.factories.requester_factory import RequesterFactory
from fuzzingtool.conn.requesters import requester, Requester


class TestRequesterFactory(unittest.TestCase):
    @patch("fuzzingtool.factories.requester_factory.getattr")
    @patch("fuzzingtool.factories.requester_factory.import_module")
    def test_creator(self,
                     mock_import_module: Mock,
                     mock_getattr: Mock):
        test_request_type = "Requester"
        test_url = "https://test-url.com/"
        test_module = requester
        test_requester = Requester
        mock_import_module.return_value = test_module
        mock_getattr.return_value = test_requester
        returned_data = RequesterFactory.creator(test_request_type, test_url)
        mock_import_module.assert_called_once_with(
            "fuzzingtool.conn.requesters",
            package=test_request_type
        )
        mock_getattr.assert_called_once_with(test_module, test_request_type)
        self.assertIsInstance(returned_data, test_requester)
