import unittest
from unittest.mock import Mock, patch

import socket
from requests.models import Response

from src.fuzzingtool.conn.requesters.subdomain_requester import SubdomainRequester
from src.fuzzingtool.utils.consts import FuzzType
from src.fuzzingtool.exceptions.request_exceptions import InvalidHostname


class TestRequester(unittest.TestCase):
    @patch("src.fuzzingtool.conn.requesters.subdomain_requester.socket.gethostbyname")
    def test_resolve_hostname(self, mock_gethostbyname: Mock):
        test_hostname = "test-host.com"
        return_expected = "127.0.0.1"
        mock_gethostbyname.return_value = return_expected
        returned_data = SubdomainRequester.resolve_hostname(SubdomainRequester, test_hostname)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.conn.requesters.subdomain_requester.socket.gethostbyname")
    def test_resolve_hostname_with_raise_exception(self, mock_gethostbyname: Mock):
        test_hostname = "test-host.com"
        mock_gethostbyname.side_effect = socket.gaierror
        with self.assertRaises(InvalidHostname):
            SubdomainRequester.resolve_hostname(SubdomainRequester, test_hostname)

    @patch("src.fuzzingtool.conn.requesters.subdomain_requester.Requester.request")
    @patch("src.fuzzingtool.conn.requesters.subdomain_requester.SubdomainRequester.resolve_hostname")
    def test_request(self,
                     mock_resolve_hostname: Mock,
                     mock_request: Mock):
        expected_ip = "127.0.0.1"
        test_payload = ''
        requester = SubdomainRequester("https://test-url.com/")
        mock_resolve_hostname.return_value = expected_ip
        mock_request.return_value = (Response(), 0.0)
        returned_data = requester.request(test_payload)
        mock_resolve_hostname.assert_called_once_with("test-url.com")
        mock_request.assert_called_once_with(test_payload, False)
        returned_response, returned_rtt, returned_ip = returned_data
        self.assertIsInstance(returned_response, Response)
        self.assertIsInstance(returned_rtt, float)
        self.assertEqual(returned_rtt, 0.0)
        self.assertIsInstance(returned_ip, str)
        self.assertEqual(returned_ip, expected_ip)

    def test_set_fuzzing_type(self):
        return_expected = FuzzType.SUBDOMAIN_FUZZING
        returned_data = SubdomainRequester("https://test-url.com/")._set_fuzzing_type()
        self.assertIsInstance(returned_data, int)
        self.assertEqual(returned_data, return_expected)
