import unittest
from typing import List

from src.fuzzingtool.core.payloader import Payloader, EncodeManager
from src.fuzzingtool.objects.payload import Payload


def assert_payload_list_is_equal(payloads: List[Payload], other_payloads: List[Payload]) -> None:
    """Checks if two payload list are equals"""
    assert len(payloads) == len(other_payloads)
    for i, payload in enumerate(payloads):
        assert payload.raw == other_payloads[i].raw
        assert payload.final == other_payloads[i].final
        assert payload.config == other_payloads[i].config


class TestPayloader(unittest.TestCase):
    def tearDown(self):
        Payloader.prefix = []
        Payloader.suffix = []
        Payloader.case = lambda ajusted_payload: ajusted_payload
        Payloader.encoder = EncodeManager()

    def test_get_customized_payload_without_mutation(self):
        test_payload = "test_payload"
        return_expected = [Payload(test_payload)]
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)

    def test_get_customized_payload_with_prefix(self):
        test_payload = "test_payload"
        test_prefix = ['<', '|']
        return_expected = [
            Payload(test_payload).with_prefix(test_prefix[0]),
            Payload(test_payload).with_prefix(test_prefix[1])
        ]
        Payloader.set_prefix(test_prefix)
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)

    def test_get_customized_payload_with_suffix(self):
        test_payload = "test_payload"
        test_suffix = ['>', '|']
        return_expected = [
            Payload(test_payload).with_suffix(test_suffix[0]),
            Payload(test_payload).with_suffix(test_suffix[1])
        ]
        Payloader.set_suffix(test_suffix)
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)

    def test_get_customized_payload_with_upper(self):
        test_payload = "test_payload"
        return_expected = [Payload(test_payload).with_case(str.upper, "Upper")]
        Payloader.set_uppercase()
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)

    def test_get_customized_payload_with_lower(self):
        test_payload = "test_payload"
        return_expected = [Payload(test_payload).with_case(str.lower, "Lower")]
        Payloader.set_lowercase()
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)

    def test_get_customized_payload_with_capitalize(self):
        test_payload = "test_payload"
        return_expected = [Payload(test_payload).with_case(str.capitalize, "Capitalize")]
        Payloader.set_capitalize()
        returned_payloads = Payloader.get_customized_payload(test_payload)
        self.assertIsInstance(returned_payloads, list)
        assert_payload_list_is_equal(returned_payloads, return_expected)
