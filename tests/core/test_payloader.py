import unittest
from typing import List

from src.fuzzingtool.core.payloader import Payloader, EncodeManager
from src.fuzzingtool.core.plugins.encoders.hex import Hex
from src.fuzzingtool.objects.payload import Payload
from src.fuzzingtool.exceptions import BadArgumentFormat


def assert_payload_list_is_equal(payloads: List[Payload], other_payloads: List[Payload]) -> None:
    """Checks if two payload list are equals"""
    assert len(payloads) == len(other_payloads)
    for i, payload in enumerate(payloads):
        assert payload.raw == other_payloads[i].raw
        assert payload.final == other_payloads[i].final
        assert payload.config == other_payloads[i].config


class TestEncodeManager(unittest.TestCase):
    def test_set_regex_with_invalid_regex(self):
        test_regex = r"?([A-Z][a-z]"
        with self.assertRaises(BadArgumentFormat) as e:
            EncodeManager().set_regex(test_regex)
        self.assertEqual(str(e.exception), f"Invalid regex format {test_regex}")

    def test_encode_without_regex(self):
        return_expected = "746573745f7061796c6f6164"
        test_payload = "test_payload"
        returned_encoded_payload = EncodeManager()._encode(Hex(), test_payload)
        self.assertIsInstance(returned_encoded_payload, str)
        self.assertEqual(returned_encoded_payload, return_expected)

    def test_encode_with_regex_without_regex_match(self):
        test_payload = ":test_payload;"
        return_expected = test_payload
        test_encode_manager = EncodeManager()
        test_encode_manager.set_regex("<|>")
        returned_encoded_payload = test_encode_manager._encode(Hex(), test_payload)
        self.assertIsInstance(returned_encoded_payload, str)
        self.assertEqual(returned_encoded_payload, return_expected)

    def test_encode_with_regex_with_regex_match(self):
        return_expected = "3ctest_payload3e"
        test_payload = "<test_payload>"
        test_encode_manager = EncodeManager()
        test_encode_manager.set_regex("<|>")
        returned_encoded_payload = test_encode_manager._encode(Hex(), test_payload)
        self.assertIsInstance(returned_encoded_payload, str)
        self.assertEqual(returned_encoded_payload, return_expected)

    def test_set_encoder(self):
        test_payload = "test_payload"
        return_expected = [Payload(test_payload).with_encoder("746573745f7061796c6f6164", "Hex")]
        test_encode_manager = EncodeManager()
        test_encode_manager.set_encoders(([Hex()], []))
        returned_encoded_payload = test_encode_manager.encode([Payload(test_payload)])
        self.assertIsInstance(returned_encoded_payload, list)
        assert_payload_list_is_equal(returned_encoded_payload, return_expected)


class TestPayloader(unittest.TestCase):
    def tearDown(self):
        Payloader.prefix = []
        Payloader.suffix = []
        Payloader.case = lambda ajusted_payload: ajusted_payload

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
