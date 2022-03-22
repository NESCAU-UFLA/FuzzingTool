import unittest

from src.fuzzingtool.objects.payload import Payload


class TestPayload(unittest.TestCase):
    def test_str(self):
        expected_result = "test-payload"
        returned_payload = Payload(expected_result)
        self.assertEqual(str(returned_payload), expected_result)

    def test_update(self):
        test_payload = Payload("test")
        returned_payload = Payload().update(test_payload)
        self.assertIsInstance(returned_payload, Payload)
        self.assertEqual(returned_payload.raw, test_payload.raw)
        self.assertEqual(returned_payload.final, test_payload.final)
        self.assertEqual(returned_payload.rlevel, test_payload.rlevel)
        self.assertDictEqual(returned_payload.config, test_payload.config)

    def test_with_prefix(self):
        test_payload_str = "test"
        test_prefix = "<prefix>"
        expected_config = {'prefix': test_prefix}
        expected_final_payload = f"{test_prefix}{test_payload_str}"
        returned_payload = Payload(test_payload_str).with_prefix(test_prefix)
        self.assertIsInstance(returned_payload, Payload)
        self.assertDictEqual(returned_payload.config, expected_config)
        self.assertEqual(returned_payload.final, expected_final_payload)

    def test_with_suffix(self):
        test_payload_str = "test"
        test_suffix = "<suffix>"
        expected_config = {'suffix': test_suffix}
        expected_final_payload = f"{test_payload_str}{test_suffix}"
        returned_payload = Payload(test_payload_str).with_suffix(test_suffix)
        self.assertIsInstance(returned_payload, Payload)
        self.assertDictEqual(returned_payload.config, expected_config)
        self.assertEqual(returned_payload.final, expected_final_payload)

    def test_with_case(self):
        test_payload_str = "test"
        test_case_callback = str.upper
        test_case_method = "Upper"
        expected_config = {'case': test_case_method}
        expected_final_payload = test_payload_str.upper()
        returned_payload = Payload(test_payload_str).with_case(
            test_case_callback, test_case_method
        )
        self.assertIsInstance(returned_payload, Payload)
        self.assertDictEqual(returned_payload.config, expected_config)
        self.assertEqual(returned_payload.final, expected_final_payload)

    def test_with_encoder(self):
        test_payload_str = "test"
        test_encoded = "testencoded"
        test_encoder = "TestEncoder"
        expected_config = {'encoder': test_encoder}
        expected_final_payload = test_encoded
        returned_payload = Payload(test_payload_str).with_encoder(
            test_encoded, test_encoder
        )
        self.assertIsInstance(returned_payload, Payload)
        self.assertDictEqual(returned_payload.config, expected_config)
        self.assertEqual(returned_payload.final, expected_final_payload)

    def test_with_recursion(self):
        test_recursion_payload = "test-payload"
        expected_config = {'rlevel_0': ''}
        returned_payload = Payload().with_recursion(test_recursion_payload)
        self.assertIsInstance(returned_payload, Payload)
        self.assertEqual(returned_payload.final, test_recursion_payload)
        self.assertEqual(returned_payload.rlevel, 1)
        self.assertDictEqual(returned_payload.config, expected_config)
