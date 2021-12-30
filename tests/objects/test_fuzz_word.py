import unittest

from src.fuzzingtool.objects.fuzz_word import FuzzWord
from src.fuzzingtool.utils.consts import FUZZING_MARK


class TestPayload(unittest.TestCase):
    def test_get_payloaded_word_without_fuzzing(self):
        test_payload = "payload"
        return_expected = "test_word"
        test_word = "test_word"
        fuzz_word = FuzzWord(test_word)
        returned_data = fuzz_word.get_payloaded_word(test_payload)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_get_payloaded_word_with_fuzzing(self):
        test_payload = "payload"
        return_expected = f"test_{test_payload}_word"
        test_word = f"test_{FUZZING_MARK}_word"
        fuzz_word = FuzzWord(test_word)
        returned_data = fuzz_word.get_payloaded_word(test_payload)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
