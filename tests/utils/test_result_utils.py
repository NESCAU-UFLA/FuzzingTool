import unittest

from src.fuzzingtool.utils.consts import MAX_PAYLOAD_LENGTH_TO_OUTPUT
from src.fuzzingtool.utils.result_utils import ResultUtils


class TestResultUtils(unittest.TestCase):
    def tearDown(self):
        ResultUtils.detailed_results = False

    def test_get_formatted_result_with_only_int(self):
        test_payload = "test_payload"
        test_words = 40
        test_lines = 7
        return_expected = (
            f"{test_payload:<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}",
            '{:>5}'.format(276) + " ms",
            '{:>7}'.format(200) + " B ",
            '{:>6}'.format(test_words),
            '{:>5}'.format(test_lines)
        )
        returned_data = ResultUtils.get_formatted_result(
            payload=test_payload,
            rtt=0.276000,
            length=200,
            words=test_words,
            lines=test_lines
        )
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_result_with_rtt_float(self):
        test_payload = "test_payload"
        test_words = 40
        test_lines = 7
        return_expected = (
            f"{test_payload:<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}",
            '{:>5}'.format(2.76) + " s ",
            '{:>7}'.format(200) + " B ",
            '{:>6}'.format(test_words),
            '{:>5}'.format(test_lines)
        )
        returned_data = ResultUtils.get_formatted_result(
            payload=test_payload,
            rtt=2.7640800,
            length=200,
            words=test_words,
            lines=test_lines
        )
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_get_formatted_result_with_length_float(self):
        test_payload = "test_payload"
        test_words = 40
        test_lines = 7
        return_expected = (
            f"{test_payload:<{MAX_PAYLOAD_LENGTH_TO_OUTPUT}}",
            '{:>5}'.format(276) + " ms",
            '{:>7}'.format('1.50') + " KB",
            '{:>6}'.format(test_words),
            '{:>5}'.format(test_lines)
        )
        returned_data = ResultUtils.get_formatted_result(
            payload=test_payload,
            rtt=0.276000,
            length=1536,
            words=test_words,
            lines=test_lines
        )
        self.assertIsInstance(returned_data, tuple)
        self.assertTupleEqual(returned_data, return_expected)

    def test_format_custom_field(self):
        return_expected = "True"
        returned_data = ResultUtils.format_custom_field(True)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_format_custom_field_with_detailed_list(self):
        return_expected = "test, test2"
        returned_data = ResultUtils.format_custom_field(["test", "test2"], force_detailed=True)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)

    def test_format_custom_field_with_list(self):
        test_custom = ["test", "test2"]
        return_expected = f"found {len(test_custom)} match(s)"
        returned_data = ResultUtils.format_custom_field(test_custom)
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)
