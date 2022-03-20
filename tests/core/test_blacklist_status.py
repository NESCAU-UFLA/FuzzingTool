import unittest

from src.fuzzingtool.core.blacklist_status import BlacklistStatus
from src.fuzzingtool.exceptions import BadArgumentType


class TestBlacklistStatus(unittest.TestCase):
    def test_build_status_list(self):
        return_expected = [200, 301, 303]
        returned_status_list = BlacklistStatus.build_status_list(BlacklistStatus, "200,301,303")
        self.assertIsInstance(returned_status_list, list)
        self.assertEqual(returned_status_list, return_expected)

    def test_build_status_list_with_invalid_status_type(self):
        with self.assertRaises(BadArgumentType) as e:
            BlacklistStatus.build_status_list(BlacklistStatus, "200,301k,303")
        self.assertEqual(str(e.exception), "Status code must be an integer")
