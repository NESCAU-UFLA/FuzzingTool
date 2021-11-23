import unittest

from fuzzingtool import version, APP_VERSION

class TestInit(unittest.TestCase):
    def test_version(self):
        return_expected = '.'.join([str(value) for value in APP_VERSION.values()])
        returned_data = version()
        self.assertIsInstance(returned_data, str)
        self.assertEqual(returned_data, return_expected)