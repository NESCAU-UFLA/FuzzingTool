import unittest

from fuzzingtool.interfaces.argument_builder import ArgumentBuilder as AB


class TestArgumentBuilder(unittest.TestCase):
    def test_build_wordlist(self):
        return_expected = [('DnsZone', ''), ('Robots', 'http://test-url.com/')]
        returned_wordlist = AB.build_wordlist('DnsZone;Robots=http://test-url.com/')
        self.assertIsInstance(returned_wordlist, list)
        self.assertEqual(returned_wordlist, return_expected)

    def test_build_encoder(self):
        return_expected = [[('Plain', '')], [('Url', '5'), ('Hex', '')]]
        returned_encoders = AB.build_encoder('Plain,Url=5@Hex')
        self.assertIsInstance(returned_encoders, list)
        self.assertEqual(returned_encoders, return_expected)

    def test_build_scanner(self):
        return_expected = ('Grep', 'email')
        returned_scanner = AB.build_scanner('Grep=email')
        self.assertIsInstance(returned_scanner, tuple)
        self.assertEqual(returned_scanner, return_expected)

    def test_build_verbose_mode_without_verbose(self):
        return_expected = [False, False]
        returned_verbose = AB.build_verbose_mode(False, False)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_verbose_mode_with_common_verbose(self):
        return_expected = [True, False]
        returned_verbose = AB.build_verbose_mode(True, False)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_verbose_mode_with_detailed_verbose(self):
        return_expected = [True, True]
        returned_verbose = AB.build_verbose_mode(False, True)
        self.assertIsInstance(returned_verbose, list)
        self.assertEqual(returned_verbose, return_expected)

    def test_build_blacklist_status_without_action(self):
        return_expected = ('429', 'stop', '')
        returned_blacklist = AB.build_blacklist_status('429')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)

    def test_build_blacklist_status_with_action(self):
        return_expected = ('429', 'stop', '')
        returned_blacklist = AB.build_blacklist_status('429:stop')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)

    def test_build_blacklist_status_with_action_and_param(self):
        return_expected = ('429', 'wait', '5')
        returned_blacklist = AB.build_blacklist_status('429:wait=5')
        self.assertIsInstance(returned_blacklist, tuple)
        self.assertEqual(returned_blacklist, return_expected)
