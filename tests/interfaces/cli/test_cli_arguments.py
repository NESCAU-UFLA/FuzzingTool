import unittest
from argparse import Namespace

from src.fuzzingtool.interfaces.cli.cli_arguments import CliArguments
from src.fuzzingtool.exceptions import BadArgumentFormat
from ...mock_utils.args_decorator import mock_sys_args


class TestCliArguments(unittest.TestCase):
    @mock_sys_args([])
    def test_invalid_args(self):
        with self.assertRaises(BadArgumentFormat):
            CliArguments()

    @mock_sys_args(['-h'])
    def test_help(self):
        CliArguments()

    @mock_sys_args(['-h=encoders'])
    def test_encoders_help(self):
        with self.assertRaises(SystemExit):
            CliArguments()

    @mock_sys_args(['-h=scanners'])
    def test_scanners_help(self):
        with self.assertRaises(SystemExit):
            CliArguments()

    @mock_sys_args(['-h=wordlists'])
    def test_wordlists_help(self):
        with self.assertRaises(SystemExit):
            CliArguments()

    @mock_sys_args(['-h=test'])
    def test_invalid_help_type(self):
        with self.assertRaises(BadArgumentFormat):
            CliArguments()

    @mock_sys_args(['-w', 'test', '-u', 'https://test-url.com/'])
    def test_args(self):
        returned_arguments = CliArguments().get_arguments()
        self.assertIsInstance(returned_arguments, Namespace)
