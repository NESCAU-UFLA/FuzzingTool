import unittest
from unittest.mock import Mock, patch

from fuzzingtool.reports import reports
from fuzzingtool.reports.base_report import BaseReport
from fuzzingtool.reports.report import Report
from fuzzingtool.reports.reports import TxtReport
from fuzzingtool.exceptions.main_exceptions import InvalidArgument


class TestReport(unittest.TestCase):
    def test_get_available_reports(self):
        return_expected = {'txt': TxtReport}
        with patch.dict(reports.__dict__, {'TxtReport': TxtReport, 'Test': None}, clear=True):
            returned_data = Report.get_available_reports()
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)

    @patch("fuzzingtool.reports.report.Report.get_available_reports")
    def test_build(self, mock_get_available_reports: Mock):
        test_name = "test_report.txt"
        mock_get_available_reports.return_value = {'txt': TxtReport}
        returned_data = Report.build(test_name)
        self.assertIsInstance(returned_data, BaseReport)

    @patch("fuzzingtool.reports.report.Report.get_available_reports")
    def test_build_with_only_extension(self, mock_get_available_reports: Mock):
        test_name = "txt"
        mock_get_available_reports.return_value = {'txt': TxtReport}
        returned_data = Report.build(test_name)
        self.assertIsInstance(returned_data, BaseReport)

    @patch("fuzzingtool.reports.report.Report.get_available_reports")
    def test_build_with_invalid_format(self, mock_get_available_reports: Mock):
        test_name = "test_report.test"
        mock_get_available_reports.return_value = {'txt': TxtReport}
        with self.assertRaises(InvalidArgument):
            Report.build(test_name)
