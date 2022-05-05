import unittest
from unittest.mock import Mock, patch
from datetime import datetime

from src.fuzzingtool.persistence import reports
from src.fuzzingtool.persistence.base_report import BaseReport
from src.fuzzingtool.persistence.report import Report, get_report_name_and_type
from src.fuzzingtool.persistence.reports import TxtReport
from src.fuzzingtool.exceptions import InvalidArgument


class TestReport(unittest.TestCase):
    def test_get_report_name_and_type_with_full_name(self):
        return_expected = ("test_report", "txt")
        test_name = "test_report.txt"
        returned_data = get_report_name_and_type(test_name)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.persistence.report.datetime")
    def test_get_report_name_and_type_with_only_extension(self, mock_datetime: Mock):
        test_datetime_now = datetime(2021, 1, 1, 0, 0)
        mock_datetime.now.return_value = test_datetime_now
        return_expected = (test_datetime_now.strftime("%Y-%m-%d_%H:%M"), "txt")
        test_name = "txt"
        returned_data = get_report_name_and_type(test_name)
        self.assertIsInstance(returned_data, tuple)
        self.assertEqual(returned_data, return_expected)

    def test_get_available_reports(self):
        return_expected = {'txt': TxtReport}
        with patch.dict(reports.__dict__, {'TxtReport': TxtReport, 'Test': None}, clear=True):
            returned_data = Report.get_available_reports()
        self.assertIsInstance(returned_data, dict)
        self.assertEqual(returned_data, return_expected)

    @patch("src.fuzzingtool.persistence.report.Report.get_available_reports")
    def test_build(self, mock_get_available_reports: Mock):
        test_name = "test_report.txt"
        mock_get_available_reports.return_value = {'txt': TxtReport}
        returned_data = Report.build(test_name)
        self.assertIsInstance(returned_data, BaseReport)

    @patch("src.fuzzingtool.persistence.report.Report.get_available_reports")
    def test_build_with_invalid_format(self, mock_get_available_reports: Mock):
        test_name = "test_report.test"
        mock_get_available_reports.return_value = {'txt': TxtReport}
        with self.assertRaises(InvalidArgument):
            Report.build(test_name)
