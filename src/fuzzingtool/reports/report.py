# Copyright (c) 2020 - present Vitor Oriel <https://github.com/VitorOriel>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from typing import Dict, Type

from . import reports
from .base_report import BaseReport
from ..utils.utils import stringfy_list
from ..exceptions.main_exceptions import InvalidArgument


class Report:
    """Class that handles with the report operations"""
    @staticmethod
    def get_available_reports() -> Dict[str, Type[BaseReport]]:
        """Gets the available report formats

        @returns Dict[str, Type[BaseReport]]: The dict that contains
                                              the available reports
        """
        return {cls.file_extension: cls for cls in reports.__dict__.values()
                if isinstance(cls, type(BaseReport))}

    @staticmethod
    def build(name: str) -> BaseReport:
        """Build the report

        @type name: str
        @param name: The name of the report file
        @returns BaseReport: The report object
        """
        if '.' in name:
            report_name, report_type = name.rsplit('.', 1)
        else:
            report_type = name
            report_name = ''
        report_type = report_type.lower()
        available_reports = Report.get_available_reports()
        try:
            return available_reports[report_type](report_name)
        except KeyError:
            raise InvalidArgument(
                f"Unsupported report format for {report_type}! Accepts: "
                + stringfy_list(list(available_reports.keys()))
            )
