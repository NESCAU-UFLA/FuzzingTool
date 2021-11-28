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

import csv
from typing import List

from ..base_report import BaseReport
from ...decorators.report_meta import report_meta
from ...objects.result import Result


@report_meta
class CsvReport(BaseReport):
    __author__ = ("Vitor Oriel",)
    __version__ = "0.1"

    file_extension = 'csv'

    def _header(self) -> None:
        """Do not write any header"""
        pass

    def _results(self, results: List[Result]) -> None:
        writer = csv.DictWriter(
            self._file,
            fieldnames=[key for key in dict(results[0]).keys()]
        )
        writer.writeheader()
        for content in results:
            writer.writerow(dict(content))

    def _footer(self) -> None:
        """Do not write any footer"""
        pass
