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

from abc import ABC, abstractmethod
from typing import List
from pathlib import Path

from ..objects.result import Result
from ..utils.consts import OUTPUT_DIRECTORY


class BaseReport(ABC):
    """Base Report

    Attributes:
        filename: The report filename
        file: The file object
    """
    def __init__(self, filename: str = ''):
        """Class constructor

        @type filename: str
        @param filename: The report filename
        """
        self.__filename = filename
        self._file = None

    def open(self, host: str) -> str:
        """Opens the report file to store the results

        @type host: str
        @param host: The target hostname
        @returns str: The report path and name
        """
        report_type = self.file_extension
        report_name = self.__filename
        report_dir = f"{OUTPUT_DIRECTORY}/{host}/reports"
        report_full_path = Path(f'{report_dir}/{report_name}.{report_type}')
        try:
            self._file = open(report_full_path, 'w')
        except FileNotFoundError:
            Path(report_dir).mkdir(parents=True, exist_ok=True)
            self._file = open(report_full_path, 'w')
        return str(report_full_path)

    def write(self, results: List[Result]) -> None:
        """Write the results in the report file,
           also a header and footer if the report supports it

        @type results: List[Result]
        @param results: The results objects list
        """
        self._header()
        self._results(results)
        self._footer()
        self._file.close()

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Gets the file type"""
        pass

    @abstractmethod
    def _header(self) -> None:
        """Writes the header information on the report"""
        pass

    @abstractmethod
    def _results(self, results: List[Result]) -> None:
        """Writes the results on the report

        @type results: List[Result]
        @param results: The results objects list
        """
        pass

    @abstractmethod
    def _footer(self) -> None:
        """Writes the footer information on the report"""
        pass
