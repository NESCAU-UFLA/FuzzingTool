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

from datetime import datetime
from pathlib import Path

from .consts import OUTPUT_DIRECTORY


class Logger:
    """Class to handle with the program logging

    Attributes:
        log_full_path: The path of the log file
    """
    def __init__(self):
        self.__log_full_path = ''

    def setup(self, host: str) -> str:
        """Setup the log path to save the current logs

        @type host: str
        @param host: The target hostname
        @returns str: The log path and name
        """
        date_now = datetime.now()
        log_file_name = f"log-{date_now.strftime('%Y-%m-%d_%H:%M')}.log"
        log_dir = f'{OUTPUT_DIRECTORY}/{host}/logs'
        self.__log_full_path = Path(f'{log_dir}/{log_file_name}')
        try:
            log_file = open(self.__log_full_path, 'w+')
        except FileNotFoundError:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            log_file = open(self.__log_full_path, 'w+')
        log_file.write(
            f"Log for {host} on {date_now.strftime('%Y/%m/%d %H:%M')}\n\n"
        )
        log_file.close()
        return str(self.__log_full_path)

    def write(self, exception: str, payload: str) -> None:
        """Write the exception on the log file

        @type exception: str
        @param exception: The exception to be saved on the log file
        @type payload: str
        @param payload: The payload used in the request
        """
        time = datetime.now().strftime("%H:%M:%S")
        with open(self.__log_full_path, 'a') as log_file:
            log_file.write(f'{time} | {exception} using payload: {payload}\n')
