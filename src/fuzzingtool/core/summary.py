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

import time


class Summary:
    """Class to store the summary information of the controller

    Attributes:
        results: The list of the found results
        elapsed_time: The elapsed time of the fuzzing test
        time_before: A buffer to handle with the pause and resume timer
    """
    def __init__(self):
        self.results = []
        self.elapsed_time = 0
        self.__time_before = 0

    def start_timer(self) -> None:
        """Starts the timer"""
        self.elapsed_time = time.time()

    def stop_timer(self) -> None:
        """Stops the timer"""
        if self.__time_before:
            self.resume_timer()
        self.elapsed_time = time.time() - self.elapsed_time

    def pause_timer(self) -> None:
        """Pauses the timer"""
        self.__time_before = time.time()

    def resume_timer(self) -> None:
        """Resumes the timer"""
        self.elapsed_time += (time.time() - self.__time_before)
        self.__time_before = 0
