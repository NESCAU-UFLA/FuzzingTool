## FuzzingTool
# 
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from ..core.Result import Result

import csv
import json
from datetime import datetime
from pathlib import Path

OUTPUT_DIRECTORY = f'{Path.home()}/.FuzzingTool'

class Logger:
    def setup(self, host: str):
        """Setup the log path to save the current logs
        
        @type host: str
        @param host: The target hostname
        @returns str: The log path and name
        """
        dateNow = datetime.now()
        logFileName = f"log-{dateNow.strftime('%Y-%m-%d_%H:%M')}.log"
        logDir = f'{OUTPUT_DIRECTORY}/{host}/logs'
        self.__logFullPath = f'{logDir}/{logFileName}'
        try:
            logFile = open(self.__logFullPath, 'w+')
        except FileNotFoundError:
            Path(logDir).mkdir(parents=True, exist_ok=True)
            logFile = open(self.__logFullPath, 'w+')
        logFile.write(f"Log for {host} on {dateNow.strftime('%Y/%m/%d %H:%M')}\n\n")
        logFile.close()
        return self.__logFullPath

    def write(self, exception: str, payload: str):
        """Write the exception on the log file

        @type exception: str
        @param exception: The exception to be saved on the log file
        @type payload: str
        @param payload: The payload used in the request
        """
        time = datetime.now().strftime("%H:%M:%S")
        logFile = open(self.__logFullPath, 'a')
        logFile.write(f'{time} | {exception} using payload: {payload}\n')
        logFile.close()

class Reporter:
    def __init__(self):
        self.__metadata = {
            'Type': 'txt',
            'Name': '',
        }
        self.__file = None
    
    def setMetadata(self, report: str):
        """The report metadata setter

        @type report: str
        @param report: The report format and name
        """
        if '.' in report:
            reportName, reportType = report.rsplit('.', 1)
        else:
            reportType = report
            reportName = ''
        reportType = reportType.lower()
        if reportType not in ['txt', 'csv', 'json']:
            raise Exception(f"Unsupported report format for {reportType}! Accepts: txt, csv and json")
        self.__metadata = {
            'Type': reportType,
            'Name': reportName,
        }
    
    def open(self, host: str):
        """Opens the report file to store the FuzzingTool matcher results
        
        @type host: str
        @param host: The target hostname
        @returns str: The report path and name
        """
        reportType = self.__metadata['Type']
        reportName = self.__metadata['Name']
        reportDir = f"{OUTPUT_DIRECTORY}/{host}/reports"
        if not reportName:
            now = datetime.now()
            reportName = now.strftime("%Y-%m-%d_%H:%M")
        reportFullPath = f'{reportDir}/{reportName}.{reportType}'
        try:
            self.__file = open(reportFullPath, 'w')
        except FileNotFoundError:
            Path(reportDir).mkdir(parents=True, exist_ok=True)
            self.__file = open(reportFullPath, 'w')
        return reportFullPath

    def write(self, results: list):
        """Write the vulnerable input and response content into a report
        
        @type results: list
        @param results: The list with the FuzzingTool matched results
        """
        if self.__metadata['Type'] == 'txt':
            self.__txtWriter(results)
        elif self.__metadata['Type'] == 'csv':
            self.__csvWriter(results)
        elif self.__metadata['Type'] == 'json':
            self.__jsonWriter(results)
        self.__file.close()

    def __txtWriter(self, results: list):
        """The txt report writer

        @type results: list
        @param results: The list with the FuzzingTool matched results
        """
        for content in results:
            for key, value in content:
                self.__file.write(f'{key}: {str(value)}\n')
            self.__file.write('\n')
    
    def __csvWriter(self, results: list):
        """The csv report writer

        @type results: list
        @param results: The list with the FuzzingTool matched results
        """
        writer = csv.DictWriter(
            self.__file,
            fieldnames=[key for key in dict(results[0]).keys()]
        )
        writer.writeheader()
        for content in results:
            writer.writerow(dict(content))

    def __jsonWriter(self, results: list):
        """The json report writer

        @type results: list
        @param results: The list with the FuzzingTool matched results
        """
        json.dump([dict(result) for result in results], self.__file)

class FileHandler:
    """Class that handle with the files
       Singleton Class
    """
    __instance = None

    @staticmethod
    def getInstance():
        if FileHandler.__instance == None:
            FileHandler()
        return FileHandler.__instance

    """
    Attributes:
        logger: The object that handles with the log files
        reporter: The object that handles with the report files
    """
    def __init__(self):
        if FileHandler.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            FileHandler.__instance = self
        self.logger = Logger()
        self.reporter = Reporter()

    def read(self, fileName: str):
        """Reads content of a file.

        @type fileName: str
        @param fileName: The file path and name
        @returns list: The content into the file
        """
        try:
            with open(f'{fileName}', 'r') as thisFile:
                return [line.rstrip('\n') for line in thisFile if not line.startswith('#!')]
        except FileNotFoundError:
            raise Exception(f"File '{fileName}' not found")

fileHandler = FileHandler.getInstance()