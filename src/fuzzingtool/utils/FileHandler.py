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

import csv
import json
from datetime import datetime
from pathlib import Path

OUTPUT_DIRECTORY = f'{Path.home()}/.FuzzingTool'

class Logger:
    def __init__(self):
        self.__file = None

    def __del__(self):
        self.close()

    def open(self, host: str):
        """Open the log file to save the current logs
        
        @type host: str
        @param host: The target hostname
        @returns str: The log path and name
        """
        now = datetime.now()
        logFileName = f'log-{now.strftime("%Y-%m-%d_%H:%M")}.log'
        logDir = f'{OUTPUT_DIRECTORY}/{host}/logs'
        logFullPath = f'{logDir}/{logFileName}'
        try:
            self.__file = open(logFullPath, 'w')
        except FileNotFoundError:
            Path(logDir).mkdir(parents=True, exist_ok=True)
            self.__file = open(logFullPath, 'w')
        return logFullPath

    def write(self, exception: str):
        """Write the exception on the log file

        @type exception: str
        @param exception: The exception to be saved on the log file
        """
        now = datetime.now()
        time = now.strftime("%H:%M:%S")
        self.__file.write(f'{time} | {exception}\n')
    
    def close(self):
        """Closes the log file if it's open"""
        if self.__file:
            self.__file.close()

class Reporter:
    def __init__(self):
        self.__metadata = {
            'Type': 'txt',
            'Name': '',
        }
        self.__file = None
    
    def setMetadata(self, report: str):
        """The report setter

        @type report: str
        @param report: The report format and name
        """
        if '.' in report:
            reportName, reportType = report.split('.')
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
        """Opens the report file 
           for store the probably vulnerable response data
        
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

    def write(self, results: dict):
        """Write the vulnerable input and response content into a report

        @param type: dict
        @param results: The list with probably vulnerable content
        """
        if self.__metadata['Type'] == 'txt':
            self.__txtWriter(results)
        elif self.__metadata['Type'] == 'csv':
            self.__csvWriter(results)
        elif self.__metadata['Type'] == 'json':
            self.__jsonWriter(results)
        self.__file.close()

    def __txtWriter(self, reportContent: list):
        """The txt report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        for content in reportContent:
            for key, value in content.items():
                self.__file.write(f'{key}: {str(value)}\n')
            self.__file.write('\n')
    
    def __csvWriter(self, reportContent: list):
        """The csv report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        writer = csv.DictWriter(
            self.__file,
            fieldnames=[key for key in reportContent[0].keys()]
        )
        writer.writeheader()
        for content in reportContent:
            writer.writerow(content)

    def __jsonWriter(self, reportContent: list):
        """The json report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        json.dump(reportContent, self.__file)

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
            raise Exception(f"File '{fileName}' not found.")

fileHandler = FileHandler.getInstance()