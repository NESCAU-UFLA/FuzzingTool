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

from .OutputHandler import outputHandler as oh

import platform
import os
import csv
import json
from datetime import datetime
from pathlib import Path

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
        wordlistFile: The wordlist file
        report: The report format and name dict
        reportFile: The report file
        logFile: The log file
    """
    def __init__(self):
        """Class constructor"""
        if FileHandler.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            FileHandler.__instance = self
        self.__outputDirectory = f'{Path.home()}/.FuzzingTool'
        self.__wordlistFile = None
        self.__report = {
            'Type': 'txt',
            'Name': '',
            'Host': ''
        }
        self.__reportFile = None
        self.__logFile = None
    
    def __del__(self):
        """Class destructor"""
        if self.__logFile: # If the logFile is open, closes the file
            self.__close(self.__logFile)

    def readRaw(self, rawFile: str):
        '''Reads the raw HTTP request.

        @type rawFile: str
        @param rawFile: The file path and name
        @returns list: The content into data file
        '''
        try:
            with open(f'{rawFile}', 'r') as rawFile:
                return [data.rstrip('\n') for data in rawFile]
        except FileNotFoundError:
            oh.errorBox(f"File '{rawFile}' not found.")

    def getProxiesFile(self):
        """The proxiesFile getter

        @returns file: The proxies file
        """
        return self.__proxiesFile

    def readProxies(self, proxiesFile: str):
        """Open the proxies file, and read the proxies
        
        @type proxiesFile: str
        @param proxiesFile: The proxies file path and name
        @returns list: The list with proxies dictionary
        """
        proxies = []
        try:
            with open(f'{proxiesFile}', 'r') as proxiesFile:
                for line in proxiesFile:
                    line = line.rstrip("\n")
                    proxies.append({
                        'http': 'http://'+line,
                        'https': 'https://'+line
                    })
        except FileNotFoundError:
            oh.errorBox(f"File '{proxiesFile}' not found")
        return proxies

    def openWordlist(self, wordlistFile: str):
        """Open the wordlist file

        @type wordlistFile: str
        @param wordlistFile: The wordlist file path and name
        """
        try:
            self.__wordlistFile = open(f'{wordlistFile}', 'r')
        except FileNotFoundError:
            oh.errorBox(f"File '{wordlistFile}' not found. Did you put it in the correct directory?")

    def setReport(self, report: dict):
        """The report setter

        @type report: dict
        @param report: The report format and name dict
        """
        self.__report = report

    def getWordlistContentAndLength(self):
        """Get the wordlist content, into a list, and the number of lines in file

        @returns tuple(list, int): The tuple with the wordlist and the number of lines
        """
        wordlist = []
        length = 0
        for line in self.__wordlistFile:
            line = line.rstrip("\n")
            wordlist.append(line)
            length += 1
        self.__close(self.__wordlistFile)
        return (wordlist, length)

    def openLog(self):
        """Open the log file to save the current logs"""
        now = datetime.now()
        logFileName = f'log-{now.strftime("%Y-%m-%d_%H:%M")}.log'
        logDir = f'{self.__outputDirectory}/logs'
        logFullPath = f'{logDir}/{logFileName}'
        try:
            self.__logFile = open(logFullPath, 'w')
        except FileNotFoundError:
            Path(logDir).mkdir(parents=True, exist_ok=True)
            self.__logFile = open(logFullPath, 'w')
        finally:
            oh.infoBox(f'The logs will be saved on \'{logFullPath}\'')

    def writeLog(self, exception: str):
        """Write the exception on the log file

        @type exception: str
        @param exception: The exception to be saved on the log file
        """
        now = datetime.now()
        time = now.strftime("%H:%M:%S")
        self.__logFile.write(f'{time} | {exception}\n')

    def writeReport(self, reportContent: list):
        """Write the vulnerable input and response content into a report

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        if reportContent:
            self.__openReport()
            if self.__report['Type'] == 'txt':
                self.__txtWriter(reportContent)
            elif self.__report['Type'] == 'csv':
                self.__csvWriter(reportContent)
            elif self.__report['Type'] == 'json':
                self.__jsonWriter(reportContent)
            self.__close(self.__reportFile)
            oh.infoBox('Results saved')

    def __openReport(self):
        """Opens the report file 
           for store the probably vulnerable response data
        """
        reportType = self.__report['Type']
        reportName = self.__report['Name']
        reportDir = f"{self.__outputDirectory}/reports/{self.__report['Host']}"
        if not reportName:
            now = datetime.now()
            reportName = now.strftime("%Y-%m-%d_%H:%M")
        reportFullPath = f'{reportDir}/{reportName}.{reportType}'
        try:
            self.__reportFile = open(reportFullPath, 'w')
        except FileNotFoundError:
            Path(reportDir).mkdir(parents=True, exist_ok=True)
            self.__reportFile = open(reportFullPath, 'w')
        finally:
            oh.infoBox(f'Saving results on \'{reportFullPath}\' ...')

    def __close(self, file: object):
        """Closes the file

        @type file: object
        @param file: The file
        """
        file.close()

    def __txtWriter(self, reportContent: list):
        """The txt report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        for content in reportContent:
            for key, value in content.items():
                self.__reportFile.write(f'{key}: {str(value)}\n')
            self.__reportFile.write('\n')
    
    def __csvWriter(self, reportContent: list):
        """The csv report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        writer = csv.DictWriter(
            self.__reportFile,
            fieldnames=[key for key, value in reportContent[0].items()]
        )
        writer.writeheader()
        for content in reportContent:
            writer.writerow(content)

    def __jsonWriter(self, reportContent: list):
        """The json report writer

        @param type: list
        @param reportContent: The list with probably vulnerable content
        """
        json.dump(reportContent, self.__reportFile)

fileHandler = FileHandler.getInstance()