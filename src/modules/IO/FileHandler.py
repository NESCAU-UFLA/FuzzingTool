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

import os
import csv
import json
from datetime import datetime

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
        outputFile: The output file
        report: The report format and name dict
    """
    def __init__(self):
        """Class constructor"""
        if FileHandler.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            FileHandler.__instance = self
        self.__wordlistFile = None
        self.__outputFile = None
        self.__report = {
            'Type': 'txt',
            'Name': ''
        }
    
    def readData(self, dataFileName: str):
        '''Reads the default data of the requests.

        @type dataFileName: str
        @param dataFileName: The filename
        @returns list: The content into data file
        '''
        try:
            with open('./input/'+dataFileName, 'r') as dataFile:
                return [data.rstrip('\n') for data in dataFile]
        except FileNotFoundError:
            oh.errorBox("File '"+dataFileName+"' not found.")

    def getProxiesFile(self):
        """The proxiesFile getter

        @returns file: The proxies file
        """
        return self.__proxiesFile

    def readProxies(self, proxiesFileName: str):
        """Open the proxies file, and read the proxies
        
        @type proxiesFileName: str
        @param proxiesFileName: The name of the proxies file
        @returns list: The list with proxies dictionary
        """
        proxies = []
        try:
            with open('./input/'+proxiesFileName, 'r') as proxiesFile:
                for line in proxiesFile:
                    line = line.rstrip("\n")
                    proxies.append({
                        'http': 'http://'+line,
                        'https': 'https://'+line
                    })
        except FileNotFoundError:
            oh.errorBox("File '"+proxiesFileName+"' not found.")
        return proxies

    def openWordlist(self, wordlistFileName: str):
        """Open the wordlist file

        @type wordlistFileName: str
        @param wordlistFileName: The name of the wordlist file
        """
        try:
            self.__wordlistFile = open('./input/'+wordlistFileName, 'r')
        except FileNotFoundError:
            oh.errorBox("File '"+wordlistFileName+"' not found. Did you put it in the correct directory?")

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

    def writeOnOutput(self, outputContent: list):
        """Write the vulnerable input and response content into a report

        @param type: list
        @param outputContent: The list with probably vulnerable content
        """
        if outputContent:
            self.__openOutput()
            if self.__report['Type'] == 'txt':
                self.__txtWriter(outputContent)
            elif self.__report['Type'] == 'csv':
                self.__csvWriter(outputContent)
            elif self.__report['Type'] == 'json':
                self.__jsonWriter(outputContent)
            self.__close(self.__outputFile)
            oh.infoBox('Results saved')

    def __openOutput(self):
        """Opens the output file 
           for store the probably vulnerable response data
        """
        reportType = self.__report['Type']
        reportName = self.__report['Name']
        if not reportName:
            now = datetime.now()
            reportName = now.strftime("%Y-%m-%d_%H:%M")
        try:
            self.__outputFile = open(f'./output/{reportType}/{reportName}.{reportType}', 'w')
        except FileNotFoundError:
            if not os.path.exists('./output'):
                os.system('mkdir ./output')
            os.system(f'mkdir ./output/{reportType}')
            self.__outputFile = open(f'./output/{reportType}/{reportName}.{reportType}', 'w')
        finally:
            oh.infoBox(f'Saving results on \'./output/{reportType}/{reportName}.{reportType}\' ...')

    def __close(self, file: object):
        """Closes the file

        @type file: object
        @param file: The file
        """
        file.close()

    def __txtWriter(self, outputContent: list):
        """The txt report writer

        @param type: list
        @param outputContent: The list with probably vulnerable content
        """
        for content in outputContent:
            for key, value in content.items():
                self.__outputFile.write(key+': '+str(value)+'\n')
            self.__outputFile.write('\n')
    
    def __csvWriter(self, outputContent: list):
        """The csv report writer

        @param type: list
        @param outputContent: The list with probably vulnerable content
        """
        writer = csv.DictWriter(
            self.__outputFile,
            fieldnames=[key for key, value in outputContent[0].items()]
        )
        writer.writeheader()
        for content in outputContent:
            writer.writerow(content)

    def __jsonWriter(self, outputContent: list):
        """The json report writer

        @param type: list
        @param outputContent: The list with probably vulnerable content
        """
        json.dump(outputContent, self.__outputFile)

fileHandler = FileHandler.getInstance()