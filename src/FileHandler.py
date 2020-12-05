from OutputHandler import *
from datetime import datetime
import os

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
    
    def __init__(self):
        """Class constructor"""
        if FileHandler.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            FileHandler.__instance = self
        self.__wordlistFile = None
        self.__proxiesFile = None
        self.__outputFile = None
    
    def getProxiesFile(self):
        return self.__proxiesFile

    def openProxies(self, proxiesFileName: str):
        try:
            self.__proxiesFile = open('../input/'+proxiesFileName, 'r')
        except FileNotFoundError:
            oh.errorBox("File '"+fileName+"' not found.")

    def readProxies(self):
        """Read the proxies from a file"""
        proxies = []
        for line in self.__proxiesFile:
            line = line.rstrip("\n")
            proxies.append({
                'http://': 'http://'+line,
                'https://': 'http://'+line
            })
        self.__close(self.__proxiesFile)
        return proxies

    def openWordlist(self, wordlistFileName: str):
        try:
            self.__wordlistFile = open('../input/'+wordlistFileName, 'r')
        except FileNotFoundError:
            oh.errorBox("File '"+wordlistFileName+"' not found. Did you put it in the correct directory?")

    def getWordlistContentAndLength(self):
        wordlist = []
        length = 0
        for line in self.__wordlistFile:
            line = line.rstrip("\n")
            wordlist.append(line)
            length += 1
        self.__close(self.__wordlistFile)
        return (wordlist, length)

    def writeOnOutput(self, outputContent: list):
        """Write the vulnerable input and response content into a file

        @param type: list
        @param outputContent: The list with probably vulnerable content
        """
        self.__openOutput()
        for content in outputContent:
            for key, value in content.items():
                self.__outputFile.write(key+': '+value+'\n')
            self.__outputFile.write('\n')
        self.__close(self.__outputFile)

    def __openOutput(self):
        """Opens the output file 
           for store the probably vulnerable response data
        """
        t = datetime.now()
        try:
            self.__outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')
        except FileNotFoundError:
            os.system('mkdir ../output')
            self.__outputFile = open('../output/'+str(t.year)+'-'+str(t.month)+'-'+str(t.day)+'_'+str(t.hour)+':'+str(t.minute)+'.txt', 'w')

    def __close(self, file: object):
        file.close()

fh = FileHandler.getInstance()