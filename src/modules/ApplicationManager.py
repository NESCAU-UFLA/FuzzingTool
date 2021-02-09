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

from .parsers.CLIParser import CLIParser
from .core.Fuzzer import Fuzzer
from .conn.Request import Request
from .conn.RequestException import RequestException
from .IO.OutputHandler import outputHandler as oh
from .IO.FileHandler import fileHandler as fh

import time

APP_VERSION = {
    'MAJOR_VERSION': 3,
    "MINOR_VERSION": 5,
    "PATCH": 0
}

def version():
    global APP_VERSION
    version = (str(APP_VERSION['MAJOR_VERSION'])+"."+
               str(APP_VERSION['MINOR_VERSION'])+"."+
               str(APP_VERSION['PATCH']))
    return version

def banner():
    banner = ("\033[36m   ____                        _____       _"+'\n'+
              "\033[36m  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| | \033[0mVersion "+version()+'\n'+
              "\033[36m  |  __| | |- _|- _|'|   | . |  | | . | . | |"+'\n'+
              "\033[36m  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|"+'\n'+
              "\033[36m                         |___|\033[0m\n\n"
              "  [!] Disclaimer: We're not responsible for the misuse of this tool.\n"
              "      This project was created for educational purposes\n"
              "      and should not be used in environments without legal authorization.\n")
    return banner

class ApplicationManager:
    """Class that handle with the entire application

    Attributes:
        fuzzer: The fuzzer object
        requester: The request object
        startedTime: The time when start the fuzzing test
    """
    def __init__(self):
        """Class constructor"""
        self.__fuzzer = None
        self.__requester = None
        self.__startedTime = 0

    def main(self, argv: list):
        """The main function

        @type argv: list
        @param argv: The arguments given in the execution
        """
        if (len(argv) < 2):
            oh.print(banner())
            oh.errorBox("Invalid format! Use -h on 2nd parameter to show the help menu.")
        if (argv[1] == '-h' or argv[1] == '--help'):
            oh.showHelpMenu()
        if (argv[1] == '-v' or argv[1] == '--version'):
            exit("FuzzingTool v"+version())
        oh.print(banner())
        cliParser = CLIParser(argv)
        url, method, requestData, httpHeader = cliParser.getDefaultRequestData()
        cliParser.getWordlistFile()
        self.__fuzzer = Fuzzer(Request(url, method, requestData, httpHeader))
        self.__requester = self.__fuzzer.getRequester()
        oh.infoBox(f"Set target: {self.__requester.getUrl()}")
        oh.infoBox(f"Set request method: {method}")
        if requestData:
            oh.infoBox(f"Set request data: {str(requestData)}")
        cliParser.checkCookie(self.__requester)
        cliParser.checkProxy(self.__requester)
        cliParser.checkProxies(self.__requester)
        cliParser.checkDelay(self.__fuzzer)
        cliParser.checkVerboseMode(self.__fuzzer)
        cliParser.checkNumThreads(self.__fuzzer)
        cliParser.checkPrefixAndSuffix(self.__requester)
        self.prepare()
        self.start()

    def prepare(self):
        """Prepares the application"""
        try:
            self.__checkConnectionAndRedirections()
            self.__checkProxies()
        except KeyboardInterrupt:
            exit('')

    def start(self):
        """Starts the application"""
        oh.infoBox(f"Starting test on '{self.__requester.getUrl()}' ...")
        self.__startedTime = time.time()
        try:
            if self.__fuzzer.isVerboseMode() and not self.__requester.isSubdomainFuzzing():
                oh.getHeader()
            self.__fuzzer.start()
        except KeyboardInterrupt:
            self.__fuzzer.stop()
            oh.abortBox("Test aborted")
            self.__showFooter()
        else:
            if self.__fuzzer.isVerboseMode():
                if not self.__requester.isSubdomainFuzzing():
                    oh.getHeader()
            else:
                print("")
            self.__showFooter()
            oh.infoBox("Test completed")

    def __checkConnectionAndRedirections(self):
        """Test the connection and redirection to target"""
        # If we'll not fuzzing the url paths, so
        # test the redirections before start the fuzzing
        if self.__requester.isUrlFuzzing():
            oh.infoBox("Test mode set to URL Fuzzing")
            try:
                self.__requester.testConnection()
            except RequestException as e:
                if not oh.askYesNo(f"Connection to {str(e)} failed. Continue anyway? "):
                    exit()
            else:
                oh.infoBox("Connection status: OK")
        else:
            try:
                self.__requester.testConnection()
            except RequestException as e:
                oh.errorBox(f"Failed to connect to {str(e)}")
            oh.infoBox("Connection status: OK")
            oh.infoBox("Testing redirections ...")
            if self.__requester.hasRedirection():
                if (not oh.askYesNo("You was redirected to another page. Continue? (y/N): ")):
                    exit()
            else:
                oh.infoBox("No redirections")
    
    def __checkProxies(self):
        """Check for connection status using a proxy, if a proxy is given"""
        if self.__requester.getProxy():
            oh.infoBox("Testing proxy ...")
            try:
                self.__requester.testConnection(proxy=True)
                oh.infoBox(f"Proxy {self.__requester.getProxy()['http']} worked")
            except RequestException:
                oh.warningBox(f"Proxy {proxy['http']} not worked")
                self.__requester.setProxy({})
        elif self.__requester.getProxyList():
            proxyList = []
            oh.infoBox("Testing proxies ...")
            for proxy in self.__requester.getProxyList():
                self.__requester.setProxy(proxy)
                proxyList.append(proxy)
                try:
                    self.__requester.testConnection(proxy=True)
                    proxyList.append(proxy)
                    oh.infoBox(f"Proxy {proxy['http']} worked")
                except RequestException:
                    oh.warningBox(f"Proxy {proxy['http']} not worked")
            self.__requester.setProxy({})
            self.__requester.setProxyList(proxyList)

    def __showFooter(self):
        """Show the footer content of the software, after maked the fuzzing"""
        if self.__startedTime:
            oh.infoBox(f"Time taken: {float('%.2f'%(time.time() - self.__startedTime))} seconds")
        output = self.__fuzzer.getOutput()
        if output:
            oh.infoBox(f"Found {len(output)} possible payload(s)")
            oh.getHeader()
            for content in output:
                oh.printContent([value for key, value in content.items()], True)
            oh.getHeader()
            fh.writeOnOutput(output)
        else:
            oh.infoBox("No vulnerable entries was found")