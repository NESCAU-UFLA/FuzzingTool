#!/usr/bin/python3

## FuzzingTool
# 
# Version: 3.4.0
# Authors:
#    Vitor Oriel C N Borges <https://github.com/VitorOriel>
# License: MIT (LICENSE.md)
#    Copyright (c) 2021 Vitor Oriel
#    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
## https://github.com/NESCAU-UFLA/FuzzingTool

from modules.ApplicationManager import ApplicationManager
from modules.core.Fuzzer import Fuzzer
from modules.parsers.CLIParser import CLIParser
from modules.conn.Request import Request
from modules.IO.OutputHandler import outputHandler as oh

import sys

def main(argv: list):
    """The main function

    @type argv: list
    @param argv: The arguments given in the execution
    """
    oh.showIntro()
    cliParser = CLIParser(argv)
    url, method, requestData, httpHeader = cliParser.getDefaultRequestData()
    cliParser.getWordlistFile()
    fuzzer = Fuzzer(Request(url, method, requestData, httpHeader))
    oh.infoBox(f"Set target: {fuzzer.getRequester().getUrl()}")
    oh.infoBox(f"Set request method: {method}")
    oh.infoBox(f"Set request data: {str(requestData)}")
    cliParser.checkCookie(fuzzer.getRequester())
    cliParser.checkProxy(fuzzer.getRequester())
    cliParser.checkProxies(fuzzer.getRequester())
    cliParser.checkDelay(fuzzer)
    cliParser.checkVerboseMode(fuzzer)
    cliParser.checkNumThreads(fuzzer)
    ApplicationManager(fuzzer).prepare()

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        oh.showIntro()
        oh.errorBox("Invalid format! Use -h on 2nd parameter to show the help menu.")
    if (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
        oh.showHelpMenu()
    if (sys.argv[1] == '-v' or sys.argv[1] == '--version'):
        exit("FuzzingTool v3.4.0")
    main(sys.argv)