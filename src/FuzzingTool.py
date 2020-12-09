#!/usr/bin/python3

## FuzzingTool
# 
# Version: 2.1.0
# Authors:
#    Vitor Oriel Borges <https://github.com/VitorOriel>
#
## https://github.com/NESCAU-UFLA/FuzzingTool

import sys
from Fuzzer import Fuzzer
from RequestHandler import RequestHandler
from OutputHandler import *
from FileHandler import *

def showHelpMenu():
    """Creates the Help Menu"""
    oh.helpTitle(0, "Parameters:")
    oh.helpContent(3, "-h, --help", "Display the help menu and exit")
    oh.helpContent(3, "-V, --verbose", "Enable the verbose mode")
    oh.helpContent(3, "-v, --version", "Show the current version")
    oh.helpTitle(3, "Core:")
    oh.helpContent(5, "-u URL", "Define the target URL")
    oh.helpContent(5, "-f FILENAME", "Define the payload file")
    oh.helpTitle(3, "Request options:")
    oh.helpContent(5, "--data DATA", "Define the POST data")
    oh.helpContent(5, "--proxy IP:PORT", "Define the proxy")
    oh.helpContent(5, "--proxies FILENAME", "Define the proxies file")
    oh.helpContent(5, "--cookie COOKIE", "Define the HTTP Cookie header value")
    oh.helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
    oh.helpTitle(0, "Examples:")
    oh.helpContent(3, "./FuzzingTool.py -u http://127.0.0.1/post.php?id= -f sqli.txt", '')
    oh.helpContent(3, "./FuzzingTool.py -f sqli.txt -u http://127.0.0.1/controller/user.php --data 'login&passw&user=login'", '')
    oh.helpContent(3, "./FuzzingTool.py -f paths.txt -u http://127.0.0.1/$", '')
    exit("")

def getUrl(argv: list):
    """Get the target URL

    @type argv: list
    @param argv: The arguments given in the execution
    @returns str: The target URL
    """
    try:
        return argv[argv.index('-u')+1]
    except ValueError:
        oh.errorBox("An URL is needed to make the fuzzing.")

def getMethodAndArgs(argv: list, url: str):
    """Get the param method to use ('?' or '$' in URL if GET, or --data) and the request param string

    @type argv: list
    @param argv: The arguments given in the execution
    @type url: str
    @param url: The target URL
    @returns tuple(str, str, str): The tuple with the new target URL, the request method and params
    """
    param = ''
    if '?' in url or '$' in url:
        if '?' in url:
            url, param = url.split('?', 1)
        method = 'GET'
    else:
        method = 'POST'
        try:
            index = argv.index('--data')+1
            param = argv[index]
        except ValueError:
            oh.errorBox("You must set at least GET or POST parameters for the fuzzing test.")
    return (url, method, param)

def getRequestParams(argv: list, param: str):
    """Split all the request parameters into a list of arguments used in the request

    @type argv: list
    @param argv: The arguments given in the execution
    @type param: str
    @param param: The parameter string of the request
    @returns dict: The entries data of the request
    """
    defaultParam = {}
    if ('&' in param):
        param = param.split('&', param.count('&'))
        for arg in param:
            makeDefaultParam(defaultParam, arg)
    else:
        makeDefaultParam(defaultParam, param)
    return defaultParam

def makeDefaultParam(defaultParam: dict, param: str):
    """Set the default parameter values if are given

    @type defaultParam: dict
    @param defaultParam: The entries data of the request
    @type param: str
    @param param: The parameter string of the request
    """
    if '=' in param and not '=$' in param:
        param, value = param.split('=')
        defaultParam[param] = value
    else:
        defaultParam[param] = ''

def getWordlistFile(argv: list):
    """Get the fuzzing wordlist filename from -f argument, and returns the file object
       if the argument -f doesn't exists, or the file couldn't be open, an error is thrown and the application exits

    @type argv: list
    @param argv: The arguments given in the execution
    """
    try:
        index = argv.index('-f')+1
        wordlistFileName = argv[index]
        fh.openWordlist(wordlistFileName)
    except ValueError:
        oh.errorBox("An file is needed to make the fuzzing")

def checkCookie(argv: list, requestHandler: RequestHandler):
    """Check if the --cookie argument is present, and set the value into the requestHandler

    @type argv: list
    @param argv: The arguments given in the execution
    @type requestHandler: RequestHandler
    @param requestHandler: The object responsible to handle the requests
    """
    if ('--cookie' in argv):
        cookie = argv[argv.index('--cookie')+1]
        requestHandler.setCookie(cookie)
        oh.infoBox("Set cookie: "+cookie)

def checkProxy(argv: list, requestHandler: RequestHandler):
    """Check if the --proxy argument is present, and set the value into the requestHandler

    @type argv: list
    @param argv: The arguments given in the execution
    @type requestHandler: RequestHandler
    @param requestHandler: The object responsible to handle the requests
    """
    if ('--proxy' in argv):
        index = argv.index('--proxy')+1
        proxy = argv[index]
        requestHandler.setProxy({
            'http://': 'http://'+proxy,
            'https://': 'http://'+proxy
        })
        oh.infoBox("Set proxy: "+proxy)

def checkProxies(argv: list):
    """Check if the --proxies argument is present, and open a file

    @type argv: list
    @param argv: The arguments given in the execution
    """
    if ('--proxies' in argv):
        index = argv.index('--proxies')+1
        proxiesFileName = argv[index]
        fh.openProxies(proxiesFileName)
        oh.infoBox("Set proxy: Load proxies from file.")

def checkDelay(argv: list, fuzzer: Fuzzer):
    """Check if the --delay argument is present, and set the value into the fuzzer

    @type argv: list
    @param argv: The arguments given in the execution
    @type fuzzer: Fuzzer
    @param fuzzer: The Fuzzer object
    """
    if ('--delay' in argv):
        delay = argv[argv.index('--delay')+1]
        fuzzer.setDelay(float(delay))
        oh.infoBox("Set delay: "+delay+" second(s)")

def checkVerboseMode(argv: list, fuzzer: Fuzzer):
    """Check if the -V or --verbose argument is present, and set the verbose mode

    @type argv: str
    @param argv: The arguments given in the execution
    @type fuzzer: Fuzzer
    @param fuzzer: The Fuzzer object
    """
    if ('-V' in argv or '--verbose' in argv):
        fuzzer.setVerboseMode(True)

def main(argv: list):
    """The main function

    @type argv: list
    @param argv: The arguments given in the execution
    """
    if (len(argv) < 2):
        oh.errorBox("Invalid format! Use -h on 2nd parameter to show the help menu.")
    if (argv[1] == '-h' or argv[1] == '--help'):
        showHelpMenu()
    if (argv[1] == '-v' or argv[1] == '--version'):
        exit("FuzzingTool v2.1.0")
    url = getUrl(argv)
    url, method, param = getMethodAndArgs(argv, url)
    defaultParam = getRequestParams(argv, param) if param != '' else {}
    getWordlistFile(argv)
    fuzzer = Fuzzer(RequestHandler(url, method, defaultParam))
    oh.infoBox("Set target: "+url)
    oh.infoBox("Set request method: "+method)
    oh.infoBox("Set request data: "+str(defaultParam))
    checkCookie(argv, fuzzer.getRequestHandler())
    checkProxy(argv, fuzzer.getRequestHandler())
    checkProxies(argv)
    checkDelay(argv, fuzzer)
    checkVerboseMode(argv, fuzzer)
    fuzzer.prepareApplication()

if __name__ == "__main__":
   main(sys.argv)