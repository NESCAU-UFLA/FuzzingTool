import sys
from RequestHandler import RequestHandler
from OutputHandler import *
import settings

def helpMenu():
    """Creates the Help Menu"""
    print("\nParameters:")
    print(' '*3+"{:<23}".format("-h")+" Displays the help menu and exit")
    print("\n"+' '*3+"Core:")
    print(' '*5+"{:<21}".format("-u URL")+" Define the target URL")
    print(' '*5+"{:<21}".format("-f fileName")+" Define the entry file")
    print("\n"+' '*3+"Request options:")
    print(' '*5+"{:<21}".format("--data DATA")+" Define the POST data")
    print(' '*5+"{:<21}".format("--proxy IP:PORT")+" Define the proxy")
    print(' '*5+"{:<21}".format("--proxies fileName")+" Define the proxies file")
    print(' '*5+"{:<21}".format("--cookie COOKIE")+" Define the HTTP Cookie header value")
    print(' '*5+"{:<21}".format("--delay DELAY")+" Define the delay between each request (in seconds)")
    exit("")

def getUrl(argv):
    """Get the target URL

    @type argv: list
    @param argv: The arguments given in the execution
    @rtype: str
    @returns url: The target URL
    """
    try:
        return argv[argv.index('-u')+1]
    except ValueError as e:
        oh.errorBox("An URL is needed to make the fuzzying.")

def getMethodAndArgs(argv, url):
    """Get the param method to use ('?' in URL if GET, or --data) and the request param string

    @type argv: list
    @param argv: The arguments given in the execution
    @type url: str
    @param url: The target URL
    @rtype: tuple
    @returns (url, method, param): The tuple with the request method and params
        @rtype: str
        @returns url: The new target URL
        @rtype: str
        @returns method: The request method
        @rtype: str
        @returns param: The string parameter of the request
    """
    if ('?' in url):
        url, param = url.split('?')
        method = 'GET'
    else:
        method = 'POST'
        try:
            index = argv.index('--data')+1
            param = argv[index]
        except ValueError as e:
            oh.errorBox("You must set at least GET or POST parameters for the Fuzzying test.")
    return (url, method, param)

def getRequestParams(argv, param):
    """Split all the request parameters into a list of arguments used in the request
       also set the default parameters value if is given

    @type argv: list
    @param argv: The arguments given in the execution
    @type param: str
    @param param: The parameter string of the request
    @rtype: tuple
    @returns (entries, defaultEntries): The tuple with the request arguments
        @rtype: list
        @returns entries: The variable list of the request arguments
        @rtype: list
        @returns defaultEntries: The default parameters (variables and values) used in the first request
    """
    entries = []
    defaultEntries = {}
    if ('&' in param):
        param = param.split('&', param.count('&'))
        for arg in param:
            if ('=' in arg):
                arg, value = arg.split('=')
                entries.append(arg)
                if (value != ''):
                    defaultEntries[arg] = value
    else:
        if ('=' in param):
            arg, value = param.split('=')
            entries.append(arg)
            if (value != ''):
                defaultEntries[arg] = value
    return (entries, defaultEntries)

def getWordlistFile(argv):
    """Get the fuzzying wordlist filename from -f argument, and returns the file object
       if the argument -f doesn't exists, or the file couldn't be open, an error is thrown and the application exits

    @type argv: list
    @param argv: The arguments given in the execution
    """
    try:
        index = argv.index('-f')+1
        fileName = argv[index]
        try:
            settings.wordlistFile = open('../input/'+fileName, 'r')
        except FileNotFoundError as e:
            oh.errorBox("File '"+fileName+"' not found.")
    except ValueError as e:
        oh.errorBox("An file is needed to make the fuzzying")

def checkCookie(argv, requestHandler):
    """Check if the --cookie argument is present, and set the value into the requestHandler

    @type argv: list
    @param argv: The arguments given in the execution
    @type requestHandler: RequestHandler
    @param requestHandler: The object responsible to handle the requests
    """
    if ('--cookie' in argv):
        cookie = argv[argv.index('--cookie')+1]
        cookieSplited = cookie.split('=')
        requestHandler.setCookie({cookieSplited[0]: cookieSplited[1]})
        oh.infoBox("Set cookie: "+cookie)

def checkProxy(argv, requestHandler):
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

def checkProxies(argv):
    """Check if the --proxies argument is present, and open a file

    @type argv: list
    @param argv: The arguments given in the execution
    """
    if ('--proxies' in argv):
        index = argv.index('--proxies')+1
        proxiesFileName = argv[index]
        try:
            settings.proxiesFile = open('../input/'+proxiesFileName, 'r')
        except FileNotFoundError as e:
            oh.errorBox("File '"+fileName+"' not found.")

def checkDelay(argv, requestHandler):
    """Check if the --delay argument is present, and set the value into the requestHandler

    @type argv: list
    @param argv: The arguments given in the execution
    @type requestHandler: RequestHandler
    @param requestHandler: The object responsible to handle the requests
    """
    if ('--delay' in argv):
        delay = argv[argv.index('--delay')+1]
        requestHandler.setDelay(float(delay))
        oh.infoBox("Set delay: "+delay+" second(s)")

def checkVerboseMode(argv):
    """Check if the -V or --verbose argument is present, and set the verbose mode

    @type argv: str
    @param argv: The arguments given in the execution
    """
    if ('-V' in argv or '--verbose' in argv):
        settings.verboseMode = True

def main(argv):
    """The main function

    @type argv: list
    @param argv: The arguments given in the execution
    """
    if (len(argv) < 2):
        oh.errorBox("Invalid format! Use -h parameter to show the help menu.")
    if (argv[1] == '-h'):
        helpMenu()
    url = getUrl(argv)
    url, method, param = getMethodAndArgs(argv, url)
    entries, defaultEntries = getRequestParams(argv, param)
    getWordlistFile(argv)
    requestHandler = RequestHandler(url, method, entries, defaultEntries)
    oh.infoBox("Set target: "+url)
    oh.infoBox("Set param method: "+method)
    oh.infoBox("Set param variables: "+str(entries))
    oh.infoBox("Set default entries: "+str(defaultEntries))
    checkCookie(argv, requestHandler)
    checkProxy(argv, requestHandler)
    checkProxies(argv)
    checkDelay(argv, requestHandler)
    checkVerboseMode(argv)
    requestHandler.start()

if __name__ == "__main__":
   main(sys.argv)