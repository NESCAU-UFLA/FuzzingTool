import sys
from RequestHandler import RequestHandler
from OutputHandler import *

def helpMenu():
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
    try:
        index = argv.index('-u')+1
        return argv[index]
    except ValueError as e:
        oh.errorBox("An URL is needed to make the fuzzying.")

def getMethodAndArgs(argv, url):
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
    entries = []
    defaultEntries = {}
    if ('&' in param):
        param = param.split('&', param.count('&'))
        for arg in param:
            if ('=' in arg):
                arg, value = arg.split('=')
                entries.append(arg)
            else:
                value = ''
            defaultEntries[arg] = value
    else:
        if ('=' in param):
            arg, value = param.split('=')
            entries.append(arg)
        else:
            value = ''
        defaultEntries[arg] = value
    return (entries, defaultEntries)

def getFile(argv):
    try:
        index = argv.index('-f')+1
        fileName = argv[index]
        try:
            file = open(fileName, 'r')
        except FileNotFoundError as e:
            oh.errorBox("File '"+fileName+"' not found.")
    except ValueError as e:
        oh.errorBox("An file is needed to make the fuzzying")
    return file

def checkCookie(argv, requestHandler):
    if ('--cookie' in argv):
        index = argv.index('--cookie')+1
        cookie = argv[index].split('=')
        requestHandler.setCookie({cookie[0]: cookie[1]})

def checkProxy(argv, requestHandler):
    if ('--proxy' in argv):
        index = argv.index('--proxy')+1
        proxy = argv[index]
        requestHandler.setProxy({
            'http://': 'http://'+proxy,
            'https://': 'http://'+proxy
        })

def checkProxies(argv):
    if ('--proxies' in argv):
        index = argv.index('--proxies')+1
        proxiesFileName = argv[index]
        try:
            proxiesFile = open(proxiesFileName, 'r')
        except FileNotFoundError as e:
            oh.errorBox("File '"+fileName+"' not found.")
    else:
        proxiesFile = None
    return proxiesFile

def checkDelay(argv, requestHandler):
    if ('--delay' in argv):
        index = argv.index('--delay')+1
        requestHandler.setDelay(float(argv[index]))

def main(argv):
    if (len(argv) < 2):
        oh.errorBox("Invalid format! Use -h parameter to show the help menu.")
    if (argv[1] == '-h'):
        helpMenu()
    url = getUrl(argv)
    url, method, param = getMethodAndArgs(argv, url)
    entries, defaultEntries = getRequestParams(argv, param)
    file = getFile(argv)
    requestHandler = RequestHandler(url, method, entries, defaultEntries)
    checkCookie(argv, requestHandler)
    checkProxy(argv, requestHandler)
    proxiesFile = checkProxies(argv)
    checkDelay(argv, requestHandler)
    requestHandler.start(file, proxiesFile)

if __name__ == "__main__":
   main(sys.argv)