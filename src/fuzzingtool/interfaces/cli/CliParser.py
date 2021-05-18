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

from .CliOutput import cliOutput as co
from ..ArgumentBuilder import ArgumentBuilder as AB
from ...utils.utils import getIndexesToParse, getPluginNamesFromCategory
from ...utils.FileHandler import fileHandler as fh
from ...factories.PluginFactory import PluginFactory
from ...core.scanners.Matcher import Matcher
from ...exceptions.MainExceptions import InvalidPluginName

def parsePlugin(plugin: str):
    """Parse the plugin name into name and parameter

    @type plugin: str
    @param plugin: The plugin argument
    @returns tuple(str, str): The plugin name and parameter
    """
    if '=' in plugin:
        plugin, param = plugin.split('=')
    else:
        plugin = plugin
        param = ''
    return (plugin, param)

def showHelpMenu():
    co.helpTitle(0, "Parameters:")
    co.helpTitle(3, "Misc:")
    co.helpContent(5, "-h, --help", "Show the help menu and exit")
    co.helpContent(5, "-v, --version", "Show the current version and exit")
    co.helpTitle(3, "Request options:")
    co.helpContent(5, "-r FILE", "Define the file with the raw HTTP request (scheme not specified)")
    co.helpContent(5, "--scheme SCHEME", "Define the scheme used in the URL (default http)")
    co.helpContent(5, "-u URL", "Define the target URL")
    co.helpContent(5, "-X METHOD", "Define the request http verbs (method)")
    co.helpContent(5, "-d DATA", "Define the request body data")
    co.helpContent(5, "--proxy IP:PORT", "Define the proxy")
    co.helpContent(5, "--proxies FILE", "Define the file with a list of proxies")
    co.helpContent(5, "--cookie COOKIE", "Define the HTTP Cookie header value")
    co.helpContent(5, "--timeout TIMEOUT", "Define the request timeout (in seconds)")
    co.helpContent(5, "--unfollow-redirects", "Stop to follow redirects")
    co.helpTitle(3, "Payload options:")
    co.helpContent(5, "-w WORDLIST", "Define the wordlist dictionary (--help=dictionaries for more info)")
    co.helpContent(5, "-e ENCODER", "Define the encoder used on payloads (--help=encoders for more info)")
    co.helpContent(5, "--prefix PREFIX", "Define the prefix(es) used with the payload")
    co.helpContent(5, "--suffix SUFFIX", "Define the suffix(es) used with the payload")
    co.helpContent(5, "--upper", "Set the uppercase case for the payloads")
    co.helpContent(5, "--lower", "Set the lowercase case for the payloads")
    co.helpContent(5, "--capitalize", "Set the capitalize case for the payloads")
    co.helpTitle(3, "Match options:")
    co.helpContent(5, "-Mc STATUS", "Match responses based on their status codes")
    co.helpContent(5, "-Ms SIZE", "Match responses based on their length (in bytes)")
    co.helpContent(5, "-Mt TIME", "Match responses based on their elapsed time (in seconds)")
    co.helpContent(5, "--scanner SCANNER", "Define the custom scanner (--help=scanners for more info)")
    co.helpTitle(3, "More options:")
    co.helpContent(5, "(-V, -V1) | -V2", "Enable the verbose mode (common or full verbose)")
    co.helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
    co.helpContent(5, "-t NUMBEROFTHREADS", "Define the number of threads used in the tests")
    co.helpContent(5, "-o REPORT", "Define the report format (accept txt, csv and json)")
    co.helpContent(5, "--blacklist-status STATUS:ACTION", "Blacklist status codes from response, and take an action when one is detected. Available actions: skip (to skip the current target), wait=SECONDS (to pause the app for some seconds)")
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u http://127.0.0.1/post.php?id= -w /path/to/wordlist/sqli.txt -Mt 20 -Mc 500-600 -t 30 -o fuzzingGet.csv\n")
    co.print("FuzzingTool -w /path/to/wordlist/sqli.txt -u http://127.0.0.1/controller/user.php -d 'login&passw&user=login' -Ms 1200\n")
    co.print("FuzzingTool -w /path/to/wordlist/paths.txt -u http://127.0.0.1/$ -u http://192.168.0.133/$ --suffix .php,.html --unfollow-redirects -Mc 200,302,303\n")
    co.print("FuzzingTool -w /path/to/wordlist/subdomains.txt -u https://$.domainexample.com/ -t 100 -Ms 1500 --timeout 5\n")
    co.print("FuzzingTool -r /path/to/raw-http1.txt -r /path/to/raw-http2.txt --scheme https -w /path/to/wordlist/sqli.txt -V -o json\n")

def showCustomPackageHelp(category: str):
    """Show the custom package help

    @type category: str
    @param category: The package category to search for his plugins
    """
    for pluginName in getPluginNamesFromCategory(category):
        Plugin = PluginFactory.classCreator(pluginName, category)
        if not Plugin.__type__:
            typeFuzzing = ''
        else:
            typeFuzzing = f" (Used for {Plugin.__type__})"
        if not Plugin.__params__:
            params = ''
        else:
            params = f"={Plugin.__params__}"
        co.helpContent(5, f"{Plugin.__name__}{params}", f"{Plugin.__desc__}{typeFuzzing}\n")

def showDictionariesHelp():
    co.helpTitle(0, "Dictionary options: (-w)")
    co.helpTitle(2, "Default: The default dictionaries are selected by default when no custom are choiced\n")
    co.helpContent(5, "FILEPATH", "Set the path of the wordlist file")
    co.helpContent(5, "[PAYLOAD1,PAYLOAD2,]", "Set the payloads list to be used as wordlist")
    co.helpTitle(2, "Custom (Dictionary=PARAM): Set the custom dictionary and his parameter\n")
    showCustomPackageHelp('dictionaries')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w /path/to/wordlist/subdomains.txt -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w [wp-admin,admin,webmail,www,cpanel] -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://$.domainexample.com/ -w CrtSh=domainexample.com -t 30 --timeout 5 -V2\n")
    co.print("FuzzingTool -u https://domainexample.com/$ -w Overflow=5000,:../:etc/passwd -t 30 --timeout 5 -V2\n")

def showEncodersHelp():
    co.helpTitle(0, "Encoder options: (-e)")
    co.helpTitle(2, "Set the encoder used on the payloads\n")
    showCustomPackageHelp('encoders')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://domainexample.com/page.php?id= -w /path/to/wordlist/sqli.txt -e Url=2 -t 30 --scanner Find=SQL\n")

def showScannersHelp():
    co.helpTitle(0, "Scanner options:")
    co.helpTitle(2, "Default: The default scanners are selected automatically during the tests, if a custom scanner wasn't gived\n")
    co.helpContent(5, "DataScanner", "Scanner for the data fuzzing")
    co.helpContent(5, "PathScanner", "Scanner for the path URL fuzzing")
    co.helpContent(5, "SubdomainScanner", "Scanner for the subdomain URL fuzzing")
    co.helpTitle(2, "Custom (--scaner SCANNER): Set the custom scanner\n")
    showCustomPackageHelp('scanners')
    co.helpTitle(0, "Examples:\n")
    co.print("FuzzingTool -u https://domainexample.com/search.php?query= -w /path/to/wordlist/xss.txt --scanner Reflected -t 30 -o csv\n")

class CliParser:
    """Class that handle with the sys argument parsing"""
    def __init__(self, argv: list):
        """Class constructor

        @type argv: list
        @param argv: The system arguments list
        """
        self.__argv = argv
        self.setArguments()
    
    def setArguments(self):
        """Set all the app arguments"""
        self.setRequestArguments()
        self.setDictionaryArguments()
        self.setMatchArguments()
        self.setGeneralArguments()

    def setRequestArguments(self):
        """Set the request arguments"""
        self.targets = []
        self.extendTargetsFromRawHttp()
        self.extendTargetsFromArgs()
        if not self.targets:
            raise Exception("A target is needed to make the fuzzing")
        self.setCookie()
        self.setProxy()
        self.setProxies()
        self.setTimeout()
        self.setFollowRedirects()

    def extendTargetsFromRawHttp(self):
        """Updated the targets list based on raw https"""
        headerFilenames = []
        for i in getIndexesToParse(self.__argv, '-r'):
            headerFilenames.append(self.__argv[i+1])
        if headerFilenames:
            # Check if a scheme is specified, otherwise set http as default
            if '--scheme' in self.__argv:
                scheme = self.__argv[self.__argv.index('--scheme')+1]
            else:
                scheme = 'http'
            self.targets.extend(AB.buildTargetsFromRawHttp(headerFilenames, scheme))
    
    def extendTargetsFromArgs(self):
        """Updated the targets list based on the urls"""
        urls = []
        for i in getIndexesToParse(self.__argv, '-u'):
            urls.append(self.__argv[i+1])
        if urls:
            if '-X' in self.__argv:
                method = self.__argv[self.__argv.index('-X')+1]
            else:
                method = ''
            if '-d' in self.__argv:
                data = self.__argv[self.__argv.index('-d')+1]
            else:
                data = ''
            self.targets.extend(AB.buildTargetsFromArgs(urls, method, data))

    def setCookie(self):
        """Check if the --cookie argument is present, and set it"""
        self.cookie = ''
        if '--cookie' in self.__argv:
            self.cookie = self.__argv[self.__argv.index('--cookie')+1]
            co.infoBox(f"Set cookie: {self.cookie}")

    def setProxy(self):
        """Check if the --proxy argument is present, and set it"""
        self.proxy = ''
        if '--proxy' in self.__argv:
            self.proxy = self.__argv[self.__argv.index('--proxy')+1]
            co.infoBox(f"Set proxy: {self.proxy}")

    def setProxies(self):
        """Check if the --proxies argument is present, and read the proxies from a file"""
        self.proxies = []
        if '--proxies' in self.__argv:
            proxiesFilename = self.__argv[self.__argv.index('--proxies')+1]
            try:
                self.proxies = fh.read(proxiesFilename)
            except Exception as e:
                raise Exception(str(e))
            co.infoBox(f"Proxies loaded from file '{proxiesFilename}'")

    def setTimeout(self):
        """Check if the --timeout argument is present, and set the request timeout"""
        self.timeout = 0
        if '--timeout' in self.__argv:
            timeout = self.__argv[self.__argv.index('--timeout')+1]
            try:
                self.timeout = int(timeout)
            except:
                raise Exception(f"The request timeout ({timeout}) must be an integer")
            co.infoBox(f"Set request timeout: {timeout} seconds")

    def setFollowRedirects(self):
        """Check if the --unfollow-redirects argument is present, and set the follow redirects flag"""
        self.unfollowRedirects = True
        if '--unfollow-redirects' in self.__argv:
            self.unfollowRedirects = False
            co.infoBox(f"Stop to following redirects")

    def setDictionaryArguments(self):
        """Set the dictionary arguments"""
        self.setDictionary()
        self.setPrefixAndSuffix()
        self.setCase()
        self.setEncoder()

    def setDictionary(self):
        """Set the fuzzing dictionary"""
        try:
            dictionary = self.__argv[self.__argv.index('-w')+1]
        except ValueError:
            raise Exception("An wordlist is needed to make the fuzzing")
        dictionary, param = parsePlugin(dictionary)
        try:
            self.dictionary = PluginFactory.objectCreator(dictionary, 'dictionaries', param)
        except InvalidPluginName:
            try:
                if dictionary.startswith('[') and dictionary.endswith(']'):
                    from ...core.dictionaries.default.ListDictionary import ListDictionary
                    self.dictionary = ListDictionary(dictionary)
                else:
                    # For default, read the wordlist from a file
                    from ...core.dictionaries.default.FileDictionary import FileDictionary
                    self.dictionary = FileDictionary(dictionary)
            except Exception as e:
                raise Exception(str(e))
        except Exception as e:
            raise Exception(str(e))
        co.infoBox("Building dictionary ...")
        try:
            self.dictionary.setWordlist()
        except Exception as e:
            raise Exception(str(e))
        co.infoBox(f"Dictionary is done, loaded {len(self.dictionary)} payloads")

    def setPrefixAndSuffix(self):
        """Check if the --prefix argument is present, and set the prefix
           Check if the --suffix argument is present, and set the suffix
        """
        prefix = ''
        suffix = ''
        if '--prefix' in self.__argv:
            prefix = self.__argv[self.__argv.index('--prefix')+1]
            co.infoBox(f"Set prefix: {prefix}")
        if '--suffix' in self.__argv:
            suffix = self.__argv[self.__argv.index('--suffix')+1]
            co.infoBox(f"Set suffix: {suffix}")
        self.prefix = AB.buildPrefixSuffix(prefix)
        self.suffix = AB.buildPrefixSuffix(suffix)

    def setCase(self):
        """Check if the --upper argument is present, and set the uppercase case mode
           Check if the --lower argument is present, and set the lowercase case mode
           Check if the --capitalize argument is present, and set the capitalize case mode
        """
        self.lowercase = False
        self.uppercase = False
        self.capitalize = False
        if '--lower' in self.__argv:
            self.lowercase = True
            co.infoBox("Set payload case: lowercase")
        elif '--upper' in self.__argv:
            self.uppercase = True
            co.infoBox("Set payload case: uppercase")
        elif '--capitalize' in self.__argv:
            self.capitalize = True
            co.infoBox("Set payload case: capitalize")

    def setEncoder(self):
        """Check if the -e argument is present, and set the encoder"""
        self.encoder = None
        if '-e' in self.__argv:
            encoder = self.__argv[self.__argv.index('-e')+1]
            encoder, param = parsePlugin(encoder)
            try:
                self.encoder = PluginFactory.objectCreator(
                    encoder, 'encoders', param
                )
            except Exception as e:
                raise Exception(str(e))
            co.infoBox(f"Set encoder: {encoder}")

    def setMatchArguments(self):
        """Set the match arguments"""
        self.setMatcher()
        self.setScanner()

    def setMatcher(self):
        """Set the matcher object"""
        self.matcher = Matcher()
        if '-Mc' in self.__argv:
            status = self.__argv[self.__argv.index('-Mc')+1]
            if '200' not in status:
                if co.askYesNo('warning', "Status code 200 (OK) wasn't included. Do you want to include it to the allowed status codes?"):
                    status += ",200"
            self.matcher.setAllowedStatus(AB.buildMatcherAllowedStatus(status))
            co.infoBox(f"Set the allowed status codes: {status}")
        length = None
        time = None
        if '-Ms' in self.__argv:
            length = self.__argv[self.__argv.index('-Ms')+1]
            try:
                length = int(length)
            except:
                raise Exception(f"The match length argument ({length}) must be an integer")
            co.infoBox(f"Exclude by length: {str(length)} bytes")
        if '-Mt' in self.__argv:
            time = self.__argv[self.__argv.index('-Mt')+1]
            try:
                time = float(time)
            except:
                raise Exception(f"The match time argument ({time}) must be a number")
            co.infoBox(f"Exclude by time: {str(time)} seconds")
        self.matcher.setComparator(AB.buildMatcherComparator(length, time))

    def setScanner(self):
        """Check if the --scanner argument is present, and set it"""
        self.scanner = None
        if '--scanner' in self.__argv:
            scanner = self.__argv[self.__argv.index('--scanner')+1]
            scanner, param = parsePlugin(scanner)
            try:
                self.scanner = PluginFactory.objectCreator(
                    scanner, 'scanners', param
                )
            except Exception as e:
                co.errorBox(str(e))
            co.infoBox(f"Set scanner: {scanner}")

    def setGeneralArguments(self):
        """Set the general arguments"""
        self.setVerboseMode()
        self.setDelay()
        self.setNumThreads()
        self.setBlacklistedStatus()
        self.setReporter()

    def setVerboseMode(self):
        """Check if the -V or --verbose argument is present, and set the verbose mode"""
        if '-V' in self.__argv or '-V1' in self.__argv:
            self.verbose = [True, False]
        elif '-V2' in self.__argv:
            self.verbose = [True, True]
        else:
            self.verbose = [False, False]

    def setDelay(self):
        """Check if the --delay argument is present, and set it"""
        self.delay = 0
        if '--delay' in self.__argv:
            delay = self.__argv[self.__argv.index('--delay')+1]
            try:
                self.delay = float(delay)
            except:
                raise Exception(f"The delay ({delay}) must be a number")
            co.infoBox(f"Set delay: {str(delay)} second(s)")

    def setNumThreads(self):
        """Check if the -t argument is present, and set it"""
        self.numberOfThreads = 1
        if '-t' in self.__argv:
            numberOfThreads = self.__argv[self.__argv.index('-t')+1]
            try:
                self.numberOfThreads = int(numberOfThreads)
            except:
                raise Exception(f"The number of threads ({numberOfThreads}) must be an integer")
        co.infoBox(f"Set number of threads: {str(self.numberOfThreads)} thread(s)")

    def setBlacklistedStatus(self):
        """Check if the --blacklist-status argument is present, and set the blacklisted status and action"""
        self.blacklistedStatus = ''
        if '--blacklist-status' in self.__argv:
            status = self.__argv[self.__argv.index('--blacklist-status')+1]
            if ':' in status:
                status, self.blacklistAction = status.split(':', 1)
                self.blacklistAction = self.blacklistAction.lower()
            else:
                self.blacklistAction = 'skip'
            self.blacklistedStatus = AB.buildBlacklistStatus(status)

    def setReporter(self):
        """Check if the -o argument is present, and set the report metadata (name and type)"""
        if '-o' in self.__argv:
            report = self.__argv[self.__argv.index('-o')+1]
            fh.reporter.setMetadata(report)
            co.infoBox(f"Set report: {report}")