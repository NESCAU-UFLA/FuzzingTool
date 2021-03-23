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

from datetime import datetime
import platform
import threading
import sys

if platform.system() == 'Windows':
    try:
        from colorama import init
    except:
        exit("Colorama package not installed. Install all dependencies first.")
    init()

def fixPayloadToOutput(payload: str):
    """Fix the payload's size

    @type payload: str
    @param payload: The payload used in the request
    @returns str: The fixed payload to output
    """
    if '	' in payload:
        payload = payload.replace('	', ' ')
    if len(payload) > 30:
        output = ""
        for i in range(27):
            output += payload[i]
        output += '...'
        return output
    else:
        return payload

def getFormatedResult(result: dict):
    """Format the result into a dict of strings

    @type result: dict
    @param result: The result dict
    @returns dict: The result formated with strings
    """
    return {
        'Request': '{:<7}'.format(result['Request']),
        'Payload': '{:<30}'.format(fixPayloadToOutput(result['Payload'])),
        'Time Taken': '{:>10}'.format(result['Time Taken']),
        'Status': result['Status'],
        'Length': '{:>8}'.format(result['Length']),
        'Words': '{:>6}'.format(result['Words']),
        'Lines': '{:>5}'.format(result['Lines'])
    }

class Colors:
    """Class that handle with the colors"""
    RESET = '\033[0m'
    GRAY = '\033[90m'
    YELLOW = '\033[33m'
    RED = '\u001b[31;1m'
    GREEN = '\u001b[32;1m'
    BLUE_GRAY = '\033[36m'
    LIGHT_GRAY = '\u001b[38;5;250m'
    LIGHT_YELLOW = '\u001b[33;1m'
    LIGHT_GREEN = '\u001b[38;5;48m'
    BOLD = '\033[1m'

class OutputHandler:
    """Class that handle with the outputs
       Singleton Class
    """
    __instance = None

    @staticmethod
    def getInstance():
        if OutputHandler.__instance == None:
            OutputHandler()
        return OutputHandler.__instance

    """
    Attributes:
        lastInline: A flag to say if the last output was inline or not
        lock: The threads locker
        info: The info label
        warning: The warning label
        error: The error label
        abort: The abort label
        worked: The worked label
        notWorked: The not worked label
    """
    def __init__(self):
        """Class constructor"""
        if OutputHandler.__instance != None:
            raise Exception("This class is a singleton!")
        else:
            OutputHandler.__instance = self
        self.__lastInline = False
        self.__lock = threading.Lock()
        self.__info = f'{Colors.GRAY}[{Colors.BLUE_GRAY}INFO{Colors.GRAY}]{Colors.RESET} '
        self.__warning = f'{Colors.GRAY}[{Colors.YELLOW}WARNING{Colors.GRAY}]{Colors.RESET} '
        self.__error = f'{Colors.GRAY}[{Colors.RED}ERROR{Colors.GRAY}]{Colors.RESET} '
        self.__abord = f'{Colors.GRAY}[{Colors.RED}ABORT{Colors.GRAY}]{Colors.RESET} '
        self.__worked = f'{Colors.GRAY}[{Colors.GREEN}+{Colors.GRAY}]{Colors.RESET} '
        self.__notWorked = f'{Colors.GRAY}[{Colors.RED}-{Colors.GRAY}]{Colors.RESET} '

    def setPrintContentMode(self, scanner: object, verboseMode: bool):
        """Set the print content mode by the Fuzzer responses

        @type scanner: object
        @param scanner: The subdomain fuzzing flag
        @type verboseMode: bool
        @param verboseMode: The verbose mode flag
        """
        if verboseMode:
            self.__lock = None
        self.printContent = self.printForBoxMode
        try:
            self.__getMessage = scanner.getMessage
        except Exception as e:
            exit(str(e))

    def infoBox(self, msg: str):
        """Print the message with a info label

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getInfo(msg)}')

    def errorBox(self, msg: str):
        """End the application with error label and a message

        @type msg: str
        @param msg: The message
        """
        exit(f'{self.__getTime()}{self.__getError(msg)}')
 
    def warningBox(self, msg: str):
        """Print the message with a warning label

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getWarning(msg)}')

    def abortBox(self, msg: str):
        """Print the message with abort label and a message

        @type msg: str
        @param msg: The message
        """
        if self.__lock:
            with self.__lock:
                sys.stdout.flush()
        print(f'\n{self.__getTime()}{self.__getAbort(msg)}')

    def workedBox(self, msg: str):
        """Print the message with worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(f'{self.__getTime()}{self.__getWorked(msg)}')

    def notWorkedBox(self, msg: str):
        """Print the message with not worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(f"{self.__getTime()}{self.__getNotWorked(msg)}")

    def askYesNo(self, askType: str, msg: str):
        """Ask a question for the user

        @type askType: str
        @param askType: The type of the asker
        @type msg: str
        @param msg: The message
        @returns bool: The answer based on the user's input
        """
        if askType == 'warning':
            getType = self.__getWarning
        else:
            getType = self.__getInfo
        print(f"{self.__getTime()}{getType(msg)} (y/N) ", end='')
        action = input()
        if action == 'y' or action == 'Y':
            return True
        else:
            return False

    def askData(self, msg: str):
        """Ask data for the user

        @type msg: str
        @param msg: The message
        @returns int|float: The data asked
        """
        print(self.__getTime()+self.__getInfo(msg)+': ', end='')
        return input()

    def progressStatus(self, status: str):
        """Output the progress status of the fuzzing

        @type status: str
        @param status: The status progress of the fuzzing (between 0% to 100%)
        """
        with self.__lock:
            if not self.__lastInline:
                self.__eraseLine()
                self.__lastInline = True
            sys.stdout.flush()
            print('\r'+self.__getTime()+self.__getInfo(f"Status: {status} completed"), end='')

    def printForBoxMode(self, result: dict, vulnValidator: bool):
        """Custom output print for box mode

        @type result: dict
        @param result: The result dictionary
        @type vulnValidator: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        msg = self.__getMessage(result)
        if not vulnValidator:
            self.notWorkedBox(msg)
        else:
            if self.__lock:
                with self.__lock:
                    if self.__lastInline:
                        self.__eraseLine()
                        self.__lastInline = False
                    sys.stdout.flush()
            self.workedBox(msg)

    def __getTime(self):
        """Get a time label

        @returns str: The time label with format HH:MM:SS
        """
        now = datetime.now()
        time = now.strftime("%H:%M:%S")
        return f'{Colors.GRAY}[{Colors.LIGHT_GREEN}{time}{Colors.GRAY}]{Colors.RESET} '

    def __getInfo(self, msg: str):
        """The info getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with info label
        """
        return f'{self.__info}{msg}'

    def __getWarning(self, msg: str):
        """The warning getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with warning label
        """
        return f'{self.__warning}{msg}'
    
    def __getError(self, msg: str):
        """The error getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with error label
        """
        return f'{self.__error}{msg}'

    def __getAbort(self, msg: str):
        """The abort getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with abort label
        """
        return f'{self.__abord}{msg}'

    def __getWorked(self, msg: str):
        """The worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with worked label
        """
        return f'{self.__worked}{msg}'
    
    def __getNotWorked(self, msg: str):
        """The not worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with not worked label
        """
        return f'{self.__notWorked}{Colors.LIGHT_GRAY}{msg}{Colors.RESET}'

    def __eraseLine(self):
        """Erases the current line"""
        sys.stdout.flush()
        sys.stdout.write("\033[1K")
        sys.stdout.write("\033[0G")
        sys.stdout.flush()

    def __helpTitle(self, numSpaces: int, title: str):
        """Output the help title

        @type numSpaces: int
        @param numSpaces: The number of spaces before the title
        @type title: str
        @param title: The title or subtitle
        """
        print("\n"+' '*numSpaces+title)

    def __helpContent(self, numSpaces: int, command: str, desc: str):
        """Output the help content

        @type numSpaces: int
        @param numSpaces: The number of spaces before the content
        @type command: str
        @param command: The command to be used in the execution argument
        @type desc: str
        @param desc: The description of the command
        """
        print(' '*numSpaces+("{:<"+str(27-numSpaces)+"}").format(command)+' '+desc)
    
    def print(self, msg: str):
        """Print the message

        @type msg: str
        @param msg: The message
        """
        print(msg)

    def showHelpMenu(self):
        """Creates the Help Menu"""
        self.__helpTitle(0, "Parameters:")
        self.__helpTitle(3, "Misc:")
        self.__helpContent(5, "-h, --help", "Show the help menu and exit")
        self.__helpContent(5, "-v, --version", "Show the current version and exit")
        self.__helpTitle(3, "Request options:")
        self.__helpContent(5, "-r FILE", "Define the file with the raw HTTP request (scheme not specified)")
        self.__helpContent(5, "--scheme SCHEME", "Define the scheme used in the URL (default http)")
        self.__helpContent(5, "-u URL", "Define the target URL")
        self.__helpContent(5, "--data DATA", "Define the POST data")
        self.__helpContent(5, "--proxy IP:PORT", "Define the proxy")
        self.__helpContent(5, "--proxies FILE", "Define the file with a list of proxies")
        self.__helpContent(5, "--cookie COOKIE", "Define the HTTP Cookie header value")
        self.__helpContent(5, "--timeout TIMEOUT", "Define the request timeout (in seconds)")
        self.__helpContent(5, "--unfollow-redirects", "Stop to follow redirections")
        self.__helpTitle(3, "Dict options:")
        self.__helpContent(5, "-f FILE", "Define the wordlist file with the payloads")
        self.__helpContent(5, "--prefix PREFIX", "Define the prefix(es) used with the payload")
        self.__helpContent(5, "--suffix SUFFIX", "Define the suffix(es) used with the payload")
        self.__helpContent(5, "--upper", "Set the uppercase flag for the payloads")
        self.__helpContent(5, "--lower", "Set the lowercase flag for the payloads")
        self.__helpContent(5, "--capitalize", "Set the capitalize flag for the payloads")
        self.__helpTitle(3, "Match options:")
        self.__helpContent(5, "-Xc STATUS", "Allow responses based on their status codes")
        self.__helpContent(5, "-Xs SIZE", "Allow responses based on their length (in bytes)")
        self.__helpContent(5, "-Xt TIME", "Allow responses based on their elapsed time (in seconds)")
        self.__helpTitle(3, "More options:")
        self.__helpContent(5, "(-V, -V1) | -V2", "Enable the verbose mode (common or full verbose)")
        self.__helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
        self.__helpContent(5, "-t NUMBEROFTHREADS", "Define the number of threads used in the tests")
        self.__helpContent(5, "-o REPORT", "Define the report format (accept txt, csv and json)")
        self.__helpTitle(0, "Examples:")
        self.__helpContent(3, "./FuzzingTool.py -u http://127.0.0.1/post.php?id= -f /path/to/wordlist/sqli.txt -o fuzzingGet.csv", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/sqli.txt -u http://127.0.0.1/controller/user.php --data 'login&passw&user=login'", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/paths.txt -u http://127.0.0.1/$ --suffix .php,.html", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/subdomains.txt -u http://$.domainexample.com --timeout 5 -Xc 200,302,303,500-600", '')
        self.__helpContent(3, "./FuzzingTool.py -r /path/to/wordlist/raw-http.txt -f /path/to/wordlist/sqli.txt -V -o json", '')
        exit("")

outputHandler = OutputHandler.getInstance()