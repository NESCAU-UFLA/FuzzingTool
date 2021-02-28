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

if platform.system() == 'Windows':
    try:
        from colorama import init
    except:
        exit("Colorama package not installed. Install all dependencies first.")
    init()

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
        self.__info = '\033[90m['+'\033[36mINFO'+'\033[90m] \033[0m'
        self.__warning = '\033[90m['+'\033[33mWARNING'+'\033[90m] \033[0m'
        self.__error = '\033[90m['+'\u001b[31;1mERROR'+'\033[90m] \033[0m'
        self.__abord = '\033[90m['+'\u001b[31;1mABORT'+'\033[90m] \033[0m'
        self.__worked = '\033[90m['+'\u001b[32;1m+'+'\033[90m] \033[0m'
        self.__notWorked = '\033[90m['+'\u001b[31;1m-'+'\033[90m] \033[0m'

    def setPrintContentMode(self, subdomainFuzzing: bool):
        """Set the print content mode by the Fuzzer responses

        @type subdomainFuzzing: bool
        @param subdomainFuzzing: The subdomain fuzzing flag
        """
        if subdomainFuzzing:
            self.printContent = self.printForSubdomainMode
        else:
            self.printContent = self.printForDefaultMode

    def infoBox(self, msg: str):
        """Print the message with a info label

        @type msg: str
        @param msg: The message
        """
        print(self.__getTime()+self.__getInfo(msg))

    def errorBox(self, msg: str):
        """End the application with error label and a message

        @type msg: str
        @param msg: The message
        """
        exit(self.__getTime()+self.__getError(msg))
 
    def warningBox(self, msg: str):
        """Print the message with a warning label

        @type msg: str
        @param msg: The message
        """
        print(self.__getTime()+self.__getWarning(msg))

    def abortBox(self, msg: str):
        """Print the message with abort label and a message

        @type msg: str
        @param msg: The message
        """
        print('\n'+self.__getTime()+self.__getAbort(msg))

    def workedBox(self, msg: str):
        """Print the message with worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(self.__getTime()+self.__getWorked(msg))

    def notWorkedBox(self, msg: str):
        """Print the message with not worked label and a message

        @type msg: str
        @param msg: The message
        """
        print(self.__getTime()+self.__getNotWorked(msg))

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
        print(self.__getTime()+getType(msg)+' (y/N) ', end='')
        action = input()
        if (action == 'y' or action == 'Y'):
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

    def getInitOrEnd(self):
        """Output the initial line of the requests table"""
        print('  +'+('-'*9)+
              '+'+('-'*32)+
              '+'+('-'*12)+
              '+'+('-'*6)+
              '+'+('-'*10)+
              '+'+('-'*8)+
              '+'+('-'*7)+
              '+')

    def getHeader(self):
        """Output the header of the requests table"""
        self.getInitOrEnd()
        self.printForDefaultMode({
            'Request': 'Request',
            'Payload': 'Payload',
            'Time Taken': 'Time Taken',
            'Status': 'Code',
            'Length': 'Length',
            'Words': 'Words',
            'Lines': 'Lines',
        }, False)
        self.getInitOrEnd()

    def progressStatus(self, status: str, itemsFound: int):
        """Output the progress status of the fuzzing

        @type status: str
        @param status: The status progress of the fuzzing (between 0 to 100)
        @type itemsFound: int
        @param itemsFound: The number of possible payloads found
        """
        print('\r'+self.__getTime()+self.__getInfo("Progress status: "+'{:<4}'.format(status+'%')+f' completed | Found {str(itemsFound)} possible payload(s)'), end='')

    def printForDefaultMode(self, response: dict, vulnValidator: bool):
        """Output the content of the requests table

        @type response: dict
        @param response: The response dictionary
        @type vulnValidator: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        if not vulnValidator:
            colorCode = '\033[0m'
        else:
            colorCode = '\u001b[32;1m'
        print(f'  | {colorCode}'+'{:<7}'.format(response['Request'])+
              f'\033[0m | {colorCode}'+'{:<30}'.format(self.__fixLineToOutput(response['Payload']))+
              f'\033[0m | {colorCode}'+'{:<10}'.format(response['Time Taken'])+
              f'\033[0m | {colorCode}'+'{:<4}'.format(response['Status'])+
              f'\033[0m | {colorCode}'+'{:<8}'.format(response['Length'])+
              f'\033[0m | {colorCode}'+'{:<6}'.format(response['Words'])+
              f'\033[0m | {colorCode}'+'{:<5}'.format(response['Lines'])+
               '\033[0m |')

    def printForSubdomainMode(self, response: dict, vulnValidator: bool):
        """Custom output print for the subdomain fuzzing mode

        @type response: dict
        @param response: The response dictionary
        @type vulnValidator: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        msg = f"Host {response['Payload']} ({response['IP']}) connected, raised a {response['Status']} status code"
        if not vulnValidator:
            self.notWorkedBox(msg)
        else:
            self.workedBox(msg)

    def __fixLineToOutput(self, line: str):
        """Fix the line's size readed by the file

        @type line: str
        @param line: The line from the file
        @returns str: The fixed line to output
        """
        if (len(line) > 30):
            output = ""
            for i in range(27):
                if line[i] == '	':
                    output += ' '
                else:
                    output += line[i]
            output += '...'
            return output.rstrip()
        else:
            return line.rstrip()

    def __getTime(self):
        """Get a time label

        @returns str: The time label with format HH:MM:SS
        """
        now = datetime.now()
        time = now.strftime("%H:%M:%S")
        return '\033[90m['+'\u001b[38;5;48m'+time+'\033[90m] \033[0m'

    def __getInfo(self, msg: str):
        """The info getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with info label
        """
        return self.__info + msg

    def __getWarning(self, msg: str):
        """The warning getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with warning label
        """
        return self.__warning + msg
    
    def __getError(self, msg: str):
        """The error getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with error label
        """
        return self.__error + msg

    def __getAbort(self, msg: str):
        """The abort getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with abort label
        """
        return self.__abord + msg

    def __getWorked(self, msg: str):
        """The worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with worked label
        """
        return self.__worked + msg
    
    def __getNotWorked(self, msg: str):
        """The not worked getter, with a custom message

        @type msg: str
        @param msg: The custom message
        @returns str: The message with not worked label
        """
        return self.__notWorked + '\u001b[38;5;250m' + msg + '\033[0m'

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
        print(' '*numSpaces+("{:<"+str(30-numSpaces)+"}").format(command)+' '+desc)
    
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
        self.__helpTitle(3, "Dict options:")
        self.__helpContent(5, "-f FILE", "Define the wordlist file with the payloads")
        self.__helpContent(5, "--prefix PREFIX", "Define the prefix(es) used with the payload")
        self.__helpContent(5, "--suffix SUFFIX", "Define the suffix(es) used with the payload")
        self.__helpContent(5, "--upper", "Set the uppercase flag for the payloads")
        self.__helpContent(5, "--lower", "Set the lowercase flag for the payloads")
        self.__helpContent(5, "--capitalize", "Set the capitalize flag for the payloads")
        self.__helpTitle(3, "More options:")
        self.__helpContent(5, "-V, --verbose", "Enable the verbose mode")
        self.__helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
        self.__helpContent(5, "-t NUMBEROFTHREADS", "Define the number of threads used in the tests")
        self.__helpContent(5, "--allowed-status STATUS", "Define the allowed status codes for responses to be saved on report")
        self.__helpContent(5, "-o REPORT", "Define the report format (accept txt, csv and json)")
        self.__helpTitle(0, "Examples:")
        self.__helpContent(3, "./FuzzingTool.py -u http://127.0.0.1/post.php?id= -f /path/to/wordlist/sqli.txt -o fuzzingGet.csv", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/sqli.txt -u http://127.0.0.1/controller/user.php --data 'login&passw&user=login'", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/paths.txt -u http://127.0.0.1/$ --suffix .php,.html", '')
        self.__helpContent(3, "./FuzzingTool.py -f /path/to/wordlist/subdomains.txt -u http://$.domainexample.com --timeout 5 --allowed-status 200,302,303,500-600", '')
        self.__helpContent(3, "./FuzzingTool.py -r /path/to/wordlist/raw-http.txt -f /path/to/wordlist/sqli.txt -V -o json", '')
        exit("")

outputHandler = OutputHandler.getInstance()