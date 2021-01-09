from datetime import datetime

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

    def getInitOrEnd(self):
        """Output the initial line of the requests table"""
        print('  +'+('-'*9)+'+'+('-'*12)+'+'+('-'*32)+'+'+('-'*8)+'+'+('-'*10)+'+'+('-'*12)+'+')

    def getHeader(self):
        """Output the header of the requests table"""
        self.getInitOrEnd()
        self.printContent(['Request','Req Time' , 'Payload', 'Status', 'Length', 'Resp Time'], False)
        self.getInitOrEnd()

    def printContent(self, args: list, vulnValidator: bool):
        """Output the content of the requests table

        @type args: list
        @param args: The arguments used in the table content
        @type vulnValidator: bool
        @param vulnValidator: Case the output is marked as vulnerable
        """
        if (not vulnValidator):
            print('  | '+'{:<7}'.format(args[0])+' | '+'{:<10}'.format(args[1])+' | '+'{:<30}'.format(self.fixLineToOutput(args[2]))+' | '+'{:<6}'.format(args[3])+' | '+'{:<8}'.format(args[4])+' | '+'{:<10}'.format(args[5])+' |')
        else:
            print('  | '+u'\u001b[32;1m{:<7}'.format(args[0])+'\033[0m | '+'\u001b[32;1m{:<10}'.format(args[1])+'\033[0m | '+'\u001b[32;1m{:<30}'.format(self.fixLineToOutput(args[2]))+'\033[0m | '+'\u001b[32;1m{:<6}'.format(args[3])+'\033[0m | '+'\u001b[32;1m{:<8}'.format(args[4])+'\033[0m | '+'\u001b[32;1m{:<10}'.format(args[5])+'\033[0m |')

    def askYesNo(self, msg: str):
        """Output an warning message, and ask for the user if wants to continue

        @type msg: str
        @param msg: The message
        @returns bool: The answer based on the user's input
        """
        action = input(self.__getTime()+self.__getWarning(msg))
        if (action == 'y' or action == 'Y'):
            return True
        else:
            return False

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

    def fixLineToOutput(self, line: str):
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

    def progressStatus(self, status: str, itemsFound: int):
        """Output the progress status of the fuzzing

        @type status: str
        @param status: The status progress of the fuzzing (between 0 to 100)
        """
        print('\r'+self.__getTime()+self.__getInfo("Progress status: "+'{:<4}'.format(status+'%')+f' completed | Found {str(itemsFound)} possible payload(s)'), end='')

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
        print(' '*numSpaces+("{:<"+str(26-numSpaces)+"}").format(command)+' '+desc)
    
    def showIntro(self):
        """Creates the intro"""
        print("\033[36m   ____                        _____       _")
        print("\033[36m  |  __|_ _ ___ ___ _ ___ ___ |_   _|_ ___| | \033[0mVersion 3.2.0")
        print("\033[36m  |  __| | |- _|- _|'|   | . |  | | . | . | |")
        print("\033[36m  |_|  |___|___|___|_|_|_|_  |  |_|___|___|_|")
        print("\033[36m                         |___|\033[0m\n")
        print("  [!] Disclaimer: We're not responsible for the misuse of this tool.")
        print("      This project was created for educational purposes")
        print("      and should not be used in environments without legal authorization.\n")

    def showHelpMenu(self):
        """Creates the Help Menu"""
        self.__helpTitle(0, "Parameters:")
        self.__helpContent(3, "-h, --help", "Show the help menu and exit")
        self.__helpContent(3, "-V, --verbose", "Enable the verbose mode")
        self.__helpContent(3, "-v, --version", "Show the current version and exit")
        self.__helpTitle(3, "Core:")
        self.__helpContent(5, "-r FILENAME", "Define the request data (including target)")
        self.__helpContent(5, "-u URL", "Define the target URL")
        self.__helpContent(5, "-f FILENAME", "Define the wordlist file with the payloads")
        self.__helpTitle(3, "Request options:")
        self.__helpContent(5, "--data DATA", "Define the POST data")
        self.__helpContent(5, "--proxy IP:PORT", "Define the proxy")
        self.__helpContent(5, "--proxies FILENAME", "Define the file with a list of proxies")
        self.__helpContent(5, "--cookie COOKIE", "Define the HTTP Cookie header value")
        self.__helpTitle(3, "More options:")
        self.__helpContent(5, "--delay DELAY", "Define the delay between each request (in seconds)")
        self.__helpContent(5, "-t NUMBEROFTHREADS", "Define the number of threads used in the tests")
        self.__helpTitle(0, "Examples:")
        self.__helpContent(3, "./FuzzingTool.py -u http://127.0.0.1/post.php?id= -f sqli.txt", '')
        self.__helpContent(3, "./FuzzingTool.py -f sqli.txt -u http://127.0.0.1/controller/user.php --data 'login&passw&user=login'", '')
        self.__helpContent(3, "./FuzzingTool.py -f paths.txt -u http://127.0.0.1/$", '')
        self.__helpContent(3, "./FuzzingTool.py -r data.txt -f sqli.txt -V", '')
        exit("")

outputHandler = OutputHandler.getInstance()