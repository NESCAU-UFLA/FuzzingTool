class VulnValidator:
    """A vulnerability validator

    Attributes:
        urlFuzzing: The URL Fuzzing flag
        defaultComparator: The dictionary with the default entries to be compared with the current request
    """
    def __init__(self, urlFuzzing: bool, length: int = 0, time: float = 0):
        """Class constructor

        @type urlFuzzing: bool
        @param urlFuzzing: The URL Fuzzing flag
        @type length: int
        @param length: The first request length
        @type time: float
        @param time: The first request time taken
        """
        self.__urlFuzzing = urlFuzzing
        self.__defaultComparator = {
            'Length': 300 + length,
            'Time': 5 + time,
        }
    
    def isVulnerable(self, thisResponse: dict):
        """Check if the request content has some predefined characteristics based on a payload, it'll be considered as vulnerable
        
        @type thisResponse: dict
        @param thisResponse: The actual response dictionary
        @returns bool: A vulnerability flag
        """
        if thisResponse['Status'] < 400:
            if self.__urlFuzzing:
                return True
            elif self.__defaultComparator['Length'] < int(thisResponse['Length']):
                return True
        if not self.__urlFuzzing and self.__defaultComparator['Time'] < (thisResponse['Resp Time']+thisResponse['Req Time']):
            return True
        return False