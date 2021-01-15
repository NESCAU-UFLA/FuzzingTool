class RequestException(Exception):
    def __init__(self, exceptType: str = '', msg: str = ''):
        super().__init__(msg)
        self.type = exceptType