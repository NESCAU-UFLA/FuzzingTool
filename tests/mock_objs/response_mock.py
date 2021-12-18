from unittest.mock import Mock
import datetime

from requests.models import PreparedRequest, Response
from urllib3 import HTTPResponse


class ResponseMock(Mock):
    def __init__(self):
        super().__init__(spec=Response)
        mock_raw = Mock(spec=HTTPResponse)
        mock_raw.version = 11
        mock_request = Mock(spec=PreparedRequest)
        mock_request.method = "GET"
        self.raw = mock_raw
        self.status_code = 200
        self.reason = "OK"
        self.url = "https://test-url.com/"
        self.request = mock_request
        self.elapsed = datetime.timedelta(seconds=2.0)
        self.headers = {
            'Server': "nginx/1.19.0",
            'Date': "Fri, 17 Dec 2021 17:42:14 GMT",
            'Content-Type': "text/html; charset=UTF-8",
            'Transfer-Encoding': "chunked",
            'Connection': "keep-alive",
            'X-Powered-By': "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1"
        }
        self.content = b"My Body Text\nFooter Text\n"
        self.text = "My Body Text\nFooter Text\n"
