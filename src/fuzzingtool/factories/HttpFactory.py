from .BaseFactories import BaseHttpFactory
from ..conn.requests import *

from importlib import import_module

class HttpFactory(BaseHttpFactory):
    def requestCreator(requestType, url, **kwargs):
        Request = import_module(
            f"fuzzingtool.conn.requests.{requestType}",
            package=requestType
        )
        return getattr(Request, requestType)(url, **kwargs)