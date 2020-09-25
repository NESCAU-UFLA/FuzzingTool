import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import random
import socket
import struct

class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, **kwargs):
        self.source_address = self.generateAddress()
        super(SourceAddressAdapter, self).__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       source_address=self.source_address)
    
    def generateAddress(self):
        return (socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff))), 80)