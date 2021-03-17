from xing.core import PluginType, SchemeType
from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
import socket

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.SNIFFER
        self.default_port = [3306]
        self.target_scheme = SchemeType.MYSQL

    def sniffer(self, host, port):
        scheme_ack = b'mysql\r\n'
        check0 = b'\x00\x00\x00'
        check1 = b"MySQL"
        check2 = b"mysql"
        client = socket.socket()
        client.settimeout(4)
        client.connect((host, port))
        client.send(scheme_ack)
        data = client.recv(256)
        client.close()
        
        if len(data) >= 10 and data[1:4] == check0:
            if check1 in data or check2 in data:
                return self.target_scheme
        return False

