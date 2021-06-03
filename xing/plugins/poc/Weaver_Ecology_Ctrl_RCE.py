from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


"""
参考：
https://github.com/PeiQi0/PeiQi-WIKI-POC/blob/0e9c156abed6db1f7fe78c45540e2805f8ee0cb1/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20weaver.common.Ctrl%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.md
"""

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "泛微 Ecology weaver.common.Ctrl 任意文件上传漏洞"
        self.app_name = 'Ecology'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        path = "/weaver/weaver.common.Ctrl/.css"

        url = target + path
        conn = http_req(url)

        if len(conn.content) != 0:
            return False

        cookie = conn.headers.get("Set-Cookie", "")

        if "ecology_JSessionId" in cookie:
            self.logger.success("found Ecology RCE {}".format(target))
            return url