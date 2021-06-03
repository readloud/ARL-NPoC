from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


"""
参考：
https://github.com/huahaiYa/poc_tools/blob/15d7135543d5090a0e10b6094058cf70a4db67f0/%E7%94%A8%E5%8F%8BNC6.xRCE/yongyource.py
"""

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "用友 NC BshServlet 远程命令执行漏洞"
        self.app_name = 'YonYou'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        path = "/servlet/~ic/bsh.servlet.BshServlet"

        url = target + path
        conn = http_req(url)

        if b">BeanShell Test Servlet<" in conn.content:
            self.logger.success("found 用友NC RCE {}".format(target))
            return url
