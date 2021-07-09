from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "YApi 存在开放注册"
        self.app_name = 'YApi'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        url = target + "/api/user/status"
        conn = http_req(url)

        if b'"canRegister":true' in conn.content:
            self.logger.success("found YApi 存在开放注册 {}".format(url))
            return True
        else:
            return False
