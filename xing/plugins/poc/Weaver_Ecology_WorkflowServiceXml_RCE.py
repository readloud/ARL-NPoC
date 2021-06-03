from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


"""
参考：
http://wiki.xypbk.com/Web%E5%AE%89%E5%85%A8/%E6%B3%9B%E5%BE%AEoa/%E6%B3%9B%E5%BE%AEE-Cology%20WorkflowServiceXml%20RCE%E4%B9%9F%E5%8F%ABxstream%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md
"""

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "泛微 Ecology WorkflowServiceXml XStream 反序列化"
        self.app_name = 'Ecology'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        path = "/services%20/WorkflowServiceXml"
        path_404 = "/services%20/WorkflowServiceXm"

        check = b"Invalid SOAP request"
        headers = {
            "SOAPAction": '""'
        }
        url = target + path
        conn = http_req(url, headers=headers)
        if check not in conn.content:
            self.logger.debug("not found SOAP {}".format(url))
            return

        url_404 = target + path_404
        conn = http_req(url_404, headers=headers)

        if check not in conn.content:
            self.logger.success("found Ecology RCE {}".format(target))
            return url
