from xing.core.ServiceBrutePlugin import ServiceBrutePlugin
from xing.core import PluginType, SchemeType


"""
测试有问题
"""


class Plugin(ServiceBrutePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.BRUTE
        self.vul_name = "MongoDB 弱口令"
        self.app_name = 'mongodb'
        self.scheme = [SchemeType.MONGODB]

        self.username_file = "username_mongodb.txt"
        self.password_file = "password_mongodb.txt"

    def service_brute(self):
        return self._crack_user_pass()


"""
创建容器
docker run -p 27018:27017 -it --rm -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD=secret mongo:4.0 mongod

"""






