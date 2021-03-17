## 说明

集漏洞验证和漏洞利用的一个框架


## 依赖
https://nmap.org/ncrack/


## 安装
```
pip3 install -e .
```

## 使用

```
xing -h

usage: xing [-h] [--version] [--quit]
            [--log {debug,info,success,warning,error}]
            {list,scan,sniffer,exploit,brute} ...

positional arguments:
  {list,scan,sniffer,exploit,brute}
                        子命令
    list                显示插件
    scan                扫描
    sniffer             协议识别
    exploit             漏洞利用
    brute               弱口令爆破

optional arguments:
  -h, --help            show this help message and exit
  --version, -V         show program's version number and exit
  --quit, -q            安静模式 (default: False)
  --log {debug,info,success,warning,error}, -L {debug,info,success,warning,error
}
                        日志等级 (default: info)
```

其中子命令的`-t`参数可以为文件名也可以为单个指定的目标，`-n` 按照文件名筛选`PoC`

## 备注
本项目是ARL中的子模块

https://github.com/TophantTechnology/ARL