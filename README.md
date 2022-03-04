# ARL-NPoC

## dependencies
https://nmap.org/ncrack/


## Install
````
pip3 install -r requirements.txt
pip3 install -e .
````

## use

````
xing -h

usage: xing [-h] [--version] [--quit]
[--log {debug,info,success,warning,error}]
{list,scan,sniffer,exploit,brute} ...

positional arguments:
{list,scan,sniffer,exploit,brute}
subcommand
list show plugins
scan scan
sniffer protocol identification
exploit exploit
brute weak password blasting

optional arguments:
-h, --help show this help message and exit
--version, -V show program's version number and exit
--quit, -q Quiet mode (default: False)
--log {debug,info,success,warning,error}, -L {debug,info,success,warning,error
}
log level (default: info)
````

The `-t` parameter of the subcommand can be a file name or a single specified target, and `-n` filters `PoC` according to the file name

## Remark
This project is a submodule in ARL

[TophantTechnology](https://github.com/TophantTechnology/ARL)

## Disclaimer
If you download, install, use, modify this system and related codes, it means that you trust this system.
We shall not be liable for any loss or injury of any kind to yourself or others while using this system.
If you have any illegal behavior in the process of using this system, you shall bear the corresponding consequences by yourself, and we will not bear any legal and joint responsibility.
Please be sure to carefully read and fully understand the contents of each clause, especially the clauses exempting or limiting liability, and choose to accept or not to accept.
You have no right to download, install or use this system unless you have read and accepted all the terms of this agreement.
Your download, installation, use and other behaviors are deemed that you have read and agreed to be bound by the above agreement.
