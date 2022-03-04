<h1 align="center">Welcome to xray 👋</h1>
<p>
<img src="https://img.shields.io/github/release/chaitin/xray.svg" />
<img src="https://img.shields.io/github/release-date/chaitin/xray.svg?color=blue&label=update" />
<img src="https://img.shields.io/badge/go report-A+-brightgreen.svg" />
<a href="https://chaitin.github.io/xray/#/">
<img alt="Documentation" src="https://img.shields.io/badge/documentation-yes-brightgreen.svg" target="_blank" />
</a>
</p>

> A powerful security assessment tool

### ✨ Demo

![](https://docs.xray.cool/assets/term.svg)

🏠[Documentation](https://docs.xray.cool) ⬇️[Download](https://github.com/chaitin/xray/releases)

Note: xray is not open source, you can directly download the built binary files. The POCs in the warehouse are mainly contributed to the community, and each xray release will be automatically packaged.

## 🚀 Quick use

**Before using, please be sure to read and agree to the terms in the [License](https://github.com/chaitin/xray/blob/master/LICENSE.md) file, otherwise please do not install and use this tool. **

1. Use the basic crawler to crawl and scan the links crawled by the crawler for vulnerabilities
 
```bash
xray webscan --basic-crawler http://example.com --html-output vuln.html
./xray_linux_amd64 webscan --basic-crawler http://simantan.one --html-output vuln.html
````

1. Passive scanning using an HTTP proxy
 
```bash
xray webscan --listen 127.0.0.1:7777 --html-output proxy.html
````
Set the browser http proxy to `http://127.0.0.1:7777`, you can automatically analyze and scan the proxy traffic.
 
> To scan https traffic, please read the `Capturing https traffic` section of the document below

1. Only scan a single url, do not use crawlers
 
```bash
xray webscan --url http://example.com/?a=b --html-output single-url.html
````

1. Manually specify the plugin to run this time
 
By default, all built-in plugins will be enabled, you can use the following command to specify which plugins are enabled for this scan.
 
```bash
xray webscan --plugins cmd-injection,sqldet --url http://example.com
xray webscan --plugins cmd-injection,sqldet --listen 127.0.0.1:7777
````
 
1. Specify plugin output

You can specify to output the vulnerability information of this scan to a file:
 
```bash
xray webscan --url http://example.com/?a=b \
--text-output result.txt --json-output result.json --html-output report.html
````
 
[Example report](https://docs.xray.cool/assets/report_example.html)

For other usage, please read the documentation: https://docs.xray.cool


## 🛠 Detection module

New detection modules will be added continuously

- XSS vulnerability detection (key: xss)

Detecting XSS Vulnerabilities Using Semantic Analysis

- SQL injection detection (key: sqldet)

Support error injection, Boolean injection and blind time injection, etc.

- Command/code injection detection (key: cmd-injection)

Support shell command injection, PHP code execution, template injection, etc.

- Directory enumeration (key: dirscan)

Detect more than 10 types of sensitive paths and files such as backup files, temporary files, debug pages, and configuration files

- Path traversal detection (key: path-traversal)

Supports common platforms and encodings

- XML ​​entity injection detection (key: xxe)

Supports platform detection with echo and anti-connection

- poc management (key: phantasm)

Some common POCs are built in by default, and users can build and run POCs according to their own needs. Documentation: https://docs.xray.cool/#/guide/poc

- File upload detection (key: upload)

Support for common backend languages

- Weak password detection (key: brute-force)

Community edition supports detection of HTTP basic authentication and simple form weak passwords, built-in common username and password dictionary

- jsonp detection (key: jsonp)

Detect jsonp interfaces containing sensitive information that can be read across domains

- ssrf detection (key: ssrf)

ssrf detection module, supports common bypass techniques and anti-connection platform detection

- Baseline check (key: baseline)

Detect low SSL versions, missing or incorrectly added http headers, etc.

- Arbitrary jump detection (key: redirect)

Support HTML meta jump, 30x jump, etc.

- CRLF injection (key: crlf-injection)

Detect HTTP header injection, support query, body and other parameters
 
- Struts2 series vulnerability detection (advanced version, key: struts)

Detect whether the target website has Struts2 series of vulnerabilities, including s2-016, s2-032, s2-045 and other common vulnerabilities

- Thinkphp series vulnerability detection (advanced version, key: thinkphp)

Detect related vulnerabilities of websites developed by ThinkPHP
 
- ..


## ⚡️ Advanced usage

Please see https://docs.xray.cool/ for the following advanced usage.

- Modify configuration files
- Grab https traffic
- Modify the http package configuration
- The use of anti-connection platform
- ...

## 😘 Contribute POC

Reference: https://docs.xray.cool/#/guide/contribute

## 📝 Discussion

Submit false positives and false negatives, etc. Please read https://docs.xray.cool/#/guide/feedback first

If you have any questions, you can raise an issue on GitHub, or in the discussion group below

1. GitHub issue: https://github.com/chaitin/xray/issues
2. QQ group: 717365081
3. WeChat official account: Scan the following QR code on WeChat to follow us

<img src="https://docs.xray.cool/assets/wechat.jpg?cache=_none" height="200px">

4. WeChat group: Scan the following QR code on WeChat to join the group

<img src="https://ctstack-oss.oss-cn-beijing.aliyuncs.com/xray/ctstack-group-qr-code.jpg" height="200px">


