<h1 align="center" >SiteScan</h1>

<h4 align="center" >渗透本质--信息收集</h3>
<p align="center">
    <a href="https://github.com/kracer127/SiteScan"><img alt="SiteScan" src="https://visitor-badge.glitch.me/badge?page_id=kracer127.SiteScan"></a>
    <a href="https://github.com/kracer127/SiteScan"><img alt="SiteScan" src="https://img.shields.io/github/stars/kracer127/SiteScan.svg"></a>
    <a href="https://github.com/kracer127/SiteScan/releases"><img alt="SiteScan" src="https://img.shields.io/github/release/kracer127/SiteScan.svg"></a>
</p>

## 🏝 0x01 介绍
作者：kracer

定位：专注一站式解决渗透测试的信息收集任务。

语言：python3开发

功能：包括域名ip历史解析、nmap常见端口爆破、子域名信息收集、旁站信息收集、whois信息收集、网站架构分析、cms解析、备案号信息收集、CDN信息解析、是否存在waf检测、后台寻找以及生成检测结果html报告表等。



## 🎸0x02 安装使用

1、所需库安装

```python
pip3 install -r requirements.txt
```

2、使用

```python
>>python3 main.py -u http://www.xxx.com
>>python3 main.py -u http://www.xxx.com -p http://127.0.0.1:8080
```

3、说明

```python
文件夹：lib文件夹 --- 配置文件。
文件夹: output文件夹 --- 探测结果生成的html报告表。
文件夹：Third --- 第三方模块, 包含wafwoof识别云waf、JSFinder爬取js文件。
文件：commom.py --- 用户输入处理、网址存活检测等。
文件：config.py --- requests库的请求设置：header头部、超时时间、google的url提取量、网络错误尝试次数、重定向和代理设置，以及定义扫描的端口。
文件：main.py --- 主函数入口。
文件：process.py --- 处理最终结果并生成html报告。
文件：request.py --- 封装的所有请求类。
```



## 💡0x03 效果展示
**1、程序运行过程：**

<img src="lib\imgs\operating.png" alt="operating" style="zoom:80%;" />



**2、生成的html报告：**

<img src="lib\imgs\result.png" alt="result" style="zoom:80%;" />

## 📝0x04 声明:

​	**本项目仅供学习, 测试, 交流使用, 勿用于非法用途。**

​	**请使用者遵守《中华人民共和国网络安全法》，勿用于非授权测试，如作他用所承受的法律责任一概与**

**作者无关，下载使用即代表使用者同意上述观点**。

​	**喜欢❤️请收藏给一个star吧👍**

​	**借鉴：**https://github.com/Threezh1/JSFinder

​	           https://github.com/EnableSecurity/wafw00f
