# -*- coding:utf-8 -*-
# by:kracer

# 引入模块、包部分
from gevent import monkey
monkey.patch_all()
import time
from request import *   #获取返回内容
from threading import Thread
from common import *
from process import *
from Third.JSFinder import *
from Third.wafw00f import entrance
from threading import Thread
from queue import Queue
from colorama import init
init(autoreset=True)





# 定义的常量、变量

t = [] #线程组
logo = '''\033[1;32m
  ____   *     _                ____ 
 /___ |  _   _| |_    ___ ,   /___ |  ____   _____    _____
 \_  \  | | |__ __| / ___, |  \_  \  / ___/ /  __\ \  | ___ \ 
  __) | | |   | |   | \__|_|   __) | | (__  | |__| |  | | | |
/____/  |_|   |__|  \_'____\ /____/  \____\ \ ____\ \ |_| |_|

                                                        \033[1;36mBy:kracer
                                                        \033[1;36mGithub:https://github.com/kracer127\033[0m
'''

# 主函数入口
def main(url, subDomain):
    tasks = []
    print('[+] 检测任务开启, 预估需要5min......')
    # 进入 domain2ip函数 获取当前url的ip解析及粗略地理位置
    t1 = request(url).domain2ip()
    t1_1 = Thread(target=t1)
    tasks.append(t1_1)
    # 进入 PangZhan函数 获取当前域名下的同服务器网站
    t2 = request(url).pangZhan()
    t2_1 = Thread(target=t2)
    tasks.append(t2_1)
    # 进入 IP138函数 获取备案、子域名、历史ip绑定信息
    t3 = request(url).IP138()
    t3_1 = Thread(target=t3)
    tasks.append(t3_1)
    # 进入 whatweb函数 获取网站的架构信息
    t4 = request(url).whatWeb()
    t4_1 = Thread(target=t4)
    tasks.append(t4_1)
    # 进入 icp.chinaz函数， 获取备案信息
    t5 = request(subDomain).Icp()
    t5_1 = Thread(target=t5)
    tasks.append(t5_1)
    # 进入 getCms函数 获取网站的架构信息
    t6 = request(url).getCms()
    t6_1 = Thread(target=t6)
    tasks.append(t6_1)
    # 进入 crt.sh函数 获取子域名信息
    t7 = request(subDomain).getCrtDomain()
    t7_1 = Thread(target=t7)
    tasks.append(t7_1)
    # 进入 virusTotal函数 获取子域名信息
    t8 = request(subDomain).virusDomain()
    t8_1 = Thread(target=t8)
    tasks.append(t8_1)
    # 判断能否翻墙以便进入下面两个函数
    def able2GFW():
        gfwFlag = request(url).ableGFW()
        if gfwFlag == True:
            # 进入 Hackertarget函数 获取子域名函数(需翻墙)
            request(subDomain).hackerTarget()
            # 进入 GoogleHacking函数 获取子所有域名+url路径 (需翻墙）
            request(subDomain).googleHack()
    t9 = Thread(target=able2GFW)
    tasks.append(t9)
    # 进入getPorts函数 获取网站开发端口信息
    t10 = request(url).getPorts()
    t10_1 = Thread(target=t10)
    tasks.append(t10_1)
    # 进入 isCDN函数 判断是否存在CDN信息
    t11 = request(url).isCDN()
    t11_1 = Thread(target=t11)
    tasks.append(t11_1)
    # 进入 JSfinder函数 查找js文件及提取子域名
    t12 = request(url).jsFinder()
    t12_1 = Thread(target=t12)
    tasks.append(t12_1)
    # 进入 wafw00f函数 侦探网站的waf
    def mainDetect():
        domain = allDict['urlPATH']
        keyURL_list = []
        for k in domain:
            if ('=' in k) and ('?' in k):
               keyURL_list.append(k)
        if len(keyURL_list) >= 2:
            request(keyURL_list[0]).detectWaf()
            request(keyURL_list[1]).detectWaf()
        elif len(keyURL_list) == 1:
            request(keyURL_list[0]).detectWaf()
            request(url).detectWaf()
        else:
            request(url).detectWaf()
            if len(domain) > 0:
                request(domain[0]).detectWaf()
        print("\033[1;34m[*] 完成网站waf信息侦测, 共"+str(len(allDict['framework'][2]))+"条数据!!\033[0m")
    t13 = mainDetect()
    t13_1 = Thread(target=t13)
    tasks.append(t13_1)
    for i in tasks:
        i.start()
    for j in tasks:
        j.join()



# 最终执行函数
if __name__ == '__main__':
    print(logo)
    args = parse_args()
    ip_url = args.url
    start = time.time()
    url = processUrl(ip_url)[0]
    subDomain = processUrl(ip_url)[-1]
    if isAlive(url) == True:  # 检测用户输入网址是否有效
        main(url, subDomain)
    else:
        print('\033[1;35m[-] 当前网址不可访问, 尝试根域名信息查询!!\033[0m')
        request(subDomain).Icp()
        request(subDomain).getCrtDomain()
        request(subDomain).virusDomain()
        def able2GFW():
            gfwFlag = request(url).ableGFW()
            if gfwFlag == True:
                # 进入 Hackertarget函数 获取子域名函数(需翻墙)
                request(subDomain).hackerTarget()
                # 进入 GoogleHacking函数 获取子所有域名+url路径 (需翻墙）
                request(subDomain).googleHack()
        able2GFW()
        print('\033[1;34m[-] 根域名信息查询完毕!!\033[0m')
    end = time.time()
    print('[*] 所有检测任务完成, 开始生成检测报告......')
    all2HTML(url, allDict, error)
    print("\033[1;36m[*] 本次检测共消耗时间:{:.2f}s\033[0m".format(end-start))



