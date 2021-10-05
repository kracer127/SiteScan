# -*- coding:utf-8 -*-
# by:kracer

# 引入模块、包部分

import gevent
from gevent import Greenlet
from gevent.queue import Queue

import requests
import process
from lib.whois import whois
import re, json
from bs4 import BeautifulSoup as bs
from config import *
from common import *
from Third.JSFinder import *
from Third.wafw00f import entrance
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#定义的常量
allDict = {'nowIP': [], 'domain': [], 'ports': [], 'whois': [], 'beiAn': [], 'framework': [[], {}, {}], 'urlPATH': [], 'isCDN': [], 'pangZhan': [], 'historyIP': []}
error = []
times = tryTimes


# 定义的web基础信息请求包类
class request:
    def __init__(self, url):
        self.url = url
        self.subdomain = processUrl(url)[-1]
        self.proxy = proxies
        self.ip = ''

    # get请求方法
    def get(self, Domain, header):
        try:
            result = requests.get(
                url=Domain,
                headers=header,
                timeout=timeout,
                proxies=self.proxy,
                allow_redirects=allow_redirects,
                verify=allow_ssl_verify
            )
            return result.text
        except Exception as e:
            return e

    # POST 请求方法
    def post(self, Domain, header, data):
        try:
            result = requests.post(
                url=Domain,
                headers=header,
                data=data,
                timeout=timeout,
                proxies=self.proxy,
                allow_redirects=allow_redirects,
                verify=allow_ssl_verify
            )
            return result.text
        except Exception as e:
            return e

    #获取当前查询网站的ip地址 及对应的国家
    def domain2ip(self):
        global allDict, error, times
        flag1 = False
        header = headers('www.ip.cn')
        url = 'https://www.ip.cn/ip/{0}.html'.format(self.url)
        result = []
        print('[*] 正在进行url解析查询......')
        try:
            r = self.get(url, header)
            r1_ip = re.findall('<div >(.*?)</div>', r)[0]
            r1_addr = re.findall('id="tab0_address">(.*?)</div>', r)[0]
            flag1 = True
            result.append(r1_ip+'::'+r1_addr)
            allDict['nowIP'] += result
            print('\033[1;34m[*] 完成url解析查询, 共'+str(len(result))+'条数据!!\033[0m')
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'domain2ip解析错误!'+'-->'+str(e))
            print('\033[1;31m[-] url解析查询失败!\033[0m')
        finally:
            if (flag1 != True) and (times >= 1):
                self.domain2ip()
            else:
                times = tryTimes

    # 获取ip下的旁站获取
    def pangZhan(self):
        global allDict, error, times
        flag2 = False
        header = headers('www.webscan.cc')
        url = 'https://www.webscan.cc/ip_' + self.url
        print('[*] 正在进行旁站信息查询......')
        try:
            r = self.get(url, header)
            result = re.findall('target=\"_blank\">(.*?)\<\/a\>\<\/li\>', r)
            allDict['pangZhan'] = result[:-2]
            flag2 = True
            print('\033[1;34m[*] 完成旁站信息查询, 共'+str(len(result)-2)+'条数据!!\033[0m')
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'PangZhan获取旁站失败!'+'-->'+str(e))
            print('\033[1;31m[-] 旁站信息查询失败!\033[0m')
        finally:
            if (flag2 != True) and (times >= 1):
                self.pangZhan()
            else:
                times = tryTimes

    # IP138查询函数，获取域名当前ip地址历史解析、子域名、备案、whois信息
    def IP138(self):
        global allDict, error, times
        header = headers('site.ip138.com')
        site = "http://site.ip138.com/"
        ip_list, beian_list, domain_list, whois_list = [], [], [], []
        url_ip = site+self.url+'/'
        url_domain = site+self.subdomain+"/domain.htm"
        url_beian = site+self.subdomain+"/beian.htm"
        url_whois = site+self.subdomain+"/whois.htm"
        def ip(times):
            flag3_1 = False
            '''ip138的ip解析功能'''
            try:
                r_ip = self.get(url_ip, header)    #ip的解析请求
                r1_ip_date = re.findall('class="date"\>(.*?)\</span\>', r_ip)
                r1_ip_content = re.findall('target="_blank"\>(.*?)\</a\>\n</p\>', r_ip)
                flag3_1 = True
                for i, j in zip(r1_ip_content, r1_ip_date):
                    ip_str = i+'::'+j
                    ip_list.append(ip_str)
                allDict['historyIP'] = ip_list
                print("\033[1;36m[+] ip历史解析查询完成, 共"+str(len(ip_list))+"条数据!\033[0m")
            except Exception as e:
                times -= 1
                error.append(self.url+'-->'+'ip138获取地址ip信息失败!'+'-->'+str(e))
                print('\033[1;31m[~] IP138地址ip解析失败!\033[0m')
            finally:
                if (flag3_1 != True) and (times >= 1):
                    ip(times)
                else:
                    times = tryTimes
        def domain(times):
            flag3_2 = False
            '''ip138的子域名功能'''
            try:
                r_domain = self.get(url_domain, header)  #子域名的解析请求
                r1_domain = re.findall('target="_blank"\>(.*?)\</a\>\</p\>', r_domain)
                flag3_2 = True
                allDict['domain'] = r1_domain
                print("\033[1;36m[+] 子域名查询完成, 共"+str(len(r1_domain))+"条数据!!\033[0m")
            except Exception as e:
                times -= 1
                error.append(self.url+'-->'+'ip138获取子域名信息失败!'+'-->'+str(e))
                print('\033[1;31m[~] IP138获取子域名信息失败!\033[0m')
            finally:
                if (flag3_2 != True) and (times >= 1):
                    domain(times)
                else:
                    times = tryTimes
        def beian(times):
            flag3_3 = False
            '''ip138的备案功能'''
            try:
                r_beian = self.get(url_beian, header)  #备案的解析请求
                r1_beian_date = re.findall('class="date">\n(.*?)</span>', r_beian)
                r1_beian_content = re.findall('target="_blank">(.*?)</a>\n</p>', r_beian)
                flag3_3 = True
                if r1_beian_content == []:
                    r1_beian_content = ['未备案']
                if r1_beian_date == []:
                    r1_beian_date = ['空']
                for i, j in zip(r1_beian_content, r1_beian_date):
                    beian_str = i+':'+j.rstrip(' ')  #去除多余的空格
                    beian_list.append(beian_str)
                allDict['beiAn'] = beian_list
                print("\033[1;36m[+] 域名备案信息查询完成, 共"+str(len(beian_list))+"条数据!!\033[0m")
            except Exception as e:
                times -= 1
                error.append(self.url+'-->'+'ip138获取备案信息失败!'+'-->'+str(e))
                print('\033[1;31m[~] IP138获取备案信息失败!\033[0m')
            finally:
                if (flag3_3 != True) and (times >= 1):
                    beian(times)
                else:
                    times = tryTimes
        def isWho(times):
            flag3_4 = False
            '''ip138的whois查询不稳定，此调用python-whois库来实现'''
            try:
                r_whois = whois(self.url)
                r1_whois = {}
                if r_whois["domain_name"] == None:
                    r1_whois = []
                else:
                    for k in r_whois.keys():
                        r1_whois[k] = str(r_whois[k])
                flag3_4 = True
                allDict['whois'] += [r1_whois]
                print("\033[1;36m[+] whois信息查询完成, 共"+str(len(r1_whois))+"条数据!!\033[0m")
            except Exception as e:
                times -= 1
                error.append(self.url+'-->'+'ip138获取whois信息失败!'+'-->'+str(e))
                print('\033[1;31m[~] IP138获取whois信息失败!\033[0m')
            finally:
                if (flag3_4 != True) and (times >= 1):
                    isWho(times)
                else:
                    times = tryTimes
        print("[*] 正在进行ip138查询......")
        ip(times)
        domain(times)
        beian(times)
        isWho(times)
        print("\033[1;34m[*] IP138所有信息查询完成!!\033[0m")

    # whatweb获取网站的架构信息
    def whatWeb(self):
        global allDict, error, times
        flag4 = False
        header = headers('www.whatweb.net')
        site = 'https://www.whatweb.net/whatweb.php'
        result = []
        data = {'target': self.url}
        print('[*] 正在进行网站的架构信息查询......')
        try:
            r = self.post(site, header, data)
            if r != '':
                r1 = r.rstrip('\n')
                result = r1.split(', ')
                result[0] = result[0].split(' ')[-1]
            flag4 = True
            allDict['framework'][0] += result
            print('\033[1;34m[*] 完成网站的架构信息查询, 共'+str(len(result)-2)+'条数据!!\033[0m')
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'whatweb获取网站的架构信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] 网站的架构信息查询失败!\033[0m')
        finally:
            if (flag4 != True) and (times >= 1):
                self.whatWeb()
            else:
                times = tryTimes

    # icpchacha.com备案查询函数
    def Icp(self):
        global allDict, error, times
        flag5 = False
        header = headers('www.icpchacha.com')
        site = "http://www.icpchacha.com/s/"
        beian_list = []   # 定义一个列表，接受返回结果
        print("[*] 正在进行备案信息查询......")
        url1 = site+self.url+'/'  # 该域名下的网站备案情况
        try:
            res = self.get(url1, header)
            if '没有符合条件的记录' not in res:   #解决未备案情况的报错
                res1 = re.findall('id=\"ba_Name\">(.*?)</span>', res)
                res2 = re.findall('id=\"ba_Type\">(.*?)</span>', res)
                res3 = re.findall('id=\"ba_License\">(.*?)</span>', res)
                res4 = re.findall('id=\"ba_WebName\">(.*?)</span>', res)
                res5 = re.findall('id=\"ba_WebName\">(.*?)</span>', res)
                res6 = re.findall('id=\"ba_DateTime\">(.*?)</span>', res)
                beianStr = "主办单位: " + str(res1[0])+'('+str(res2[0])+')'+'\n'+"备案号: " + res3[0]+'\n'+"网站名称: " + res4[0]+'\n'+"网站首页: " + res5[0]+'\n'+"审核时间: " + str(res6[0])
                beian_list = beianStr.split('\n')
                allDict['beiAn'] += beian_list
                url2 = 'http://www.icpchacha.com/l/'+res3[0]+'/?i=2'
                otherBeian = self.get(url2, header)
                otherBeian_list = re.findall('class=\"view-link\" target=\"_blank">(.*?)</a></td>', otherBeian)
                allDict['beiAn'] += [{"该备案号下的其他域名": otherBeian_list}]
            else:
                beian_list = []
            flag5 = True
            print('\033[1;34m[*] 完成所有备案信息查询完成, 共'+str(len(beian_list))+'条数据!!\033[0m')
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'Icp获取网站的备案信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] 域名备案信息查询失败!\033[0m')
        finally:
            if (flag5 != True) and (times >= 1):
                self.Icp()
            else:
                times = tryTimes

    # whatweb.bugscanner网站的CMS信息查询函数
    def getCms(self):
        global allDict, error, times
        flag6 = False
        header = headers('whatweb.bugscaner.com')
        site = 'http://whatweb.bugscaner.com/what.go'
        payload = {'url': self.url, 'location_capcha':'no'}
        Cms_list = []
        print("[*] 正在进行网站的指纹识别......")
        try:
            res = self.post(site, header, payload)
            Cms_list = json.loads(res)
            flag6 = True
            allDict['framework'][1] = Cms_list
            print('\033[1;34m[*] 完成网站指纹识别, 共'+str(len(Cms_list))+'条数据!!\033[0m')
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'whatweb获取网站指纹信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] 网站指纹信息查询失败!\033[0m')
        finally:
            if (flag6 != True) and (times >= 1):
                self.getCms()
            else:
                times = tryTimes

    # crt.sh查询子域名函数
    def getCrtDomain(self):
        global allDict, error, times
        flag7 = False
        header = headers('crt.sh')
        site = "https://crt.sh/?q="
        crt_list = []
        print("[*] 正在通过crt查询域名......")
        url = site + self.url
        suffix = self.url.split('.')[-1]  #获取域名的后缀
        try:
            r = self.get(url, header)
            r1 = re.findall(suffix+'</TD>\n    <TD>(.*?)</TD>\n    <TD><A', r)
            flag7 = True
            for i in r1:
                if "<BR>" in i:
                    other = i.split("<BR>")
                    for j in other:
                        crt_list.append(j)
                else:
                    crt_list.append(i)
            crt_list = list(set(crt_list))
            allDict['domain'] += crt_list
            print("\033[1;34m[*] 完成crt子域名获取, 共"+str(len(crt_list))+"条数据!!\033[0m")
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'crt获取子域名信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] crt.sh获取子域名信息查询失败!\033[0m')
        finally:
            if (flag7 != True) and (times >= 1):
                self.getCrtDomain()
            else:
                times = tryTimes

    # virusTotal获取子域名函数
    def virusDomain(self):
        global allDict, error, times
        flag8 = False
        header = headers('www.virustotal.com')
        site = "https://www.virustotal.com/vtapi/v2/domain/report?apikey=e3ce6d7c072b832b91392dd57e8124c0a16775b80e04081c9827a74b5f79abe1&domain="
        result = []
        print("[*] 正在通过virusTotal查询子域名......")
        url = site + self.url
        try:
            r = self.get(url, header)
            try:
                datas = json.loads(r)['subdomains']
            except Exception as e:
                datas = []
            for i in datas:
                result.append(i)
            flag8 = True
            allDict['domain'] += result
            print("\033[1;34m[*] 完成virusTotal子域名获取, 共"+str(len(result))+"条数据!!\033[0m")
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'virusTotal获取子域名信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] virusTotal获取子域名信息查询失败!\033[0m')
        finally:
            if (flag8 != True) and (times >= 1):
                self.virusDomain()
            else:
                times = tryTimes

    # chaziyu.com获取子域名函数
    def Chaziyu(self):
        global allDict, error, times
        flag9 = False
        header = headers('chaziyu.com')
        site = "https://chaziyu.com/"
        result = []
        print("[*] 正在通过chaziyu.com收集子域名......")
        url = site + self.subdomain + '/'
        try:
            r = requests.get(url=url, proxies=proxies, headers=header)
            r1 = re.findall('target="_blank">(.*)</a>', r.text)
            for i in r1:
                if self.subdomain in i:
                    result.append(i)
            flag9 = True
            result1 = list(set(result))
            allDict['domain'] += result1
            print("\033[1;34m[*] 完成chaziyu.com子域名获取, 共"+str(len(result1))+"条数据!!\033[0m")
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'chaziyu.com获取子域名信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] chaziyu.com获取子域名信息查询失败!\033[0m')
        finally:
            if (flag9 != True) and (times >= 1):
                self.Chaziyu()
            else:
                times = tryTimes

    # GoogleHacking获取子域名
    def googleHack(self):
        global allDict, error, times
        flag10 = False
        header = headers('www.google-fix.com')
        result = []
        site = 'https://www.google-fix.com/search?hl=zh-CN&gbv=2&q=site:'+self.url
        print('[*] 正在通过GoogleHack收集url路径......')
        try:
            r = self.get(site, header)
            num0 = re.findall('id=\"result-stats\"\>(.*?)\<', r)  #获取一共有多少条
            if num0 != []:
                num1 = re.findall(' (.*?) ', num0[0])[0]
                if ',' in num1:
                    num1 = int(num1.replace(',', ''))  # 4,306 ==> 4306
                print("\033[1;36m[*] Google共搜索到"+str(num1)+"条数据!!\033[0m")
                if int(num1) > num2google:  # 避免几千条数据的长时间爬取
                    num1 = num2google
                for i in range((int(num1)//10)+1):
                    site1 = 'https://www.google-fix.com/search?hl=zh-CN&gbv=2&q=site:'+self.url+'&start={0}'.format(i*10)
                    r = self.get(site1, header)
                    soup = bs(r, 'lxml')
                    data = soup.find_all(name='a')
                    for i in data:
                        r1 = re.findall('href=\"(.*?)\"', str(i))
                        for j in r1:
                            if (self.url+'/' in j) and ('.google' not in j): #当前域名的提取目录
                                print("\033[1;36m[*] 从Google中成功提取地址："+str(j)+"\033[0m")
                                result.append(j)
            flag10 = True
            result1 = list(set(result))  #去重
            print("\033[1;34m[*] 完成GoogleHack获取url路径, 共"+str(len(result1))+"条数据!!\033[0m")
            initURLPATH = allDict['urlPATH']
            count = 0
            for d in result1:
                count += 1
                if d not in initURLPATH:
                    print('[*] 对google搜索到第{0}条路径 {1} 再次进行js爬取......'.format(count, d))
                    request(d).jsFinder()
                else:
                    print('\033[1;35m[-] 第{0}条网址 {1} 已经爬取过, 将执行跳过!\033[0m'.format(count, d))
            allDict['urlPATH'] += result1
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'GoogleHack获取url路径信息失败!'+'-->'+str(e))
            print('\033[1;31m[-] GoogleHack获取url路径信息查询失败!\033[0m')
        finally:
            if (flag10 != True) and (times >= 1):
                self.googleHack()
            else:
                times = tryTimes

    # ip33.com的api获取网站开发端口信息
    def getPorts(self):
        global allDict, error, times
        flag11 = False
        header = {
    'Host': 'api.ip33.com',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Referer': 'http://www.ip33.com/port_scan.html',
    'Content-Length': '34',
    'Origin': 'http://www.ip33.com',
    'DNT': '1',
    'X-Forwarded-For': '8.8.8.8',
    'Connection': 'close'
        }
        site = 'http://api.ip33.com/port_scan/scan'
        result = []
        print('[*] 正在探测端口开放情况(时间稍长)......')
        class brutePorts():
            def __init__(self):
                self.url_port = 'http://api.ip33.com/port_scan/scan'
                self.header_port = {
                    'Host': 'api.ip33.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                    'Accept-Encoding': 'gzip, deflate',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Referer': 'http://www.ip33.com/port_scan.html',
                    'Content-Length': '34',
                    'Origin': 'http://www.ip33.com',
                    'DNT': '1',
                    'X-Forwarded-For': '8.8.8.8',
                    'Connection': 'close'
                }
                self.tasks = Queue()
                for i in ports:
                    data3 = {"ip": "121.5.219.229", "port": int(i), "time": 3000}
                    self.tasks.put_nowait(data3)

            def bruteMain(self):
                while not self.tasks.empty():
                    data4 = self.tasks.get_nowait()
                    self.msg()
                    try:
                        r = requests.post(url=self.url_port, headers=self.header_port, data=data4, proxies=proxies, verify=False).text
                        r1 = json.loads(r)
                        if r1['state'] == True:
                            allDict['ports'].append(str(r1['port']))
                    except Exception as e:
                        self.tasks.put_nowait(data4)

            def msg(self):
                complete = round((((21043-self.tasks.qsize())/21043)*100),2)
                msg ='\033[1;34m[+] ALL: 1224 | Thread: 500 | Schedule: '+ str(complete) + '%\033[0m'
                sys.stdout.write('\r'+str(msg))
                sys.stdout.flush()

            def bruteStart(self):
                gevent_list = []
                for j in range(500):
                    gev = gevent.spawn(self.bruteMain)
                    gevent_list.append(gev)
                gevent.joinall(gevent_list)
        try:
            brutePorts().bruteStart()
            flag11 = True
            print('\n'+"\033[1;34m[*] 完成获取端口信息, 共"+str(len(allDict['ports']))+"条数据!!\033[0m")
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'获取端口信息失败!'+'-->'+str(e))
            print('\n'+'\033[1;31m[-] ip138获取端口开放信息失败!\033[0m')
        finally:
            if (flag11 != True) and (times >= 1):
                self.getPorts()
            else:
                times = tryTimes

    # 判断是否存在CDN
    def isCDN(self):
        global allDict, error, times
        flag12 = False
        header = headers('myssl.com')
        result = []
        site = 'https://myssl.com/api/v1/tools/cdn_check?domain='
        url = site + self.url
        print('[*] 正在通过myssl.com判断网站是否存在CDN......')
        try:
            r = requests.get(url=url, headers=header, timeout=40, proxies=self.proxy, allow_redirects=allow_redirects, verify=allow_ssl_verify)
            data = json.loads(r.text)["data"]
            flag12 = True
            allDict['isCDN'] += data   #返回的形式为 [{}]
            print("\033[1;34m[*] 完成CDN查询, 共"+str(len(data))+"条数据!!\033[0m")
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'myssl.com查询CDN失败!'+'-->'+str(e))
            print('\033[1;31m[-] myssl.com查询CDN信息失败!\033[0m')
        finally:
            if (flag12 != True) and (times >= 1):
                self.isCDN()
            else:
                time = tryTimes

    # JSfinder查找js文件及提取子域名
    def jsFinder(self):
        global times
        flag13 = False
        print('[*] 正在爬取网站js文件，查找url路径及提取子域名......')
        try:
            urls = Prepare(allDict, self.url)
            flag13 = True
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'爬取网站js文件失败!'+'-->'+str(e))
            print('\033[1;31m[-] 爬取网站js文件信息失败!\033[0m')
        finally:
            if (flag13 != True) and (times >= 1):
                self.jsFinder()
            else:
                times = tryTimes

    # wafw00f侦探网站的waf
    def detectWaf(self):
        global times
        flag14 = True
        print('[*] 正在侦探网站的waf信息......')
        try:
            entrance.main(allDict, self.url)
            flag14 = True
        except Exception as e:
            times -= 1
            error.append(self.url+'-->'+'侦探网站的waf失败!'+'-->'+str(e))
            print('\033[1;31m[-] 侦探网站的waf信息失败!\033[0m')
        finally:
            if (flag14 != True) and (times >= 1):
                self.detectWaf()
            else:
                times = tryTimes


