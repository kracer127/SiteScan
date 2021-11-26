# -*- coding:utf-8 -*-
# by:kracer

# 引入模块、包部分
import re, json, sys
import html
import dominate
from dominate.tags import *


# 对allDict的数据处理函数
def processData(allDict):
    global nowIP, historyIP, isCDN, domain, ports, pangZhan, whois, urlPATH, beiAn, framework, cms, waf, houTai, error
    nowIP = allDict['nowIP']
    if nowIP == []:
        nowIP = ['空', '空']
    else:
        nowIP = nowIP[0].split('::')
    historyIP = allDict['historyIP']
    historyIP_list = []
    if historyIP == []:
        historyIP = ['空', '空']
    isCDN = allDict['isCDN']
    if isCDN == []:
        isCDN = [{'ip': '空', 'location': '空', 'exist': '空'}]
    else:
        if len(isCDN) >= 2:
            isCDN += [{'exist': "存在CDN"}]
        else:
            isCDN += [{'exist': "不存在CDN"}]
    domain0 = allDict["domain"]
    if domain0 == []:
        domain = ['空']
    else:
        domain = list(set(domain0))   # 去重
    ports0 = allDict["ports"]
    if ports0 == []:
        ports = ['空']
    else:
        ports = list(set(ports0))
    pangZhan0 = allDict["pangZhan"]
    if pangZhan0 == []:
        pangZhan = ['空']
    else:
        pangZhan = list(set(pangZhan0))
    whois = allDict["whois"]
    if (whois == [[]]) or (whois == []):
        whois = {'空': '空'}
    else:
        whois = whois[0]
    urlPathList = []
    for urlPath in allDict["urlPATH"]:
        if '://' in urlPath:
            url0 = urlPath[urlPath.find(':')+3:]
            urlPathList.append(url0)
        else:
            urlPathList.append(urlPath)
    urlPATH = list(set(urlPathList))
    if urlPATH == []:
        urlPATH = ['空']
    beiAn = allDict["beiAn"]
    if beiAn == []:
        beiAn = ['空:空', '空:空']
    framework = allDict["framework"]
    if framework[0] == []:
        framework[0] = ['空', '空']
    cms = framework[1]
    if cms == {}:
        cms = {'空': '空'}
    waf = framework[2]
    if waf == {}:
        waf = {'waf': '没有侦测到waf'}
    houTai_list = ['admin', 'login', 'pass', 'user', 'member', 'system', 'manage', 'service', 'main']
    houTai = []
    for d in urlPATH:
        for k in houTai_list:
            if k in d:
                houTai.append(d)
    for t in houTai:
        try:
            urlPATH.remove(t)
        except Exception as e:
            continue
    error = allDict['error']


def all2HTML(url, allDict):
    processData(allDict)
    doc = dominate.document(title='webscan_report')

    with doc.head:
        link(rel='stylesheet', type="text/css", href='..\lib\\css\\bootstrap.min.css')
        meta(charset="utf-8")
        meta(name="viewport", content="width=device-width, initial-scale=1")

    with doc.body:
        body(cls="table-responsive")
        h2('探测目标：{0}'.format(url), cls="text-center text-success")  # 定义上文

        br()
        '''域名ip地址解析----allDict["nowIP"]、allDict["histotyIP"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("域名地址解析", cls="text-center text-info bg-success")
            tr(td('当前域名ip解析:', align="center"), td('{0}'.format(nowIP[0]), align="center"), td('{0}'.format(nowIP[1]), align="center"))
            for i in historyIP:
                data = i.split("::")
                if len(data) < 2:
                    data = ["空", "空"]
                tr(td('历史域名ip解析:', align="center"), td('{0}'.format(data[0]), align="center"), td('{0}'.format(data[1]), align="center"))

        br()

        '''网站是否存在CDN解析----allDict["isCDN"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("是否存在CDN", cls="text-center text-info bg-success")
            tr(td('ip', align="center"), td('location', align="center"))
            data1 = []
            for i in isCDN:
                for k, v in i.items():
                    data1.append(v)
            for j in range(0, (len(data1)-1), 2):
                tr(td('{0}'.format(data1[j]), align="center"), td('{0}'.format(data1[j+1]), align="center"))
            tr(td('{0}'.format(data1[-1]), align="center", colspan="2"))

        br()

        '''网站是子域名解析----allDict["domain"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("子域名解析", cls="text-center text-info bg-success")
            for i in domain:
                tr(td('{0}'.format(i), align="center"))

        br()

        '''网站端口开放解析----allDict["ports"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网站端口开放情况", cls="text-center text-info bg-success")
            for i in ports:
                tr(td('{0}'.format(i), align="center"))

        br()

        '''网站的旁站解析----allDict["pangZhan"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网站的旁站情况", cls="text-center text-info bg-success")
            for i in pangZhan:
                tr(td('{0}'.format(i), align="center"))

        br()

        '''根域名的whois解析----allDict["whois"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网站的whois情况", cls="text-center text-info bg-success")
            for i, k in whois.items():
                tr(td('{0}'.format(i), align="center"), td('{0}'.format(k), align="center"))

        br()

        '''网址的目录解析----allDict["urlPATH"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网址的目录解析", cls="text-center text-info bg-success")
            for h in houTai:
                tr(td('可能的后台地址: {0}'.format(h), align="center"))
            for i in urlPATH:
                tr(td('{0}'.format(i), align="center"))

        br()

        '''网站的备案解析----allDict["beiAn"]'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网站的备案信息", cls="text-center text-info bg-success")
            for i in beiAn:
                if type(i) != dict:
                    data = i.split(":")
                    tr(td('{0}'.format(data[0]), align="center"), td('{0}'.format(data[1]), align="center"))
                else:
                    for k, v in i.items():
                        tr(td('{0}'.format(k), align="center"), td('{0}'.format(v), align="center"))

        br()

        '''网站的whatweb架构信息----whatweb'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网址的架构解析", cls="text-center text-info bg-success")
            for i in framework[0]:
                tr(td('{0}'.format(i), align="center"))

        br()

        '''网站的CMS架构信息----cms'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网址的CMS解析", cls="text-center text-info bg-success")
            for k, v in cms.items():
                tr(td('{0}'.format(k), align="center"), td('{0}'.format(v), align="center"))

        br()

        '''网站的WAF信息----waf'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("网址的WAF解析", cls="text-center text-info bg-success")
            for k, v in waf.items():
                tr(td('{0}'.format(k), align="center"), td('{0}'.format(v), align="center"))

        br()

        '''侦测过程的报错信息----error'''
        with table(cls="table table-responsive table-bordered table-hover").add(tbody()):
            caption("侦测过程的错误信息", cls="text-center text-info bg-success")
            if error != []:
                for e in error:
                    tr(td('{0}'.format(e), align="center"))
            else:
                tr(td('{0}'.format("运行过程完好无报错!"), align="center"))

        br()
        br()
        br()

    with open('output/{0}_report.html'.format(url), 'w', encoding='utf-8') as f:
        f.write(doc.render())
        print("\033[1;34m[*] 检测报告位置: output/{0}_report.html!!\033[0m \n".format(url))






