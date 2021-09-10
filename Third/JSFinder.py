#!/usr/bin/env python"
# coding: utf-8
# By Threezh1
# https://threezh1.github.io/


from requests.packages import urllib3
urllib3.disable_warnings()
import requests, argparse, sys, re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import gevent
from gevent import Greenlet
from gevent.queue import Queue


tasks = Queue()


def extract_URL(JS):
	pattern_raw = r"""
	  (?:"|')                               # Start newline delimiter
	  (
	    ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
	    [^"'/]{1,}\.                        # Match a domainname (any character + dot)
	    [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
	    |
	    ((?:/|\.\./|\./)                    # Start with /,../,./
	    [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
	    [^"'><,;|()]{1,})                   # Rest of the characters can't be
	    |
	    ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
	    [a-zA-Z0-9_\-/]{1,}                 # Resource name
	    \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
	    (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
	    |
	    ([a-zA-Z0-9_\-]{1,}                 # filename
	    \.(?:php|asp|aspx|jsp|json|
	         action|html|js|txt|xml)             # . + extension
	    (?:\?[^"|']{0,}|))                  # ? mark with parameters
	  )
	  (?:"|')                               # End newline delimiter
	"""
	pattern = re.compile(pattern_raw, re.VERBOSE)
	result = re.finditer(pattern, str(JS))
	if result == None:
		return None
	js_url = []
	return [match.group().strip('"').strip("'") for match in result
		if match.group() not in js_url]

# Get the page source
def Extract_html(URL):
	header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"}
	try:
		raw = requests.get(URL, headers=header, timeout=10, verify=False)
		raw = raw.content.decode("utf-8", "ignore")
		return raw
	except:
		return None

# Handling relative URLs
def process_url(URL, re_URL):
	black_url = ["javascript:"]	# Add some keyword for filter url.
	URL_raw = urlparse(URL)
	ab_URL = URL_raw.netloc
	host_URL = URL_raw.scheme
	if re_URL[0:2] == "//":
		result = host_URL + ":" + re_URL
	elif re_URL[0:4] == "http":
		result = re_URL
	elif re_URL[0:2] != "//" and re_URL not in black_url:
		if re_URL[0:1] == "/":
			result = host_URL + "://" + ab_URL + re_URL
		else:
			if re_URL[0:1] == ".":
				if re_URL[0:2] == "..":
					result = host_URL + "://" + ab_URL + re_URL[2:]
				else:
					result = host_URL + "://" + ab_URL + re_URL[1:]
			else:
				result = host_URL + "://" + ab_URL + "/" + re_URL
	else:
		result = URL
	return result

def find_last(string,str):
	positions = []
	last_position = -1
	while True:
		position = string.find(str, last_position+1)
		if position == -1:break
		last_position = position
		positions.append(position)
	return positions

def find_robots(url1):
	header = {"Host": url1, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36"}
	robots_txt = []
	url_real = 'http://'+url1+'/robots.txt'
	try:
		r = requests.get(url=url_real, headers=header, timeout=10, verify=False).text
		if r == None:
			return robots_txt
		else:
			if 'User-agent:' in r:
				paths = re.findall('(/(.*?).*)', r)
				for path in paths:
					path_str = 'http://'+url1+path[0]
					robots_txt.append(path_str)
			return robots_txt
	except Exception as e:
		return []

def find_by_url(url):
	html_raw = Extract_html(url)
	if html_raw == None:
		tasks.put_nowait(url)
		return []
	else:
		html = BeautifulSoup(html_raw, "html.parser")
		html_scripts = html.findAll("script")
		script_array = {}
		script_temp = ""
		for html_script in html_scripts:
			script_src = html_script.get("src")
			if script_src == None:
				script_temp += html_script.get_text() + "\n"
			else:
				purl = process_url(url, script_src)
				script_array[purl] = Extract_html(purl)
		script_array[url] = script_temp
		allurls = []
		for script in script_array:
			#print(script)
			temp_urls = extract_URL(script_array[script])
			if len(temp_urls) == 0: continue
			for temp_url in temp_urls:
				allurls.append(process_url(script, temp_url))
		result = []
		for singerurl in allurls:
			url_raw = urlparse(url)
			domain = url_raw.netloc
			positions = find_last(domain, ".")
			miandomain = domain
			if len(positions) > 1:miandomain = domain[positions[-2] + 1:]
			#print(miandomain)
			suburl = urlparse(singerurl)
			subdomain = suburl.netloc
			#print(singerurl)
			if miandomain in subdomain or subdomain.strip() == "":
				if singerurl.strip() not in result:
					result.append(singerurl)
		return list(set(result))

def find_subdomain(urls, mainurl):
	subdomain = mainurl.split('.')
	if len(subdomain) == 3:
		subdomain = '.'.join(subdomain[1:])
	elif len(subdomain) == 2:
		subdomain = mainurl
	else:
		subdomain = '.'.join(subdomain[-3:])
	tempDomain_list = []
	for i in urls:
		getChar = i[0:i.find(subdomain)].split('//')[-1]
		if getChar != '':
			newDomain = getChar + subdomain
			tempDomain_list.append(newDomain)
	return tempDomain_list

def Prepare(allDict, url1):
	if not url1.startswith('http'):
		url1 = url1.split('/')[0]
		url = 'http://' + url1
	else:
		domain = url1[url1.find(':')+3:]
		subdomain = domain.split('/')[0]
		url = url1
		url1 = subdomain   # url = 'http://'+url1
	html_raw = Extract_html(url)
	if (html_raw != None) and (url not in allDict['urlPATH']):
		html = BeautifulSoup(html_raw, "html.parser")
		html_as = html.findAll("a")
		links = find_robots(url1)
		for html_a in html_as:
			src = html_a.get("href")
			if src == "" or src == None: continue
			link = process_url(url, src)
			if link not in links:
				links.append(link)
		new_links = []
		for j in links:
			if url1 in j:
				new_links.append(j.strip('\r'))
		print("\033[1;36m[+] 当前网址一共找到" + str(len(new_links)) + "条links!\033[0m")
		'''多协程进行爬取'''
		gevent_list = []
		for k in new_links:
			tasks.put_nowait(k)
		for t in range(100):
			gev = gevent.spawn(find_by_url_deep, allDict, new_links, url1)
			gevent_list.append(gev)
		gevent.joinall(gevent_list)
		print("\033[1;34m[*] 完成当前网址的所有js文件信息提取!!\033[0m")
	else:
		print('\033[1;35m[-] 当前网址不可访问，执行跳过!\033[0m')

def find_by_url_deep(allDict, new_links, url1):
	while not tasks.empty():
		link = tasks.get_nowait()
		if (link not in allDict['urlPATH']):
			temp_urls = find_by_url(link)
			print("\033[1;36m[+] 在探测URL " + link +" 中找到" + str(len(temp_urls)) + "条数据!\033[0m")
		else:
			temp_urls = []
		if temp_urls != []:
			for temp_url in temp_urls:
				if (temp_url.strip('\r') not in new_links) and (url1 in temp_url):
					new_links.append(temp_url)
					tasks.put_nowait(temp_url)
	giveresult(allDict, new_links, url1)

def giveresult(allDict, urls, domian):
	if urls == None:
		allDict['urlPATH'] += []
	domain_list = []
	for url in urls:
		if domian in url:
			allDict['urlPATH'].append(url)
			domain_list.append(url)
	subdomains = find_subdomain(domain_list, domian)
	if subdomains == []:
		allDict['domain'] += []
	else:
		allDict['domain'] += subdomains


