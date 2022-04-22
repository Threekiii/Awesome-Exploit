# ThinkphpRCE
Thinkphp  rce扫描脚本，附带日志扫描

- 2020.06.18 更新
1. 增加使用代理池功能
2. 增加输出到文件功能
3. 去掉了一些使用syetem函数的payload和重复payload（导致IP容易被封，且必要性不是很大）
4. 优化了一些代码，多个网站的时候显示进度

- 使用方法(python3.x)
```
usage: thinkphp_rce.py [-h] [-u URL] [-f FILE] [-p PROXY] [--shell]

Thinkphp Scan

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Start scanning url -u xxx.com
  -f FILE, --file FILE  read the url from the file
  -p PROXY, --proxy PROXY
                        use HTTP/HTTPS proxy
  --shell               try to get shell
```
```
python3 thinkphp_rce.py -u http://192.168.76.248/thinkphp520/public/ 

python3 thinkphp_rce.py -h host.txt

python3 thinkphp_rce.py -u http://192.168.76.248/thinkphp520/public/ --shell //批量检测和getshell

python3 thinkphp_rce.py -u http://192.168.76.248/thinkphp520/public/ --proxy proxy.txt //使用代理池（http/https）
```
- proxy.txt 
```
127.0.0.1:8080
114.107.150.215:46213
```