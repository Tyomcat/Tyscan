#! /usr/bin/python
# -*-coding:utf-8-*-
# __author__ = 'tyomcat'

import urllib2
import urllib
import re
import urlparse
import optparse
import requests
import hashlib
import copy
import time
import sys
import json
from  BeautifulSoup import BeautifulSoup
import socket
import zlib

banner = r'''
 ______
/\__  _\
\/_/\ \/ __  __    ____    ___     __      ___
   \ \ \/\ \/\ \  /',__\  /'___\ /'__`\  /' _ `\
    \ \ \ \ \_\ \/\__, `\/\ \__//\ \L\.\_/\ \/\ \
     \ \_\/`____ \/\____/\ \____\ \__/.\_\ \_\ \_\
      \/_/`/___/> \/___/  \/____/\/__/\/_/\/_/\/_/
             /\___/
             \/__/

'''


class Crawler:
    def __init__(self, seeds):
        # 初始化当前抓取的深度
        self.current_deepth = 1
        # 使用种子初始化url队列
        self.linkQuence = linkQuence()
        if isinstance(seeds, str):
            self.linkQuence.addUnvisitedUrl(seeds)
        if isinstance(seeds, list):
            for i in seeds:
                self.linkQuence.addUnvisitedUrl(i)

    # 抓取过程主函数
    def crawling(self, seeds, crawl_deepth):
        # 循环条件：抓取深度不超过crawl_deepth
        ulist = []
        while self.current_deepth <= crawl_deepth:
            # 循环条件：待抓取的链接不空
            while not self.linkQuence.unVisitedUrlsEnmpy():
                # 队头url出队列
                visitUrl = self.linkQuence.unVisitedUrlDeQuence()
                print "\n正在爬取=> %s " % str(visitUrl)
                if visitUrl is None or visitUrl == "":
                    continue
                # 获取超链接
                links = self.getHyperLinks(visitUrl)
                if links == []:
                    continue
                else:
                    pass
                ulist = ulist + links
                print "获取超链接数:%d" % len(links)
                # 将url放入已访问的url中
                self.linkQuence.addVisitedUrl(visitUrl)
                print "已经爬取过的url数量: " + str(self.linkQuence.getVisitedUrlCount())
                print "正在爬取的深度: " + str(self.current_deepth)
            for link in links:
                self.linkQuence.addUnvisitedUrl(link)
            #print "未爬取的url数量:%d" % len(self.linkQuence.getUnvisitedUrl())
            self.current_deepth += 1
        return ulist

    # 获取源码中得超链接
    def getHyperLinks(self, url):
        urls = []
        data = self.getPageSource(url)
        if data[0] == "200":
            soup = BeautifulSoup(data[1])
            links = soup.findAll('a')
            self.url = urlparse.urlparse(url).netloc
            for link in links:
                _url = link.get('href')
                if _url is None or re.match('.(jpg|png|bmp|mp3|wma|wmv|gz|zip|rar|iso|pdf|txt|db)$', _url) or re.match(
                        '^(javascript|:;|#)', _url):
                    continue
                if re.match('^(http|https)', _url):
                    sub = urlparse.urlparse(_url).netloc
                    if self.url == sub[-len(self.url):]:
                        urls.append(_url)
                else:
                    _url = _url.replace('../', '')
                    _url = "http://" + self.url + "/" + _url
                    urls.append(_url)
                    continue
        return urls

    # 获取网页源码
    def getPageSource(self, url, timeout=100, coding=None):
        try:
            socket.setdefaulttimeout(timeout)
            req = urllib2.Request(url)
            req.add_header('User-agent', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
            response = urllib2.urlopen(req)
            page = ''
            if response.headers.get('Content-Encoding') == 'gzip':
                page = zlib.decompress(page, 16 + zlib.MAX_WBITS)
            if coding is None:
                coding = response.headers.getparam("charset")
            if coding is None:
                page = response.read()
            else:
                page = response.read()
                page = page.decode(coding).encode('utf-8')
            return ["200", page]
        except Exception, e:
            print str(e)
            return [str(e), None]


class linkQuence:
    def __init__(self):
        # 已访问的url集合
        self.visted = []
        # 待访问的url集合
        self.unVisited = []

    # 获取访问过的url队列
    def getVisitedUrl(self):
        return self.visted

    # 获取未访问的url队列
    def getUnvisitedUrl(self):
        return self.unVisited

    # 添加到访问过得url队列中
    def addVisitedUrl(self, url):
        self.visted.append(url)

    # 移除访问过得url
    def removeVisitedUrl(self, url):
        self.visted.remove(url)

    # 未访问过得url出队列
    def unVisitedUrlDeQuence(self):
        try:
            return self.unVisited.pop()
        except:
            return None

    # 保证每个url只被访问一次
    def addUnvisitedUrl(self, url):
        if url != "" and url not in self.visted and url not in self.unVisited:
            self.unVisited.insert(0, url)

    # 获得已访问的url数目
    def getVisitedUrlCount(self):
        return len(self.visted)

    # 获得未访问的url数目
    def getUnvistedUrlCount(self):
        return len(self.unVisited)

    # 判断未访问的url队列是否为空
    def unVisitedUrlsEnmpy(self):
        return len(self.unVisited) == 0


def getPageSource(url, timeout=100, coding=None):
    try:
        socket.setdefaulttimeout(timeout)
        req = urllib2.Request(url)
        req.add_header('User-agent', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)')
        response = urllib2.urlopen(req)
        page = ''
        if response.headers.get('Content-Encoding') == 'gzip':
            page = zlib.decompress(page, 16 + zlib.MAX_WBITS)
        if coding is None:
            coding = response.headers.getparam("charset")
        if coding is None:
            page = response.read()
        else:
            page = response.read()
            page = page.decode(coding).encode('utf-8')
        return ["200", page]
    except Exception, e:
        return [str(e), None]


class URLLocation:

    def __init__(self, url):
        self.url = url

    def url_values_plus(self, url, vals):
        ret = []
        qs = urlparse.urlparse(self.url).query
        _url = url.replace('?' + qs, '')
        qs_dict = dict(urlparse.parse_qsl(qs))
        for val in vals:
            for k in qs_dict.keys():
                tmp_dict = copy.deepcopy(qs_dict)
                tmp_dict[k] = val
                tmp_qs = urllib.unquote(urllib.urlencode(tmp_dict))
                ret.append(_url + "?" + tmp_qs)
        return ret

    def run(self):

        payloads = ('http://tyomcat.cnblogs.com', 'aHR0cDovL3R5b21jYXQuY25ibG9ncy5jb20=')
        urls = self.url_values_plus(self.url, payloads)
        s = urllib2.urlopen('http://tyomcat.cnblogs.com').read()
        m0 = hashlib.md5()
        m0.update(s)
        s0 = m0.hexdigest()
        for _url in urls:
            try:
                print "[+] 正在测试url跳转漏洞：%s" % str(_url)
                result = urllib2.urlopen(_url).read()
            except:
                continue
            s1 = hashlib.md5()
            s1.update(result)
            if s1.hexdigest() == s0:
                print "[*]存在URL跳转漏洞: %s" % url


class Sqli(object):
    def __init__(self, server='', target='', data='', referer='', cookie=''):
        super(Sqli, self).__init__()
        self.server = server
        if self.server[-1] != '/':
            self.server = self.server + '/'
        self.target = target
        self.taskid = ''
        self.engineid = ''
        self.status = ''
        self.data = data
        self.referer = referer
        self.cookie = cookie
        self.start_time = time.time()

    # 新建任务

    def task_new(self):
        self.taskid = json.loads(requests.get(self.server + 'task/new').text)['taskid']
        print 'Created new task: ' + self.taskid
        if len(self.taskid) > 0:
            return True
        else:
            return False

    # 删除任务
    def task_delete(self):
        if json.loads(requests.get(self.server + 'task/' + self.taskid + '/delete').text)['success']:
            print '[%s] Deleted task' % (self.taskid)
            return True
        else:
            return False

    # 开始扫描

    def scan_start(self):
        headers = {'Content-Type': 'application/json'}
        payload = {'url': self.target}
        url = self.server + 'scan/' + self.taskid + '/start'
        # http://127.0.0.1:8775/scan/taskid/start
        t = json.loads(requests.post(url, data=json.dumps(payload), headers=headers).text)
        self.engineid = t['engineid']
        if len(str(self.engineid)) > 0 and t['success']:
            print 'Start scan!'
            return True
        else:
            return False

    # 扫描状态

    def scan_status(self):
        self.status = json.loads(requests.get(self.server + 'scan/' + self.taskid + '/status').text)['status']
        if self.status == 'running':
            return self.status
        elif self.status == 'terminated':
            return self.status
        else:
            return 'Error'

    # 扫描任务的细节

    def scan_data(self):
        self.data = json.loads(requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
        if len(self.data) == 0:
            print '[-]没有注入! => ' + self.target
        else:
            print '[+]恭喜，有注入!\t' + self.target

    # 设置扫描参数

    def set_options(self):
        headers = {'Content-Type': 'application/json'}
        option = {"options": {
            "smart": True,
        }
        }
        url = self.server + 'option/' + self.taskid + '/set'
        t = json.loads(requests.post(url, data=json.dumps(option), headers=headers).text)
        print t

    # 停止扫描任务
    def scan_stop(self):
        json.loads(requests.get(self.server + 'scan/' + self.taskid + '/stop').text)['success']

    # 杀死扫描任务进程
    def scan_kill(self):
        json.loads(requests.get(self.server + 'scan/' + self.taskid + '/kill').text)['success']

    def run(self):
        if not self.task_new():
            print "Error: Created task failed!"
            return False
        self.set_options()
        if not self.scan_start():
            print "Error: scan start failed."
            return False
        while True:
            self.scan_status()
            if self.scan_status() == 'running':
                print "[!]正在扫描"
                time.sleep(10)
            elif self.scan_status() == 'terminated':
                break
            else:
                print "unkown status"
                break
            if time.time() - self.start_time > 3000:
                error = True
                self.scan_stop()
                self.scan_kill()
                break
        self.scan_data()
        self.task_delete()
        print "[+]耗时:" + str(time.time() - self.start_time)


def xss(url):
    site = url
    findurl = urlparse.urlparse(site)
    parameters = urlparse.parse_qs(findurl.query, keep_blank_values=True)
    path = urlparse.urlparse(site).scheme + "://" + urlparse.urlparse(site).netloc + urlparse.urlparse(site).path
    paraname = []
    paravalue = []
    for para in parameters:
        for i in parameters[para]:
            paraname.append(para)
            paravalue.append(i)
    total = 0
    c = 0
    fpar = []
    fresult = []
    progress = 0
    for pn, pv in zip(paraname, paravalue):  # Scanning the parameter.
        print "[+]测试参数：" + pn
        fpar.append(str(pn))
        payloads = []
        with open("xsslist.txt", 'r') as f:
            for line in f.readlines():
                payloads.append(line.strip('\n'))
        for x in payloads:  #
            if x == "":
                progress = progress + 1
            else:
                sys.stdout.write("\r[+] %i / %s payloads injected!" % (progress, len(payloads)))
                sys.stdout.flush()
                progress = progress + 1
                enc = urllib.quote_plus(x)
                data = path + "?" + pn + "=" + pv + enc
                sourcecode = getPageSource(data)[1]
                if sourcecode == None:
                    continue
                if x in sourcecode:
                    print "[!]发现 XSS 漏洞!"
                    fresult.append("Vulnerable!")
                    c = 1
                    total = total + 1
                    progress = progress + 1
                    break
                else:
                    c = 0
        if c == 0:
            print " 参数%s没有XSS!" % pn
            fresult.append("Not Vulnerable")
            progress = progress + 1
            pass
        progress = 0


if __name__ == "__main__":
    print banner
    print '''
    author:tyomcat
    email:tyomcat@gmail.com
    '''
    parser = optparse.OptionParser('Usage:\n tyscan.py -f urls.txt -d 3')
    parser.add_option('-f', dest='urls', type='string', help='要扫描的域名')
    parser.add_option('-d', dest='depth', type='string', help='递归扫描的深度')
    (options, args) = parser.parse_args()
    tgturls = options.urls
    crawl_deepth = int(options.depth)
    if (tgturls == None) | (crawl_deepth == None):
        print parser.usage
        exit(0)
    with open(tgturls) as f:
        urls = f.readlines()
    ll = []
    for i in urls:
        if re.match('^(http|https)',i):
            i=i.strip('\n')
        else:
            i = "http://" + i.strip('\n')
        ll.append(i)
    craw = Crawler(ll)
    ulist = craw.crawling(ll, crawl_deepth)
    count = 1
    params = set()
    for i in ulist:
        i=str(i)
        if urlparse.urlparse(i).query == '':
            continue
        else:
            print "\n>>>带参数的url=> " + i
            # 进行参数去重
            values = urlparse.urlparse(i).query
            param = dict(urlparse.parse_qs(values))
            key = set(param.keys())
            if key <= params:
                continue
            else:
                params = params.union(key)
                print "\n[!]正在测试第%s个url:%s" % (count,i)
                # 进行 xss 测试
                xss(i)
                # 进行url重定向测试
                location = URLLocation(i)
                location.run()
                # 进行sql注入测试
                sql = Sqli("http://127.0.0.1:8775",i)
                sql.run()
            count += 1
