## web漏洞扫描小工具 Tyscan v1.0

**Tyscan** 是一款对带参数url进行漏洞测试的扫描器，目前支持对get型sql注入、XSS、URL重定向等漏洞的扫描.

**Tyscan**采用广度优先算法，对urls进行去重爬取，然后采用集合的特性，对url的参数进行去重，即参数相同或者包含于的url，只测试一次，大大减少了重复操作.


##Usage：
python tyscan.py -f urls.txt -d 2

* -f 测试的域名
* -d 递归爬取的深度

结合lijiejie的subDomainsBrute进行批量测试

* python subDomainsBrute.py domain
* awk '{print $1}' weibo.com.txt > urls.txt 
* python sqlmapapi.py -s
* python tyscan.py -f urls.txt -d 2




