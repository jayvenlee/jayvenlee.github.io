---
title: NMAP安装及使用
date: 2022-12-22 14:05:47
tags: 网络安全
categories: windows
---

# 【工具-NMAP】主机渗透神器：NMAP （功能介绍，安装，使用，参数完整翻译）

**1.nmap 介绍**

Nmap（网络映射器）是由 Gordon Lyon设计，用来探测计算机网络上的主机和服务的一种 安全扫描器。为了绘制网络拓扑图，Nmap的发送特制的数据包到目标主机，然后对返回数据包进行分析。Nmap是一款枚举和测试网络的强大工具。

Nmap 特色用途： 
```
主机探测：探测网络上的主机，例如列出响应TCP和ICMP请求、icmp请求、开放特别端口的主机
端口扫描：探测目标主机所开放的端口
版本检测：探测目标主机的网络服务，判断其服务名称及版本号
系统检测：探测目标主机的操作系统及网络设备的硬件特性
支持探测脚本的编写：使用Nmap的脚本引擎（NSE）和Lua编程语言
```
**2.nmap 安装**

nmap可以到 (http://nmap.org/download.html) 下载最新版本

![nmap安装](https://img-blog.csdnimg.cn/20191012153929160.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70 "nmap")
Nmap 安装:根据提示向导，下一步、下一步进行安装，so easy！。

进入命令提示符（cmd），输入nmap，可以看到nmap的帮助信息，说明安装成功。

![nmap安装](https://img-blog.csdnimg.cn/20191012154607859.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70 "nmap")

**3.nmap 命令操作**

写在前方的技巧：

``` cmd
-S <源地址> 指定源地址，为了不被发现真实IP，扫描IP欺骗！
```
***3.1 Nmap 简单扫描***

Nmap 默认发送一个arp的ping数据包，来探测目标主机在1-10000范围内所开放的端口。

命令语法：
``` cmd
nmap <target ip address>
```
解释：Target ip address 为你目标主机的ip地址

例子：

![](https://img-blog.csdnimg.cn/20191012155334998.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70)

***3.2 Nmap 详细输出扫描结果***
命令语法：
``` cmd
nmap -vv <target ip address>
```
解释：-vv 参数设置对结果的详细输出。

例子：

![](https://img-blog.csdnimg.cn/2019101216013385.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70)

***3.3 Nmap 指定端口扫描***
nmap 默认扫描目标1-10000范围内的端口号。我们则可以通过参数-p 来设置我们将要扫描的端口号。

命令语法：

``` cmd
nmap -p(range) <target IP> 
nmap -p(range,port2,port3,...) <target ip> 
```
解释：（rangge）为要扫描的端口（范围），端口大小不能超过65535，Target ip  为目标ip地址

例子：扫描目标主机8000-8080和443端口：

![](https://img-blog.csdnimg.cn/20191012160631944.png)

***3.4 Nmap ping 扫描***
nmap 可以利用类似window/linux 系统下的ping方式进行扫描。

命令语法：

``` cmd
nmap -sP <target ip>
```
解释：sP 设置扫描方式为ping扫描

例子：感觉没啥用
![](https://img-blog.csdnimg.cn/20191012161057547.png)

***3.5 Nmap 路由跟踪***
路由器追踪功能，能够帮网络管理员了解网络通行情况，同时也是网络管理人员很好的辅助工具！通过路由器追踪可以轻松的查处从我们电脑所在地到目标地之间所经常的网络节点，并可以看到通过各个节点所花费的时间

命令语法:

``` cmd
nmap --traceroute <target ip>
```
例子：

![](https://img-blog.csdnimg.cn/20191012161932290.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70)

***3.6 Nmap 设置扫描一个网段下的ip***
命令语法：

```cmd
nmap -sP <network address></CIDR> 
nmap -sP <network address>-END
```
解释：CIDR 为你设置的子网掩码(/24 , /16 ,/8 等)，或者192.168.0.1-255

例子：24代表24位为子网掩码，即前三段不变，尾号变，相当于0-255
![](https://img-blog.csdnimg.cn/20191012181954776.png)
![](https://img-blog.csdnimg.cn/20191012174121341.png)

***3.7 Nmap 操作系统类型的探测***
nmap 通过目标开放的端口来探测主机所运行的操作系统类型。这是信息收集中很重要的一步，它可以帮助你找到特定操作系统上的含有漏洞的的服务。

命令语法：
```cmd
nmap -O <target ip>
```
例子：拿IPhone手机试试效果
![](https://img-blog.csdnimg.cn/20191012171314513.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70)

***3.8 Nmap 全功能扫描***
包含了1-10000的端口ping扫描，操作系统扫描，脚本扫描，路由跟踪，服务探测。

命令语法：
```cmd
nmap -A <target ip> 
```
例子：
![](https://img-blog.csdnimg.cn/20191012173711319.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxY2hhb3phaQ==,size_16,color_FFFFFF,t_70)

***3.9 Nmap 命令混合式扫描***
就是以上多种命令组合，没啥好多的，要啥功能自己加，如：nmap -vv -p1-1000 -O <target ip>

***3.10 Nmap 过滤结果技巧***
扫描特定端口，把开放该端口的主机IP，写入到指定文件里
```cmd
nmap -vv -n –sS -sU -p22 192.168.1.0/24  | grep "Discovered open port" | awk {'print $6'} | awk -F/ {'print $1'} > ./22-output.txt 
nmap -vv -n –sS -sU -p22 -iL iplist.txt  | grep "Discovered open port" | awk {'print $6'} | awk -F/ {'print $1'} > ./22-output.txt   
```
grep，awk都是linux指令，windows下咋办呢？见：[【工具-GnuWin】windows上使用linux指令](https://blog.csdn.net/qqchaozai/article/details/103165469)
```cmd
nmap -vv -n -sS -sU -p22 192.168.27.0/24  | C:\GnuWin\GnuWin32\bin\grep.exe "Discovered open port" | C:\GnuWin\gawk-3.1.6-1-bin\bin\awk.exe {"print $6"} | C:\GnuWin\gawk-3.1.6-1-bin\bin\awk.exe -F/ {"print $1"} > E:\桌面\hack\workspace\22-output.txt
```
还是该咋用咋用，效果一样的好。

**4 附录**
***4.1 扫描结果说明***
NMap的6种端口状态
```
open(开放的)

应用程序正在该端口接收TCP 连接或者UDP报文。发现这一点常常是端口扫描 的主要目标。安全意识强的人们知道每个开放的端口 都是攻击的入口。攻击者或者入侵测试者想要发现开放的端口。 而管理员则试图关闭它们或者用防火墙保护它们以免妨碍了合法用户。 非安全扫描可能对开放的端口也感兴趣，因为它们显示了网络上那些服务可供使用。

closed(关闭的)

关闭的端口对于Nmap也是可访问的(它接受Nmap的探测报文并作出响应)， 但没有应用程序在其上监听。 它们可以显示该IP地址上(主机发现，或者ping扫描)的主机正在运行up 也对部分操作系统探测有所帮助。 因为关闭的关口是可访问的，也许过会儿值得再扫描一下，可能一些又开放了。 系统管理员可能会考虑用防火墙封锁这样的端口。 那样他们就会被显示为被过滤的状态，下面讨论。

filtered(被过滤的)

由于包过滤阻止探测报文到达端口， Nmap无法确定该端口是否开放。过滤可能来自专业的防火墙设备，路由器规则 或者主机上的软件防火墙。这样的端口让攻击者感觉很挫折，因为它们几乎不提供 任何信息。有时候它们响应ICMP错误消息如类型3代码13 (无法到达目标: 通信被管理员禁止)，但更普遍的是过滤器只是丢弃探测帧， 不做任何响应。 这迫使Nmap重试若干次以访万一探测包是由于网络阻塞丢弃的。 这使得扫描速度明显变慢。

unfiltered(未被过滤的)

未被过滤状态意味着端口可访问，但Nmap不能确定它是开放还是关闭。 只有用于映射防火墙规则集的ACK扫描才会把端口分类到这种状态。 用其它类型的扫描如窗口扫描，SYN扫描，或者FIN扫描来扫描未被过滤的端口可以帮助确定 端口是否开放。

open|filtered(开放或者被过滤的)

当无法确定端口是开放还是被过滤的，Nmap就把该端口划分成 这种状态。开放的端口不响应就是一个例子。没有响应也可能意味着报文过滤器丢弃 了探测报文或者它引发的任何响应。因此Nmap无法确定该端口是开放的还是被过滤的。 UDP，IP协议， FIN，Null，和Xmas扫描可能把端口归入此类。

closed|filtered(关闭或者被过滤的)

该状态用于Nmap不能确定端口是关闭的还是被过滤的。 它只可能出现在IPID Idle扫描中
```

***4.2 Nmap -h 完整翻译***
使用方法: nmap [扫描类型(s)] [选项] {目标说明}

目标说明:
```
通过主机名称, IP 地址, 网段, 等等.

协议: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254

-iL <inputfilename>: 输入 主机或者网段

-iR <主机数>:随机选择目标

–exclude <主机1[,主机2][,主机3],…>: 排除的IP或者网段

–excludefile <exclude_file>: 从文件中排除
```
主机发现:
```
-sL: List Scan – 简单的列出目标进行扫描

-sn: Ping Scan – 禁用端口扫描

-Pn: Treat all hosts as online — 不使用主机发现

-PS/PA/PU/PY[portlist]: 通过TCP SYN/ACK, UDP or SCTP 等协议发现指定端口

-PE/PP/PM: 使用ICMP协议响应, 时间戳, 和子网掩码 请求 发现 探测

-PO[protocol list]: 使用ip协议

-n/-R: Never do DNS resolution/Always resolve [默认选项]

–dns-servers <serv1[,serv2],…>: 自动以DNS

–system-dns: 使用系统DNS

–traceroute: 跟踪每个主机的路径
```
扫描技术:
```
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon 等协议扫描

-sU: UDP 扫描

-sN/sF/sX: 空的TCP, FIN, 和 Xmas 扫描

–scanflags <flags>:自定义tcp扫描

-sI <zombie host[:probeport]>: 空间扫描

-sY/sZ: SCTP初始化 或者 cookie-echo扫描

-sO: IP协议扫描

-b <FTP relay host>: FTP 反弹扫描
```
规范端口和扫描序列:
```
-p <port ranges>: 只扫描指定端口

使用规范: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9

–exclude-ports <port ranges>: 排除指定端口扫描

-F: 快速扫描- 扫描常用端口

-r: 连续端口扫描 – 不随机

–top-ports <number>: 扫描 <number> 常见的端口

–port-ratio <ratio>: Scan ports more common than <ratio>
```
服务和版本检测:
```
-sV: 探索开放的端口 以确定服务和版本号

–version-intensity <level>:设置从0-9所有的探针

–version-light:最有可能的漏洞探针(intensity 2)

–version-all: 尝试每一个漏洞探针 (intensity 9)

–version-trace: 显示详细的版本扫描活动 (调试)
```
扫描脚本的使用:
```
-sC: 默认脚本进行探测

–script=<Lua scripts>: <Lua scripts> 用 逗号分隔的列表, 脚本目录or 脚本类别

–script-args=<n1=v1,[n2=v2,...]>: 为脚本提供参数

–script-args-file=filename:在一个文件中提供NSE脚本（自定义脚本）

–script-trace: 显示所有发送和接收的数据

–script-updatedb: 更新脚本数据库

–script-help=<Lua scripts>: 显示脚本帮助

<Lua scripts> 是一个逗号分隔的脚本文件列表或脚本类.
```
操作系统识别:
```
-O: 使用操作系统探测

–osscan-limit: Limit OS detection to promising targets

–osscan-guess: Guess OS more aggressively
```
定时和性能:
```
用于定时任务 <时间> 在多少秒, 或者追加’毫秒’ ,

‘秒’ , ‘分钟’ , 或者 ‘小时’去设置 (e.g. 30m).

-T<0-5>: 设置定时模板 (更方便)

–min-hostgroup/max-hostgroup <size>: 并行扫描的最大值和最小值

–min-parallelism/max-parallelism <numprobes>: 并行扫描

–min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: 指定扫描结束时间

–max-retries <tries>: Caps number of port scan probe retransmissions.

–host-timeout <time>: Give up on target after this long

–scan-delay/–max-scan-delay <time>: 调整每次扫描的延迟

–min-rate <number>: 发送的数据包不低于《数值》

–max-rate <number>: 发送的数据包不超过《数值》
```
防火墙/ IDS逃避和欺骗：
```
-f; –mtu <val>: 碎片包 (可以选择 w/given MTU)

-D <decoy1,decoy2[,ME],…>: Cloak a scan with decoys

-S <IP_Address>: 源地址欺骗

-e <iface>: 使用指定的接口

-g/–source-port <portnum>:使用给定的端口号

–proxies <url1,[url2],…>: Relay 通过使用 HTTP/SOCKS4 代理

–data <hex string>:附加一个自定义的有效载荷发送数据包

–data-string <string>: 添加一个自定义的ASCII字符串发送的数据包

–data-length <num>: 附加随机数据发送数据包

–ip-options <options>: 用指定的IP选项发送数据包

–ttl <val>: 设置ip到达目标的时间

–spoof-mac <mac address/prefix/vendor name>:欺骗本地MAC地址

–badsum:发送用来效验的伪造数据包 TCP/UDP/SCTP
```
输出:
```
-oN/-oX/-oS/-oG <file>:输出正常的扫描, XML格式, s|<rIpt kIddi3,和 Grepable 格式, respectively,或者指定的文件名

-oA <basename>: 一次输出三种主要格式

-v: 增加详细程度 (使用 -vv 显示更详细)

-d: 提高测试的详细程度 (使用 -dd参数更详细)

–reason: 显示端口处于某个特定状态的原因

–open: 只显示开放的端口

–packet-trace: 显示发送和接收的所有数据包

–iflist:打印主机接口和路由

–append-output: 附加到指定的输出文件

–resume <filename>: 回复终止的扫描

–stylesheet <path/URL>: XSL样式表转换XML输出HTML

–webxml: 从Nmap参考样式。或者更便携的XML

–no-stylesheet: Prevent associating of XSL stylesheet w/XML output
```
杂项:
```
-6: 启用ipv6扫描

-A: 使操作系统版本检测，检测，脚本扫描和跟踪

–datadir <dirname>: 指定自定义可以使用的数据文件位置

–send-eth/–send-ip:发送使用原始以太网帧或IP数据包

–privileged: 假设用户是最高权限

–unprivileged: 假设用户缺乏原始套接字特权

-V: 打印当前版本

-h: 显示英文帮助文档.
```
**5 Nmap的常用命令**

1. nmap -sT 192.168.96.4  //TCP连接扫描，不安全，慢

2. nmap -sS 192.168.96.4  //SYN扫描,使用最频繁，安全，快

3. nmap -Pn 192.168.96.4  //目标机禁用ping，绕过ping扫描

4. nmap -sU 192.168.96.4  //UDP扫描,慢,可得到有价值的服务器程序

5. nmap -sI 僵尸ip 目标ip  //使用僵尸机对目标机发送数据包

6. nmap -sA 192.168.96.4  //检测哪些端口被屏蔽

7. nmap 192.168.96.4 -p <portnumber>  //对指定端口扫描

8. nmap 192.168.96.1/24 //对整个网段的主机进行扫描

9. nmap 192.168.96.4 -oX myscan.xml //对扫描结果另存在myscan.xml

10. nmap -T1~6 192.168.96.4  //设置扫描速度，一般T4足够。

11. nmap -sV 192.168.96.4  //对端口上的服务程序版本进行扫描

12. nmap -O 192.168.96.4  //对目标主机的操作系统进行扫描

13. nmap -sC <scirptfile> 192.168.96.4  //使用脚本进行扫描，耗时长

14. nmap -A 192.168.96.4  //强力扫描，耗时长

15. nmap -6 ipv6地址   //对ipv6地址的主机进行扫描

16. nmap -f 192.168.96.4  //使用小数据包发送，避免被识别出

17. nmap –mtu <size> 192.168.96.4 //发送的包大小,最大传输单元必须是8的整数

18. nmap -D <假ip> 192.168.96.4 //发送参杂着假ip的数据包检测

19. nmap --source-port <portnumber> //针对防火墙只允许的源端口

20. nmap –data-length: <length> 192.168.96.4 //改变发生数据包的默认的长度，避免被识别出来是nmap发送的。

21. nmap -v 192.168.96.4  //显示冗余信息(扫描细节)

22. nmap -sn 192.168.96.4  //对目标进行ping检测，不进行端口扫描（会发送四种报文确定目标是否存活,）

23. nmap -sP 192.168.96.4  //仅仅对目标进行ping检测。

24. nmap -n/-p 192.168.96.4  //-n表示不进行dns解析，-p表示要

25. nmap --system-dns 192.168.96.4  //扫描指定系统的dns服务器

26. nmap –traceroute 192.168.96.4  //追踪每个路由节点。

27. nmap -PE/PP/PM: 使用ICMP echo, timestamp, and netmask 请求包发现主机。

28. nmap -sP 192.168.96.4       //主机存活性扫描，arp直连方式。

29. nmap -iR [number]       //对随机生成number个地址进行扫描。