---
title: CMD常用命令
date: 2022-11-11 09:47:10
tags: CMD
categories: windows
---

# 内网信息收集点
## Windows

**1.本机信息收集（涉及判断：我是谁？我在哪？这是哪？）**
``` C++

ipconfig /all                                                         --网卡配置
systeminfo                                                       --系统补丁信息等
echo %PROCESSOR_ARCHITECTURE%                                      --系统体系结构
wmic product get name,version                               --安装软件、版本、路径
wmic service list brief                                         --查询本机服务信息
tasklist -svc                                                          --进程查看
schtasks /query /fo list /v                                        --任务计划查询
net statistics workstation                                             --开机时间
net user                                                               --查看用户
whoami /all                                                       --SID等用户信息
net localgroup administrators                               --查看管理员组中的用户
net session                                                            --会话查看
netstat -ano                                         --网络连接以及通过端口判断服务
net share                                                                  --共享
route print                                                             --路由信息
arp -a                                                                  --arp信息
cmdkey /l                                                               --登录历史
hosts文件  Linux：/etc/hosts  Windows：c:\Windows\system32\drivers\etc\hosts
ipconfig  /displaydns                                                    --dns缓存
net view                                                                --查看共享
dir /s /b "pass" "user" "config" "username." "password."       --命令行查找敏感文件
findstr  /s /m "password" *.*              --寻找包含密码字段的文件，如数据库密码文件
net user /domain                                                      --查看域用户
net time /domain                                        --查看时间服务器（可能为DC）
net group "domain admins" /domain                                   --查看域管理员
net group "domaincontrollers" /domain                               --查看域控制器

 ```
 **2.常见默认配置文件位置**
  ``` C++
  *   Tomcat：CATALINA_HOME/conf/tomcat-users.xml；
  *   Apache：/etc/httpd/conf/httpd.conf；
  *   Nginx：/etc/nginx/nginx.conf；
  *   Wdcp：/www/wdlinux/wdcp/conf/mrpw.conf；
  *   Mysql：mysql\data\mysql\user.MYD。
  ```
 **3.SPN：服务主体名称，使用Kerberos须为服务器注册SPN，因此可以在内网中扫描SPN，快速寻找内网中注册的服务。**
  ``` C++
  setspn -T domain.com -Q */*
  ```
 **4.会话、连接收集**
``` JSON
net session     //需要管理员权限，列出或断开本地计算机和与之连接的客户端的会话
Navicat         //注册表HKEY_CURRENT_USER\SOFTWARE\PremiumSoft
xshell      //连接记录，可能回存在使用ssh key登录的主机
```
 **5.浏览器下载记录、书签、浏览历史以及浏览器保存的密码等**

github：(https://github.com/djhohnstein/SharpChromium)   //cookie，passwd，history查看

 **6.WIFI密码**
 ``` 
for /f  "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles')  do  @echo %j | findstr -i -v echo |  netsh wlan show profiles %j key=clear
 ```
**7.任务计划（有些任务执行时需要将用户名和密码一起附上）、远程桌面连接记录等**
**Linux（CentOS 7）**
**1.系统版本信息**
 ``` 
uname -a
hostnamectl
 ```
**2.系统环境变量**
```
cat /etc/profile 
cat /etc/bashrc 
cat .bash_profile
cat .bashrc 
cat .bash_logout 
env 
set
```
**3.服务、网络连接以及进程**
```
ps -aux               //进程
top
cat /etc/services
systemctl status ssh //查看某个服务是否在运行
chkconfig --list     //查看所有的服务状态
netstat -aunplt      //网络连接
arp -e
route
```
**4.查看安装程序**
```
rpm -qa
yum list installed
```
**5.常见配置、敏感文件**
```
find / -name *.conf
cat /etc/my.conf      //mysql数据库
cat /etc/httpd/conf/httpd.conf  //apache
tomcat-users.xml       //tomcat
/etc/samba/smb.conf    //samba
cat /etc/resolv.conf   //DNS域名解析
cat /etc/sysconfig/network
cat /etc/hosts
cat /var/apache2/config.inc 
cat /var/lib/mysql/mysql/user.MYD 
cat /root/anaconda-ks.cfg
/etc/sysconfig/iptables  //iptables规则
```
**6.查看任务计划**
```
crontab -l         //查看任务计划,有部分恶意任务计划需要crontab -e 编辑才能看到
查看anacron异步定时任务：cat/etc/anacrontab
cat /var/log/cron    查看任务计划日志
cat /etc/crontab
cat /etc/cron.d/
cat /etc/cron.daily/
cat /etc/cron.hourly/
cat /etc/cron.weekly/
cat /etc/cron.monthly/
cat /var/spool/cron/
service cron status  #通过任务计划执行的服务
```
**7.可能有哪些纯文本用户名和密码**
```
grep -i user [filename] 
grep -i pass [filename] 
grep -C 5 "password" [filename] 
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password" # Joomla
```
**8.用户信息**
```
cat /etc/passwd
cat /etc/shadow
ls /home   //家目录
last   //登录成功用户
w
cat /etc/sudoers
ls -alh /var/mail/
```
**9.历史记录**
```
history
cat /root/.viminfo //vim使用记录
cat .bash_history 
cat .nano_history 
cat .atftp_history 
cat .mysql_history 
cat .php_history
cat .python_history
```
**10.前端设置Chrome浏览器跨域**

首先在电脑上新建一个目录，例如：C:\MyChromeDevUserData
从快捷方式打开文件位置，找到chrome.exe文件，cmd打开命令窗口，进入...Google\Chrome\Application。然后通过命令行启动
```
chrome.exe --disable-web-security --user-data-dir=C:\MyChromeDevUserData
```