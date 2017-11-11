
####### 自启动配置
#1 root环境登录
#2 在~/.bashrc中增加如下一行[项目目录以实际情况而定]：
source /home/jhu/Project/SMS_ONE/etc/ic.env 

#3 在/etc/rc.d/rc.local中添加项目环境变量和自启动脚本:
比如：
. ~/.bash_profile
sbootall

####### 加载环境变量 
#1 root环境登录
#2 cd SMS_ONE/
#3 source ./etc/IC.env 或者. ./etc/IC.env
#4 运行命令： setenforce 0 
#4 运行脚本: sh ./scripts/ic_syslog_conf.sh

####### ic_host操作说明 
#1 root环境登录
#2 运行ic_host: ./ic_host <port>


####### ic_ping操作说明 
#1 打开文件ic_hosts_ip, 配置需要ping的主机IP
#2 运行ic_ping: ./ic_ping


####### ic_safety操作说明 
#1 root环境登录
#2 运行命令： setenforce 0 
#2 运行本目录下的ic_safety_log_srv.sh
#3 重启syslog: service rsyslog restart


####### ic_network操作说明
#1 root环境登录
#2 配置要查询的交换机IP
#2 运行ic_network: ./ic_network


####### ic_trap操作说明
#1 root环境登录
#2 配置snmptrapd.conf
#3 重启snmptrapd: service snmptrapd restart

注: 虚拟机中测试，设置IP地址和交换机地址在同一网段
### 更改虚拟机IP
#1 虚拟机网络连接：桥接模式
#2 设置network disable 
#3 配置本地IP
ifconfig eth0 down
ifconfig eth0 192.168.1.21 netmask 255.255.255.0 
ifconfig eth0 up


####### ic_host_client操作说明
#1 root环境登录
#2 运行ic_host_client: ./ic_host_client <server_ip> <port>


####### ic_safety_client操作说明
#1 root权限登录
#2 运行本目录下的ic_safety_log_client.sh
#3 打开/etc/rsyslog.d/ic_safety_log_client.conf文件, 
	 修改127.0.0.1为要发生的服务器端的IP。
#4 在root权限下运行ic_safety_client程序: ./ic_safety_client


####### 安装python2.7-rpm包
### 两个包相互依赖，一起安装
rpm -ivh python27-runtime-1.1-25.el6.x86_64.rpm 
rpm -ivh python27-python-2.7.8-18.el6.x86_64.rpm python27-python-libs-2.7.8-18.el6.x86_64.rpm
mv /usr/bin/python  /usr/bin/python2.6.6
ln -s /usr/local/python27/bin/python /usr/bin/python


###### 内存泄漏检查
valgrind --leak-check=full --show-reachable=yes -v ./bin/ic_ping

####### 修改系统时间
date -s '2017/10/20 10:10:30' && clock -w

####### 其他相关记录 #######  
1. 绑定MAC地址排序    				--解决
2. 写Log的问题					
3. snmp-v3版本实现（轮询、Trap）；轮询时间可配置  
4. 网络设备采集：配置变更、密码修改？ 
5. 主机snmp的配置文件snmp.conf和snmptrap.conf可能含有密码等敏感信息,所以权限应该设置为本用户只读写的状态。
6. ping改成select模式				--多线程方式解决
7. 测试环境搭建....		       	 	--已经搭建		
8. v3模式下各种校验(3种：认证加密、认证不加密、不认证也不加密)


注：问题记录：
1. 采集到的网络设备日志的格式定义？
2. 要查询的网络设备的(交换机)相关信息的获取(IP, 设备名称, snmp配置的相关信息等等.....)
3. 采集到的ping设备日志格式的定义？
4. ping的设备的相关信息获取(IP, 设备名称等等....)

######## 
1. 端口配置接口提供。
2. 网络安全监测装置对服务器、工作站等设备操作系统的控制操作。 (参数查看/参数设置/启动基线核查/启动主动断网)
3. 网络安全设备MIB私有库。

