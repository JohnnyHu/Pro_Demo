####### ic_network操作说明 ############
#1 配置交换机(华为交换机(S5720S-28X-SI_AC为例)：
<1> 登录交换机(串口：abcd123456)
<2> 清空配置: 见《S1720&S2700&S3700&S5700&S6700&S7700&S9700_常见操作指南(pdf)》的章节 2.5-清空配置
<3> 

######## 其他说明 #####################
#sudo apt-get install libsnmp-dev
make ic_network

#3 ###############################ic_network##############################
## 查找安装的snmp安装包
rpm -qa|grep snmp

###### 启动/停止snmp服务
service snmpd start
service snmpd stop

###### 
find /usr/include/ -name *.h | xargs grep -in "snprint_variable"
find /usr/include/ -name *.h | xargs grep -in "variable_list"
find /usr/include/ -name *.h | xargs grep -in "init_snmp"
find /usr/include/ -name *.h | xargs grep -in "SNMP_MSG_GET"
find /usr/include/ -name *.h | xargs grep -in "SNMP_MSG_GETNEXT"
find /usr/include/ -name *.h | xargs grep -in "snmp_oid_compare"
find /usr/include/ -name *.h | xargs grep -in "snmp_session"

#### 测试语句
## 网络接口：.1.3.6.1.2.1.2
## 接口当前操作状态(up|down)---ifOperStatus：
snmpwalk -v 2c -c public 192.168.175.132 .1.3.6.1.2.1.2.2.1.8
snmpwalk -v 2c -c public 192.168.175.132 system.sysDescr.0
snmpwalk -v 2c -c public 192.168.175.132 interfaces.ifNumber


####  报错情况：
[root@localhost IC_Network]# ./ic_network 
No log handling enabled - turning on stderr logging
read_objid() error: Unknown Object Identifier (Sub-id not found: (top) -> system)
qvar->name[system.sysDescr.0]

[root@localhost IC_Network]# snmptranslate system
system: Unknown Object Identifier (Sub-id not found: (top) -> system)
[root@localhost IC_Network]# snmptranslate -IR system
SNMPv2-MIB::system

### Definitions of data structures, used within the library API.
./include/net-snmp/types.h
### netsnmp_session\netsnmp_pdu\netsnmp_vardata\netsnmp_variable_list......
	 
###### 
[jhu@localhost snmp_demoapp]$  snmpgetnext -v 3 -n "" -u MD5User -a MD5 -A "The Net-SNMP Demo Password" -l authNoPriv 192.168.175.132 sysName
SNMPv2-MIB::sysName.0 = STRING: localhost.localdomain
[jhu@localhost snmp_demoapp]$  	
[jhu@localhost snmp_demoapp]$  snmpgetnext -v 3 -n "" -u MD5User -a MD5 -A "The Net-SNMP Demo Password" -l authNoPriv 192.168.175.132 .1.3.6.1.2.1.2.2.1.8
IF-MIB::ifOperStatus.1 = INTEGER: up(1)

###### snmptrap//snmptrapd相关 #########
#1 启动snmptrapd, 用于接收Agent发过来的trap消息
service snmptrapd start   

#2 查看snmptrapd 选项
[root@localhost snmp]# snmptrapd -h

#3 snmptrap命令：


#####################
#1. 交换机配置trap， 步骤是？
(1) 设计一个Trap消息
配置变更
网口状态
网口 up
网口 down
网口流量超过阈值
登录成功 
退出登录
修改用户密码
MAC 地址绑定关系

########################
HUAWEI-CONFIG-MAN-MIB是用来管理设备配置的MIB，它描述整个设备的配置情况，包括外围设备，NMS可以查询配置变化日志信息和操作管理配置。

2. 主机接收Trap发送过来的数据
3. 轮询

MAC地址表的容量可以达到8K, 所有端口共享

################# 华为交换机查询 ###############
service snmpd restart

## 查询接口状态
snmpwalk -v 2c -c community001 192.168.1.1 .1.3.6.1.2.1.2.2.1.8
snmpget -v 2c -c community001 192.168.1.1 .1.3.6.1.2.1.2.2.1.8.0

### 网络接口描述
snmpwalk -v 2c -c community001 192.168.1.1 .1.3.6.1.2.1.2.2.1.2


#########################################################################################
####################################### 交换机查询实例###################################
#### 接口索引
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1 1.3.6.1.2.1.2.2.1.1
IF-MIB::ifIndex.1 = INTEGER: 1
IF-MIB::ifIndex.2 = INTEGER: 2
IF-MIB::ifIndex.3 = INTEGER: 3
IF-MIB::ifIndex.4 = INTEGER: 4

### 网络接口描述
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1 .1.3.6.1.2.1.2.2.1.2
IF-MIB::ifDescr.1 = STRING: InLoopBack0
IF-MIB::ifDescr.2 = STRING: NULL0
IF-MIB::ifDescr.3 = STRING: Console9/0/0
IF-MIB::ifDescr.4 = STRING: MEth0/0/1
IF-MIB::ifDescr.5 = STRING: Vlanif1
IF-MIB::ifDescr.6 = STRING: GigabitEthernet0/0/1
IF-MIB::ifDescr.7 = STRING: GigabitEthernet0/0/2
IF-MIB::ifDescr.8 = STRING: GigabitEthernet0/0/3

### 网络接口的数目
[jhu@localhost IC_Network]$ snmpget -v 2c -c community001 192.168.1.1 .1.3.6.1.2.1.2.1.0
IF-MIB::ifNumber.0 = INTEGER: 34

### 端口学习到的MAC地址信息
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1  1.3.6.1.2.1.17.4.3.1.1
SNMPv2-SMI::mib-2.17.4.3.1.1.0.3.45.42.78.237 = Hex-STRING: 00 03 2D 2A 4E ED 
SNMPv2-SMI::mib-2.17.4.3.1.1.112.139.205.127.233.20 = Hex-STRING: 70 8B CD 7F E9 14 

### 标识学习MAC地址的端口索引
[jhu@localhost ~]$ 
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1  1.3.6.1.2.1.17.4.3.1.2
SNMPv2-SMI::mib-2.17.4.3.1.2.0.3.45.42.78.237 = INTEGER: 12
SNMPv2-SMI::mib-2.17.4.3.1.2.112.139.205.127.233.20 = INTEGER: 1

### 标识端口的状态
[jhu@localhost ~]$ 
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1  1.3.6.1.2.1.17.4.3.1.3
SNMPv2-SMI::mib-2.17.4.3.1.3.0.3.45.42.78.237 = INTEGER: 3
SNMPv2-SMI::mib-2.17.4.3.1.3.112.139.205.127.233.20 = INTEGER: 3


#### 该节点标识设备上的端口号
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1 1.3.6.1.2.1.17.1.4.1.1
SNMPv2-SMI::mib-2.17.1.4.1.1.1 = INTEGER: 1
SNMPv2-SMI::mib-2.17.1.4.1.1.2 = INTEGER: 2
SNMPv2-SMI::mib-2.17.1.4.1.1.3 = INTEGER: 3
SNMPv2-SMI::mib-2.17.1.4.1.1.4 = INTEGER: 4


#### 该节点标识端口在端口表中的索引
[jhu@localhost ~]$ snmpwalk -v 2c -c community001 192.168.1.1 1.3.6.1.2.1.17.1.4.1.2
SNMPv2-SMI::mib-2.17.1.4.1.2.1 = INTEGER: 6
SNMPv2-SMI::mib-2.17.1.4.1.2.2 = INTEGER: 7
SNMPv2-SMI::mib-2.17.1.4.1.2.3 = INTEGER: 8
SNMPv2-SMI::mib-2.17.1.4.1.2.4 = INTEGER: 9


#######################
## switch配置信息获取格式
ip|@|version|@|community|@|user|@|sec_level|@|auth_proto|@|priv_proto|@|auth_passwd|@|priv_passwd|@|


