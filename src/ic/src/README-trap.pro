
#########ic_trap操作说明 ##########
#1 root环境登录
#2 运行命令： setenforce 0 


###### 测试案例1 ######
<UNKNOWN>
UDP: [192.168.1.25]:61027->[192.168.1.100]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 2:19:51:31.91
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkUp
IF-MIB::ifIndex.8 8
IF-MIB::ifAdminStatus.8 up
IF-MIB::ifOperStatus.8 up
IF-MIB::ifDescr.8 GigabitEthernet0/0/3

# 运行命令：
root@jhu-ubuntu:/home/IC_Trap# ./ic_trap up
<ctrl + d>

###### 测试案例2 ######
<UNKNOWN>
UDP: [192.168.1.25]:61027->[192.168.1.100]:162
DISMAN-EVENT-MIB::sysUpTimeInstance 2:19:51:27.18
SNMPv2-MIB::snmpTrapOID.0 IF-MIB::linkDown
IF-MIB::ifIndex.10 10
IF-MIB::ifAdminStatus.10 up
IF-MIB::ifOperStatus.10 down
IF-MIB::ifDescr.10 GigabitEthernet0/0/5

# 运行命令：
root@jhu-ubuntu:/home/IC_Trap# ./ic_trap down
<ctrl + d>

###### 测试案例3 ######
<UNKNOWN>
UDP: [192.168.1.25]:61027->[192.168.1.21]
DISMAN-EVENT-MIB::sysUpTimeInstance 6:20:13:14.71
SNMPv2-MIB::snmpTrapOID.0 SNMPv2-SMI::enterprises.2011.5.25.207.2.2
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.2.34 "johnny"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.3.34 "192.168.1.20"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.4.34 "VTY0"

# 运行命令：
root@jhu-ubuntu:/home/IC_Trap# ./ic_trap hwUserLogin
<ctrl + d>

###### 测试案例4 ######
<UNKNOWN>
UDP: [192.168.1.25]:61027->[192.168.1.21]
DISMAN-EVENT-MIB::sysUpTimeInstance 6:20:13:14.71
SNMPv2-MIB::snmpTrapOID.0 SNMPv2-SMI::enterprises.2011.5.25.207.2.3
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.2.34 "johnny"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.3.34 "192.168.1.20"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.4.34 "VTY1"

# 运行命令：
root@jhu-ubuntu:/home/IC_Trap# ./ic_trap hwUserLoginFail
<ctrl + d>

###### 测试案例5 ######
<UNKNOWN>
UDP: [192.168.1.25]:61027->[192.168.1.21]
DISMAN-EVENT-MIB::sysUpTimeInstance 6:20:23:15.06
SNMPv2-MIB::snmpTrapOID.0 SNMPv2-SMI::enterprises.2011.5.25.207.2.4
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.2.34 "johnny"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.3.34 "192.168.1.20"
SNMPv2-SMI::enterprises.2011.5.25.207.1.2.1.1.4.34 "VTY2"

# 运行命令：
root@jhu-ubuntu:/home/IC_Trap# ./ic_trap hwUserLogout
<ctrl + d>

###### 其他 ######
华为交换机ssh登录： 
johnny/abcd123456

#### NET-SNMP version 5.7.3的配置搜索路径如下：
#1. Config search path: /usr/local/etc/snmp:/usr/local/share/snmp:/usr/local/lib/snmp:/root/.snmp
 

