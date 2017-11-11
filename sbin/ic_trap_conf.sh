#!/bin/bash

# fileName: ic_network_trap_conf.sh
# description: 生成trap配置
# Note: 
#	<1> 运行该脚本, 需开启Root权限
# 	<2> 关闭SElinux


gen_conf_context()
{

	echo '# Example configuration file for snmptrapd'
	echo '#'
	echo '# No traps are handled by default, you must edit this file!'
	echo '#'
	echo '# authCommunity   log,execute,net public'
	echo '# traphandle SNMPv2-MIB::coldStart    /usr/bin/bin/my_great_script cold'
	echo ""

	echo "##########################ic_trap_config##################################"
	echo "disableAuthorization yes"
	echo "traphandle IF-MIB::linkDown  $BASE_HOME/target/bin/ic_trap down"
	echo "traphandle IF-MIB::linkUp    $BASE_HOME/target/bin/ic_trap up"  
	echo ""
	
	echo "#### huawei switch private mib defines ####"
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.207.2.2  $BASE_HOME/target/bin/ic_trap  hwUserLogin"
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.207.2.3  $BASE_HOME/target/bin/ic_trap  hwUserLoginFail"
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.207.2.4  $BASE_HOME/target/bin/ic_trap  hwUserLogout"
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.191.3.1  $BASE_HOME/target/bin/ic_trap  hwcfgchgotify"	
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.41.1.7.1.1.8  $BASE_HOME/target/bin/ic_trap  hwIfMonitorInputRate"
	echo "traphandle SNMPv2-SMI::enterprises.2011.5.25.41.1.7.1.1.10 $BASE_HOME/target/bin/ic_trap  hwIfMonitorOutputRate"
	echo ""
}


shellName=`basename $0.sh`

# 生成文件名
#genFileName = `echo "$1.conf"`

curDate=`date +"%Y%m%d" `
curTime=`date +"%Y%m%d%H%M%s" `
#curDir=$(pwd)

confName="snmptrapd.conf"

confDir=/usr/local/etc/snmp
if [ ! -d ${confDir} ]; then 
	mkdir -p ${confDir}
fi

# clear file context
cat /dev/null > ${confDir}/${confName}  

echo "Generate $confName  begin............."
gen_conf_context > ${confDir}/${confName}
echo "Generate $confName  end..............."

#### close SElinux ####
echo "close SElinux............"
setenforce 0 
getenforce

##### restart snmptrapd #####

trappid=$(pgrep "snmptrapd")
if [[ $trappid =~ ^[1-9]+$ ]]; then
	kill -9  $trappid
fi
snmptrapd -c ${confDir}/${confName}

