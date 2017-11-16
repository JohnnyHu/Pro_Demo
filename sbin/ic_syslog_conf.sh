#!/bin/bash

# fileName: ic_syslog_conf.sh
# description: 生成安全防护设备的日志服务器配置
# Note: 
#	<1> 运行该脚本, 需开启Root权限
# 	<2> rsyslog运行子程序(开启omprog)需关闭SElinux
# Modify:
#  2017-11-16 修改接收到信息时的过滤条件，默认接收所有local过来的信息

gen_conf_context()
{

	echo "#### Local ic_running_logs config ####"
	echo ""

	echo "# A template which ic_running_logger declared"
	echo '$template ic_running_tmpl, "%TIMESTAMP:1:10:date-rfc3339% %TIMESTAMP:12:19:date-rfc3339%.%TIMESTAMP:::date-subseconds% %HOSTNAME% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n"'

	echo "# A template which log file save name"
	#echo '$template RemoteJGWLogs, "/var/log/%HOSTNAME%/%PROGRAMNAME%.log"'
	echo '$template ic_running_logs, "/var/log/ic_running.log"'
	echo 'local0.* ?ic_running_logs;ic_running_tmpl'

	echo "# Stop logging handle again"
	echo 'local0.* ~'
	echo ""


	echo "#### Remote ic_safety_logs config ####"
	echo ""
	
	echo "# Provides UDP syslog reception"
	echo '$ModLoad imudp'
	echo '$UDPServerRun 514'	
	echo ""

	echo "# A template which ic_safety_logger declared"
	echo '$template ic_safety_tmpl_2, "%msg:::drop-last-lf%\n"'
	echo ""

	echo "# A template which log file save name"
	echo '$template Remote_ICS_Logs, "/var/log/ic_safety_server.log"'
	#echo 'local3.* ?Remote_ICS_Logs;ic_safety_tmpl_2'
	#echo '*.* ?Remote_ICS_Logs;ic_safety_tmpl_2'
	echo ':syslogfacility-text, startswith, "local" ?Remote_ICS_Logs;ic_safety_tmpl_2'
	echo ""

	echo "# Provides output logs to a specified program"
	echo '$ModLoad  omprog'
	echo -n '$ActionOMProgBinary ' 
	echo "$BASE_HOME/target/bin/ic_safety" 
	#echo 'local3.*  :omprog:;ic_safety_tmpl_2'
	#echo '*.*  :omprog:;ic_safety_tmpl_2'
	echo ':syslogfacility-text, startswith, "local" :omprog:;ic_safety_tmpl_2'
	echo ""

	echo "# Stop logging handle again"
	#echo 'local3.* ~'
	echo ':syslogfacility-text, startswith, "local" ~'
	echo ""
}


shellName=`basename $0.sh`

# 生成文件名
#genFileName = `echo "$1.conf"`

curDate=`date +"%Y%m%d" `
curTime=`date +"%Y%m%d%H%M%s" `

#curDir=$(pwd)
curDir="/etc/rsyslog.d"
confName="ic_syslog_opr.conf"

# clear file context
cat /dev/null > ${curDir}/${confName}  

echo "generate ic_syslog conf begin............."
gen_conf_context > ${curDir}/${confName}
echo "generate ic_syslog conf end..............."

echo "close SElinux............"
setenforce 0 
getenforce

echo "restart rsyslogd daemon..................."
service rsyslog restart

