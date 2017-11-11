#!/bin/bash

# fileName: ic_safety_log_client.sh
# description: 生成隔离网关的日志服务器配置
# Note: 运行该脚本, 需开启Root权限

gen_conf_context()
{
	echo "#### ic_safety_logger config ####"
	echo ""

	echo "# Remove Rate limit"
	echo '$SystemLogRateLimitInterval 0'	
	echo ""

	echo "# A template which jgw_logger declared"
	echo '$template ic_safety_tmpl_4, "%msg:::drop-last-lf%\n"'
	echo ""

	echo "# local logging client config"
	echo 'local3.warning /var/log/ic_safety_client.log;ic_safety_tmpl_4'
	echo ""

	echo "# remote logging server config"
	echo 'local3.warning @127.0.0.1:514'
	echo ""
	
	echo "# Stop logging handle again"
	echo 'local3.warning ~'
	echo ""
}


shellName=`basename $0.sh`

# 生成文件名
#genFileName = `echo "$1.conf"`

curDate=`date +"%Y%m%d" `
curTime=`date +"%Y%m%d%H%M%s" `

#curDir=$(pwd)
curDir="/etc/rsyslog.d"
confName="ic_safety_log_client.conf"

# clear file context
cat /dev/null > ${curDir}/${confName}  

echo "Generate ic_safety_log_client begin............."
gen_conf_context > ${curDir}/${confName}
echo "Generate ic_safety_log_client end..............."

echo "Restart rsyslogd daemon........................"
service rsyslog restart

