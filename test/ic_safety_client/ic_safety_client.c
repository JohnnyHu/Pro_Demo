/** @file ic_safety_Client.c **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <syslog.h>
#include <unistd.h>

#include "Utility.h"

#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

#define DEFAULT_SEND_TIME 20

int main(int argc, char **argv) 
{
	// 初始化log服务器
	openlog("safety_logger", LOG_CONS | LOG_PID, LOG_LOCAL3);
	
	// 重启syslog服务器
	system("service rsyslog restart");
	
while (1) { 
	char *ptime = Get19DateTime(GetNowDateTime());
	
	// 纵向加密装置
	syslog(LOG_ERR, "<3> %s vead01 VEAD 0 1 admin",  ptime);
	syslog(LOG_ERR, "<3> %s vead02 VEAD 0 1 jhutest",  ptime);
	syslog(LOG_ERR, "<3> %s vead03 VEAD 0 1 liutest",  ptime);
		            
	syslog(LOG_ERR, "<2> %s vead01 VEAD 0 2 shtest",  ptime);
	syslog(LOG_ERR, "<2> %s vead02 VEAD 0 2 jhutest",  ptime);
	syslog(LOG_ERR, "<2> %s vead03 VEAD 0 2 liutest",  ptime);	
	                
	syslog(LOG_ERR, "<2> %s vead01 VEAD 0 3 1",  ptime);
	syslog(LOG_ERR, "<2> %s vead01 VEAD 0 3 2",  ptime);
	syslog(LOG_ERR, "<2> %s vead02 VEAD 0 3 2",  ptime);
	syslog(LOG_ERR, "<2> %s vead03 VEAD 0 3 1",  ptime);
	syslog(LOG_ERR, "<2> %s vead03 VEAD 0 3 3",  ptime);
	                
	syslog(LOG_ERR, "<3> %s vead01 VEAD 0 4 admin",  ptime);
	syslog(LOG_ERR, "<3> %s vead02 VEAD 0 4 jhutest",  ptime);	
	syslog(LOG_ERR, "<3> %s vead03 VEAD 0 4 liutest",  ptime);	
	                
	syslog(LOG_ERR, "<3> %s vead01 VEAD 1 2 50%% cpu loadavg",  ptime);
	syslog(LOG_ERR, "<3> %s vead02 VEAD 1 2 60%% cpu loadavg",  ptime);
	syslog(LOG_ERR, "<3> %s vead03 VEAD 1 2 70%% cpu loadavg",  ptime);
	                
	syslog(LOG_ERR, "<3> %s vead01 VEAD 1 3 65%%",  ptime);
	syslog(LOG_ERR, "<3> %s vead02 VEAD 1 3 78%%",  ptime);
	syslog(LOG_ERR, "<3> %s vead03 VEAD 1 3 81%%",  ptime);	
	                
	syslog(LOG_ERR, "<2> %s vead01 VEAD 1 6 ETH0 down",  ptime);
	syslog(LOG_ERR, "<2> %s vead02 VEAD 1 6 ETH1 down",  ptime);
	syslog(LOG_ERR, "<2> %s vead03 VEAD 1 6 ETH3 down",  ptime);
	                
	syslog(LOG_ERR, "<2> %s vead01 VEAD 1 7 ETH1 up",  ptime);
	syslog(LOG_ERR, "<2> %s vead02 VEAD 1 7 ETH1 up",  ptime);	
	syslog(LOG_ERR, "<2> %s vead05 VEAD 1 7 ETH2 up",  ptime);
	                
	syslog(LOG_ERR, "<1> %s vead01 VEAD 1 8 BackDevice HeartBeat Lost",  ptime);
	syslog(LOG_ERR, "<1> %s vead02 VEAD 1 8 BackDevice HeartBeat Lost",  ptime);
	syslog(LOG_ERR, "<1> %s vead03 VEAD 1 8 BackDevice HeartBeat Lost",  ptime);	
	                
	syslog(LOG_ERR, "<3> %s vead01 VEAD 1 10 540 8300",  ptime);
	syslog(LOG_ERR, "<3> %s vead02 VEAD 1 10 550 8302",  ptime);
	syslog(LOG_ERR, "<3> %s vead01 VEAD 1 10 545 8303",  ptime);	
	                
	syslog(LOG_ERR, "<1> %s vead01 VEAD 2 1 1 10.1.1.1 10.1.1.1 RSA Decrypted Error",  ptime);
	syslog(LOG_ERR, "<1> %s vead02 VEAD 2 1 1 10.1.1.1 10.1.1.2 RSA Decrypted Error",  ptime);
	syslog(LOG_ERR, "<1> %s vead03 VEAD 2 1 1 10.1.1.1 10.1.1.3 RSA Decrypted Error",  ptime);
	                
	syslog(LOG_ERR, "<1> %s vead01 VEAD 2 7 8 192.168.2.200 5400 192.168.2.214 80",  ptime);
	syslog(LOG_ERR, "<1> %s vead02 VEAD 2 7 8 192.168.2.201 5400 192.168.3.214 80",  ptime);
	syslog(LOG_ERR, "<1> %s vead03 VEAD 2 7 8 192.168.2.202 5400 192.168.4.214 80",  ptime);
	                         
	// 防火墙                 
	syslog(LOG_ERR, "<3> %s fw01 FW 0 1 admin 10.1.1.1",  ptime);
	syslog(LOG_ERR, "<3> %s fw02 FW 0 1 jhutest 10.1.1.2",  ptime);
	syslog(LOG_ERR, "<3> %s fw03 FW 0 1 liutest 10.1.1.3",  ptime);
	                
	syslog(LOG_ERR, "<3> %s fw01 FW 0 2 admin 10.1.1.1",  ptime);
	syslog(LOG_ERR, "<3> %s fw02 FW 0 2 jhutest 10.1.1.2",  ptime);
	syslog(LOG_ERR, "<3> %s fw03 FW 0 2 liutest 10.1.1.3",  ptime);
	              
	syslog(LOG_ERR, "<2> %s fw01 FW 0 3 shtest 10.1.1.1",  ptime);
	syslog(LOG_ERR, "<2> %s fw02 FW 0 3 jhutest 10.1.1.2",  ptime);
	syslog(LOG_ERR, "<2> %s fw03 FW 0 3 liutest 10.1.1.3",  ptime);	
	                
	syslog(LOG_ERR, "<2> %s fw01 FW 0 4 admin 10.1.1.1 Rule 20 added, permit tcp packets from 10.10.10.0/24 to 20.20.20.0/24",  ptime);
	syslog(LOG_ERR, "<2> %s fw03 FW 0 4 liutest 10.1.1.3 Rule 20 added, permit tcp packets from 10.10.11.0/24 to 20.20.21.0/24",  ptime);
	syslog(LOG_ERR, "<2> %s fw02 FW 0 4 jhutest 10.1.1.2 Rule 20 added, permit tcp packets from 10.10.12.0/24 to 20.20.22.0/24",  ptime);	
	        
	syslog(LOG_ERR, "<3> %s fw01 FW 1 1 80%%",  ptime);
	syslog(LOG_ERR, "<3> %s fw02 FW 1 1 70%%",  ptime);
	syslog(LOG_ERR, "<3> %s fw03 FW 1 1 89%%",  ptime);	
	                
	syslog(LOG_ERR, "<3> %s fw01 FW 1 2 80%%",  ptime);
	syslog(LOG_ERR, "<3> %s fw02 FW 1 2 66%%",  ptime);
	syslog(LOG_ERR, "<3> %s fw03 FW 1 2 73%%",  ptime);	
	            
	syslog(LOG_ERR, "<1> %s fw01 FW 1 3 Power_Supply_Error",  ptime);
	syslog(LOG_ERR, "<1> %s fw02 FW 1 3 Power_Supply_Error",  ptime);
	syslog(LOG_ERR, "<1> %s fw03 FW 1 3 Power_Supply_Error",  ptime);	
	      
	syslog(LOG_ERR, "<1> %s fw01 FW 1 4 Fan_Error",  ptime);
	syslog(LOG_ERR, "<1> %s fw02 FW 1 4 Fan_Error",  ptime);
	syslog(LOG_ERR, "<1> %s fw03 FW 1 4 Fan_Error",  ptime);	
	
	syslog(LOG_ERR, "<1> %s fw01 FW 1 5 Temperature_Over_Limit 65°C",  ptime);
	syslog(LOG_ERR, "<1> %s fw02 FW 1 5 Temperature_Over_Limit 75°C",  ptime);
	syslog(LOG_ERR, "<1> %s fw03 FW 1 5 Temperature_Over_Limit 85°C",  ptime);	

	syslog(LOG_ERR, "<2> %s fw01 FW 1 7 Eth1 Link down",  ptime);
	syslog(LOG_ERR, "<2> %s fw02 FW 1 7 Eth2 Link down",  ptime);
	syslog(LOG_ERR, "<2> %s fw03 FW 1 7 Eth3 Link down",  ptime);

	syslog(LOG_ERR, "<2> %s fw01 FW 1 8 Eth1 Link up",  ptime);
	syslog(LOG_ERR, "<2> %s fw02 FW 1 8 Eth2 Link up",  ptime);
	syslog(LOG_ERR, "<2> %s fw03 FW 1 8 Eth3 Link up",  ptime);	
	
	syslog(LOG_ERR, "<1> %s fw01 FW 3 1 TCP 10.1.1.1 4099 10.2.2.2 80",  ptime);
	syslog(LOG_ERR, "<1> %s fw02 FW 3 1 TCP 10.1.1.2 4099 10.2.2.3 80",  ptime);
	syslog(LOG_ERR, "<1> %s fw03 FW 3 1 TCP 10.1.1.3 4099 10.2.2.4 80",  ptime);	

	syslog(LOG_ERR, "<1> %s fw01 FW 3 2 TCP ddos-attack 192.168.2.200 8081 192.168.2.214 80",  ptime);
	syslog(LOG_ERR, "<1> %s fw02 FW 3 2 TCP ddos-attack 192.168.2.201 8081 192.168.2.215 80",  ptime);
	syslog(LOG_ERR, "<1> %s fw03 FW 3 2 TCP ddos-attack 192.168.2.202 8081 192.168.2.216 80",  ptime);
                         
	// 纵向加密装置     
	syslog(LOG_ERR, "<3> %s gddev001 FID 0 3 85%%",  ptime);
	syslog(LOG_ERR, "<3> %s gddev002 FID 0 3 88%%",  ptime);
	syslog(LOG_ERR, "<3> %s gddev003 FID 0 3 82%%",  ptime);
	                
	syslog(LOG_ERR, "<3> %s gddev001 FID 0 4 75%%",  ptime);
	syslog(LOG_ERR, "<3> %s gddev002 FID 0 4 85%%",  ptime);
	syslog(LOG_ERR, "<3> %s gddev003 FID 0 4 95%%",  ptime);

	syslog(LOG_ERR, "<3> %s gddev001 FID 0 5 root system_login",  ptime);
	syslog(LOG_ERR, "<3> %s gddev002 FID 0 5 jhutest system_login",  ptime);
	syslog(LOG_ERR, "<3> %s gddev003 FID 0 5 liutest system_login",  ptime);
	       
	syslog(LOG_ERR, "<2> %s gddev001 FID 0 6 policy change",  ptime);
	syslog(LOG_ERR, "<2> %s gddev002 FID 0 6 policy change",  ptime);
	syslog(LOG_ERR, "<2> %s gddev003 FID 0 6 policy change",  ptime);
	             
	syslog(LOG_ERR, "<1> %s gddev001 FID 2 1 TCP 10.10.10.1 4099 10.10.30.2 80",  ptime);
	syslog(LOG_ERR, "<1> %s gddev002 FID 2 1 TCP 10.10.10.2 4099 10.10.30.3 80",  ptime);
	syslog(LOG_ERR, "<1> %s gddev003 FID 2 1 TCP 10.10.10.3 4099 10.10.30.4 80",  ptime);
	
	sleep(DEFAULT_SEND_TIME);
}

	closelog();
	return 0;
}
