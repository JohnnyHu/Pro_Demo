/* @file ic_trap.c */
/***
 * traphandle format:
 * 0-hostname:
 * 1-ipaddress:
 * 2-uptime:
 * 3-trapoid:
 * 4-varlist:
 *
**/

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <time.h>

#include "ic_public.h"

#define TRAP_TYPE_DEFAULT       0   // 预留
#define TRAP_TYPE_IF_UP         1   // 网口up
#define TRAP_TYPE_IF_DOWN       2   // 网口down

#define TRAP_TYPE_HW_LOGIN_SUCC    3   // 登录成功
#define TRAP_TYPE_HW_LOGIN_FAIL    4   // 登录失败
#define TRAP_TYPE_HW_LOG_OUT       5   // 退出登录
#define TRAP_TYPE_HW_MOD_PASSWD    6   // 修改密码
#define TRAP_TYPE_HW_MOD_CONF      7   // 配置变更
#define TRAP_TYPE_HW_IF_TRAFFIC    8   // 网口流量
#define TRAP_TYPE_HW_USR_OPERATE   9   // 用户操作？？？

#define MAX_COUNT	100
#define WORD_LEN	256
#define BUFFER_SZ	512
#define MAX_BUFFER_SZ	1024

#define DTYPE_NETWORK	"SW"
#define DEVICE_TYPES	"FW FID BID SVR SW VEAD"
#define IC_TRAP_FILE 	"/var/log/ic_trap.log"
#define IC_TRAP_FILTER 	"/var/log/ic_trap_filter.log"
 
struct trap_type_desc {
    const int type;
    const char *value;
} TRAP_TYPE_DESC[] = {
    { TRAP_TYPE_IF_UP,              "up"                },
    { TRAP_TYPE_IF_DOWN,            "down"              },  
    { TRAP_TYPE_HW_LOGIN_SUCC,      "hwUserLogin"       },
    { TRAP_TYPE_HW_LOGIN_FAIL,      "hwUserLoginFail"   },
    { TRAP_TYPE_HW_LOG_OUT,         "hwUserLogout"      },
    { TRAP_TYPE_HW_MOD_PASSWD,      "hwcfgchgotify"     },
    { TRAP_TYPE_HW_MOD_CONF,        "hwcfgchgotify"     },
    { TRAP_TYPE_HW_IF_TRAFFIC,      "hwIfMonitorInputRate"  },
    { TRAP_TYPE_HW_IF_TRAFFIC,      "hwIfMonitorOutputRate" },
    { TRAP_TYPE_HW_USR_OPERATE,     " " },
    { TRAP_TYPE_DEFAULT,            " " }
};

struct trap_value {
    char type[WORD_LEN+1];
    char value[WORD_LEN+1];
}; 

static int  g_traptype  = -1;
static int  g_trapcount = -1;
static char g_traphandle[MAX_COUNT][WORD_LEN+1];

int get_trap_type(const char *strval);
int parse_message(char (*traphandle)[WORD_LEN+1], int count, int type);
int print_traphandle(char (*traphandle)[WORD_LEN+1], int count);
int print_message(const char *message, size_t len);

int gen_message(const struct trap_value *trapval, int count, int type);
int gen_message_ifstat(const struct trap_value *trapval, int count, int type);
int gen_message_logon(const struct trap_value *trapval, int count, int type);
static void log_trap(int level, const char *msg, ...);

int main(int argc, char* argv[])
{
	int ret = 0;
	open_syslog("ic", LOG_CONS | LOG_PID, LOGGER_TYPE);

	if(argc != 2) { 
		log_trap(LOG_ERR, "Usage : %s trap-type", argv[0]);
		exit(1);
	}	

	/* press ctrl+d exit */
	char str [BUFFER_SZ+1] = {0};
	while (fgets(str, sizeof(str), stdin) != NULL) {
		if ( g_trapcount < MAX_COUNT ) {
			g_trapcount++;
			memcpy(g_traphandle[g_trapcount], str, WORD_LEN);
		} else {
			log_trap(LOG_ERR, "larger than MAX_COUNT[%d]", MAX_COUNT);
		} 
	}

	ret = print_traphandle(g_traphandle, g_trapcount);
	if (ret < 0) {
		log_trap(LOG_ERR, "print_traphandle() error");
		return -1;
	}

	char *trapval = argv[1];
	ret = get_trap_type(trapval);
	if (ret < 0) {
		log_trap(LOG_ERR, "get_trap_type() error");
		return -1;
	}
	g_traptype = ret;
	
	ret = parse_message(g_traphandle, g_trapcount, g_traptype);
	if (ret < 0) {
		log_trap(LOG_ERR, "parse_message() error");
		return -1;
	}
	
	return 0;
}

static void log_trap(int level, const char *msg, ...)
{
	char buf[LOG_MSG_LEN];
	va_list ap;
	va_start(ap, msg);
	vsnprintf(buf, LOG_MSG_LEN, msg, ap);
	va_end(ap);
	syslog( LOGGER_TYPE | level,  "[ic_trap] %s",  buf);
}

int get_trap_type(const char *strval)
{
	int type = -1;
	struct trap_type_desc *ptrap = TRAP_TYPE_DESC;
	for ( ; ptrap->type != TRAP_TYPE_DEFAULT; ptrap++ ) {
		if (!strcmp(ptrap->value, strval)) {
			type = ptrap->type;
			break;
		}
	}
	return type;
}

// 打印收到的报文
int print_message(const char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_TRAP_FILTER, "a+");
	if (NULL == fp) {
		log_trap(LOG_ERR, "fopen() errors:%s", strerror(errno));
		return -1;
	}
	
	//fputs( message, fp );
	fwrite(message, sizeof(char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}	


// 打印收到的trap报文
int print_traphandle(char (*traphandle)[WORD_LEN+1], int count)
{
	FILE *fp = NULL;
	fp = fopen(IC_TRAP_FILE, "a+");
	if (NULL == fp) {
		log_trap(LOG_ERR, "fopen() errors:%s", strerror(errno));
		return -1;
	}
	
	fputs("\n", fp);
	for (int i = 0; i <= count; i++) {
		//fputs(traphandle[i], fp);
		fputs(*(traphandle+i), fp);
		//fputs("\t", fp);
		fflush(fp);
	}

	fclose(fp);
	return 0;
}


// 解析报文内容
int parse_message(char (*traphandle)[WORD_LEN+1], int count, int type)
{
	if ( count < 4 ) {
		log_trap(LOG_ERR, "parse_message arg count[%d]", count);
		return -1;
	} 

	int ret = 0;
	struct trap_value trap_val[MAX_COUNT];
	memset(&trap_val, 0x00, sizeof(trap_val));

	char *pch1, *pch2;

	// hostname
	pch1 = strchr(traphandle[0], '<');
	pch2 = strchr(traphandle[0], '>');
	if (NULL == pch1 || NULL == pch2) {
		log_trap(LOG_ERR, "parse hostname error");
		return -1;
	}
	strncpy(trap_val[0].type, "hostname", sizeof(trap_val[0].type)-1);
	strncpy(trap_val[0].value, pch1+1, pch2-pch1-1);

	// ipaddress
	pch1 = strchr(traphandle[1], '[');
	pch2 = strchr(traphandle[1], ']');
	if (NULL == pch1 || NULL == pch2) {
		log_trap(LOG_ERR, "parse ipaddress error");
		return -1;
	}
	strncpy(trap_val[1].type, "ipaddress", sizeof(trap_val[1].type)-1);
	strncpy(trap_val[1].value, pch1+1, pch2-pch1-1);
	

	char filter1[WORD_LEN+1], filter2[WORD_LEN+1];

	// uptime
	ret = sscanf(traphandle[2], "%s %s", filter1, filter2);
	if (ret == 2 ) {
		strncpy(trap_val[2].type,  filter1, sizeof(filter1));
		strncpy(trap_val[2].value, filter2, sizeof(filter2));
	}
	
	// trapoid
	ret = sscanf(traphandle[3], "%s %s", filter1, filter2);
	if (ret == 2 ) {
		strncpy(trap_val[3].type,  filter1, sizeof(filter1));
		strncpy(trap_val[3].value, filter2, sizeof(filter2));
	}
	
	// varlists
	for (int i = 4; i <= count; i++ ) {
		ret = sscanf(traphandle[i], "%s %s", filter1, filter2);
		if (ret == 2 ) {
			strncpy(trap_val[i].type,  filter1, sizeof(filter1));
			strncpy(trap_val[i].value, filter2, sizeof(filter2));
		}
	}

	ret = gen_message(trap_val, count, type);
	if (ret < 0) {
		log_trap(LOG_ERR, "gen_message() error");
		return -1;
	}	
	
	return 0;
}


int gen_message(const struct trap_value *trapval, int count, int type)
{
	int ret = 0;

	switch ( type ) {
	case TRAP_TYPE_IF_UP:
	case TRAP_TYPE_IF_DOWN: 
		ret = gen_message_ifstat(trapval, count, type);
		if (ret < 0) {
			log_trap(LOG_ERR, "gen_message_ifstat() error");
		}	
		
		break;
	case TRAP_TYPE_HW_LOGIN_SUCC:
	case TRAP_TYPE_HW_LOGIN_FAIL:
	case TRAP_TYPE_HW_LOG_OUT:
		ret = gen_message_logon(trapval, count, type);
		if (ret < 0) {
			log_trap(LOG_ERR, "gen_message_logon() error");
		}	

		break;
	case TRAP_TYPE_HW_IF_TRAFFIC:
		break;
	default:
		break;
	
	}

	return ret;
}


// 生成消息--->端口up/down
int gen_message_ifstat(const struct trap_value *trapval, int count, int type)
{
	if ( type != TRAP_TYPE_IF_UP && 
		 type != TRAP_TYPE_IF_DOWN ) {
		log_trap(LOG_ERR, "type[%d] error", type);
		return -1;
	}
	if (count < 7) {
		log_trap(LOG_ERR, "count=[%d], parse trap info error", count);
		return -1;
	}

	char datetime[19+1] = {0};
	char *ptime = Get19DateTime(GetNowDateTime());
	memcpy(datetime, ptime, sizeof(datetime));

	// 验证其他交换机的所在的port顺序????
	const char *pch = strrchr(trapval[7].value, '/'); 
	int port = (pch != NULL ? atoi(pch+1) : -1);
	if (port == -1) {
		log_trap(LOG_ERR, "find port error\n");
		return -1;
	}

	int warn_level  = 2;	
	int log_type	= 1;
	int log_stype	= (type == TRAP_TYPE_IF_UP ? 1 : 2);
	const char *device_name = "NARI"; 	// 设备名称怎么获得?.......

	char buffer[MAX_BUFFER_SZ+1] = {0};
	snprintf(buffer, sizeof(buffer), 
		"<%d> %s %s %s %d %d %d\n", 
		 warn_level, 
		 ptime, 
		 device_name, 
		 DTYPE_NETWORK, 
		 log_type, 
		 log_stype,
		 port);	

	// 打印消息.....
	print_message(buffer, strlen(buffer));

	// 采集接口上传
#if HAVE_BASE_H
	int ret = 0;
	ret = pub_device_msg(PUB_NAME, buffer);
	if (ret != 0) {
		log_trap(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
		return -1;
	} 
#endif

	return 0;
}


// 生成消息--->登录成功/登录失败/退出登录
int gen_message_logon(const struct trap_value *trapval, int count, int type)
{
		if ( type != TRAP_TYPE_HW_LOGIN_SUCC &&
			 type != TRAP_TYPE_HW_LOGIN_FAIL &&
			 type != TRAP_TYPE_HW_LOG_OUT ) {
			printf("type[%d] error\n", type);
			return -1;
		}
		if (count < 6) {
			log_trap(LOG_ERR, "count=[%d], parse trap info error", count);
			return -1;
		}
			 
		char datetime[19+1] = {0};
		char *ptime = Get19DateTime(GetNowDateTime());
		memcpy(datetime, ptime, sizeof(datetime));

		const char *admin  = trapval[4].value;
		const char *ipaddr = trapval[5].value;
		
		int warn_level	= 2;	
		int log_type	= 1;
		int log_stype = (type==TRAP_TYPE_HW_LOGIN_SUCC ? 1 : (type==TRAP_TYPE_HW_LOGIN_FAIL ? 2 : 3));
		const char *device_name = "NARI";	// 设备名称怎么获得?.......		
		
		char buffer[MAX_BUFFER_SZ+1] = {0};
		snprintf(buffer, sizeof(buffer), 
			"<%d> %s %s %s %d %d %s %s\n", 
			 warn_level, 
			 ptime, 
			 device_name, 
			 DTYPE_NETWORK, 
			 log_type, 
			 log_stype,
			 admin,
			 ipaddr); 
	
		// 打印消息.....
		print_message(buffer, strlen(buffer));
	
		// 采集接口上传
#if HAVE_BASE_H
		int ret = 0;
		ret = pub_device_msg(PUB_NAME, buffer);
		if (ret != 0) {
			log_trap(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
			return -1;
		} 
#endif
		return 0;

}




