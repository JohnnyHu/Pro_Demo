/** @file ic_safety.c **/

#include <unistd.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "ic_public.h"

#define	FILTER_LEN		(64)
#define BUFFER_SIZE		(2048)

#define DTYPE_FW		"FW"	// 防火墙
#define DTYPE_FID		"FID"	// 横向正向隔离装置
#define DTYPE_BID		"BID"	// 横向反向隔离装置
#define DTYPE_VEAD		"VEAD"	// 纵向加密装置
#define DEVICE_TYPES	"FW FID BID SVR SW VEAD"

#define IC_SAFETY_FILTER "/var/log/ic_safety_filter.log"

// 上传模式: 0-忽略、1-实时、2-归并、3-本地展示
enum upload_type {
	UTYPE_IGNORE		= 0,
    UTYPE_REAL_TIME		= 1,
    UTYPE_MERGE			= 2,
    UTYPE_LOCAL_SHOW	= 3
};

typedef struct ic_alarm_item {
	char 	dtype[FILTER_LEN];	// 设备类型
	int  	ltype;				// 日志类型
	int  	stype;				// 日志子类型
	enum upload_type  mode;		// 上传模式
}IC_ALARM_ITEM;

static IC_ALARM_ITEM IC_Alarm_Items[] = {
	{"VEAD", 0, 1,  UTYPE_IGNORE		},
	{"VEAD", 0, 2,  UTYPE_IGNORE		},
	{"VEAD", 0, 3,  UTYPE_IGNORE 		},
	{"VEAD", 0, 4,  UTYPE_IGNORE 		},
	{"VEAD", 1, 2,  UTYPE_LOCAL_SHOW 	},
	{"VEAD", 1, 3,  UTYPE_LOCAL_SHOW 	},
	{"VEAD", 1, 6,  UTYPE_IGNORE 		},
	{"VEAD", 1, 7,  UTYPE_IGNORE 		},
	{"VEAD", 1, 8,  UTYPE_LOCAL_SHOW 	},
	{"VEAD", 1, 10, UTYPE_LOCAL_SHOW 	},
	{"VEAD", 2, 1,  UTYPE_IGNORE 		},
	{"VEAD", 2, 7,  UTYPE_REAL_TIME 	},
	{"FW",   0, 1,  UTYPE_REAL_TIME 	},
	{"FW",   0, 2,  UTYPE_REAL_TIME 	},
	{"FW",   0, 3,  UTYPE_REAL_TIME 	},
	{"FW",   0, 4,  UTYPE_REAL_TIME 	},
	{"FW",   1, 1,  UTYPE_MERGE 		},
	{"FW",   1, 2,  UTYPE_MERGE 		},
	{"FW",   1, 3,  UTYPE_IGNORE 		},
	{"FW",   1, 4,  UTYPE_IGNORE 		},
	{"FW",   1, 5,  UTYPE_IGNORE 		},
	{"FW",   1, 7,  UTYPE_IGNORE 		},
	{"FW",   1, 8,  UTYPE_IGNORE 		},	
	{"FW",   3, 1,  UTYPE_MERGE 		},
	{"FW",   3, 2,  UTYPE_MERGE 		},
	{"FID",  0, 3,  UTYPE_MERGE 		},
	{"FID",  0, 4,  UTYPE_MERGE 		},
	{"FID",  0, 5,  UTYPE_IGNORE 		},
	{"FID",  0, 6,  UTYPE_IGNORE 		},
	{"FID",  1, 1,  UTYPE_MERGE 		},
	{"BID",  0, 3,  UTYPE_MERGE 		},
	{"BID",  0, 4,  UTYPE_MERGE 		},
	{"BID",  0, 5,  UTYPE_IGNORE 		},
	{"BID",  0, 6,  UTYPE_IGNORE 		},
	{"BID",  1, 1,  UTYPE_MERGE 		}
};

static void 
log_safety(int level, const char *msg, ...);

int parse_message(const char *message, size_t len);
int filter_message(const char *message, size_t len);
int print_message(const char *message, size_t len);
int get_upload_mode(IC_ALARM_ITEM * pitem);

int main(int argc, char* argv[])
{	
	// 重启syslog服务器
	//system("service rsyslog restart");
	open_syslog("ic", LOG_CONS | LOG_PID, LOGGER_TYPE);
	log_safety(LOG_NOTICE, "start-safety devices message");
	
	int ret = 0;
	char str [BUFFER_SIZE+1] = {0};

	/* press ctrl+d exit */
	while (fgets(str, sizeof(str), stdin) != NULL) {
		ret = parse_message(str, strlen(str));
		if (ret != 0) {
			log_safety(LOG_ERR, "parse_message() error");
			//break;
		}
	}

	log_safety(LOG_NOTICE, "end-safety devices message");
	return 0;
}

static void log_safety(int level, const char *msg, ...)
{
	char buf[LOG_MSG_LEN];
	va_list ap;
	va_start(ap, msg);
	vsnprintf(buf, LOG_MSG_LEN, msg, ap);
	va_end(ap);
	syslog( LOGGER_TYPE | level,  "[ic_safety] %s",  buf);
}


// 打印收到的报文
int print_message(const char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_SAFETY_FILTER, "a+");
	if (NULL == fp) {
		printf("fopen() errors:%s", strerror(errno));
		return -1;
	}
	
	//fputs((char *)message, fp);
	fwrite(message, sizeof(char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}


// 解析报文内容
int parse_message(const char *message, size_t len) 
{
	int ret = 0;
	char strmsg[BUFFER_SIZE+1] = {0};
	memcpy(strmsg, message, sizeof(strmsg)-1);
	
	// 过滤处理.......
	ret = filter_message(message, len);
	if (ret < 0) {
		log_safety(LOG_ERR, "the message format is wrong!!!");
		log_safety(LOG_ERR, "message: [%s]", message);
		return -1;
	}
	//log_safety(LOG_DEBUG, "ret[%d]-message[%.*s]", ret, (int)len, message);

	// 输出报文内容
	print_message(message, len);
	
	// 采集接口上传
#if HAVE_BASE_H
	ret = pub_device_msg(PUB_NAME, strmsg);
	if (ret != 0) {
		log_safety(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
		return -1;
	} 
#endif

	// 告警接口上传
	if (ret == UTYPE_MERGE || ret == UTYPE_MERGE) {
		;
	}

	return 0;
}

// 获取日志的上传模式
int get_upload_mode(IC_ALARM_ITEM * pitem)
{
	if (NULL == pitem) {
		log_safety(LOG_ERR, "get_upload_mode() arg invalid" );
		return -1;
	}

	for (int i=0; i < sizeof(IC_Alarm_Items)/sizeof(IC_Alarm_Items[0]); i++) {
		if (!strncmp(IC_Alarm_Items[i].dtype, pitem->dtype, strlen(pitem->dtype)) &&
			IC_Alarm_Items[i].ltype == pitem->ltype && 
			IC_Alarm_Items[i].stype == pitem->stype) {
			return IC_Alarm_Items[i].mode;
		}
			
		continue;
	}
	
	return 0;
}

// 报文内容过滤规则
int filter_message(const char *message, size_t len)
{
	int ret = 0;
	char alarm[FILTER_LEN]  = {0};
	char date[FILTER_LEN]  	= {0};
	char time[FILTER_LEN]	= {0};
	char dname[FILTER_LEN]	= {0};
	char dtype[FILTER_LEN]	= {0};
	int  ltype, stype;
	
	ret = sscanf((const char *)message, 
				"%64s %64s %64s %64s %64s %d %d", 
				alarm, date, time, dname, dtype, &ltype, &stype);
	if (!(ret == EOF || ret <= 0) && ret == 7 ) {
		if (strlen(alarm) != 3 	||
			alarm[0] != '<' 	|| 
			alarm[2] != '>' 	|| 
			!(alarm[1] >='0' && alarm[1]<='3')) {
			log_safety(LOG_ERR, "alarm format[%s] error", alarm);
			return -1;
		}

		if (strlen(date) != 10) {
			log_safety(LOG_ERR, "date format[%s] error", date);
			return -1;
		}

		if (strlen(time) != 8) {
			log_safety(LOG_ERR, "time format[%s] error", time);
			return -1;
		}

		if (NULL == strstr(DEVICE_TYPES, dtype)) {
			log_safety(LOG_ERR, "device type format[%s] error", dtype);
			return -1;
		}

		IC_ALARM_ITEM alarm_item;
		memcpy(alarm_item.dtype, dtype, sizeof(alarm_item.dtype));
		alarm_item.ltype = ltype;
		alarm_item.stype = stype;
		ret = get_upload_mode(&alarm_item);
		if (ret < 0) {
			log_safety(LOG_ERR, "get_upload_mode() error");
			return -1;
		}
		
		return ret;
	}

	return -1;

}


