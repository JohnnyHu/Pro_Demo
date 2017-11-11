/** @file ic_host.c **/
/* NOTE:
 * 多线程模型适合处理短连接，且连接的打开关闭非常频繁的情况, 但
 * 不适合处理长连接。
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <pthread.h>

#include "ic_public.h"

#define	FILTER_LEN		(64)
#define MAX_CLNT_NUM	(256)
#define BUFFER_SIZE 	(2048)
#define DEFAULT_PORT	(8800)

#define MSG_HEAD_LEN	(8)
#define MSG_TAIL_LEN	(2)
#define MSG_HEAD_FLAG	(0x55)
#define MSG_TAIL_FLAG	(0xAA)

#define MTYPE_INFO_UPLOAD		0x1		/* 采集信息上报 */
#define MTYPE_ARG_CHECK			0x2		/* 参数查看 */
#define MTYPE_ARG_SETTING 		0x3		/* 参数设置 */
#define MTYPE_BASELING_CHECK 	0x4		/* 启动基线核查 */
#define MTYPE_NETWORK_DISCON 	0x5		/* 启动主动断网       */

#define DTYPE_HOST		"SVR"
#define DEVICE_TYPES	"FW FID BID SVR SW VEAD"
#define IC_HOST_FILTER 	"/var/log/ic_host_filter.log"

#define	MSG_FILTER_OK	0
#define	MSG_NEED_ALARM	1

typedef struct packet_format {
	uint8_t		head_flag;
	uint16_t	msg_len;
	uint8_t 	*msg;
	uint8_t		checksum;
	uint8_t		tail_flag;
} PacketFormat;

struct ic_server_info {
	int 	serv_sock;
	int 	clnt_cnt;
	int		clnt_socks[MAX_CLNT_NUM];
	int 	should_stop;
	pthread_mutex_t mutex;
};

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
	{"SVR", 5, 15, UTYPE_REAL_TIME		},
	{"SVR", 5, 12, UTYPE_LOCAL_SHOW		},
	{"SVR", 5, 13, UTYPE_LOCAL_SHOW 	},
	{"SVR", 5, 16, UTYPE_REAL_TIME 		},
	{"SVR", 5, 17, UTYPE_REAL_TIME 		},
	{"SVR", 5, 18, UTYPE_REAL_TIME 		},
	{"SVR", 5, 19, UTYPE_REAL_TIME 		},
	{"SVR", 5, 20, UTYPE_REAL_TIME 		},
	{"SVR", 5, 21, UTYPE_REAL_TIME 		},
	{"SVR", 5, 22, UTYPE_REAL_TIME 		},
	{"SVR", 5, 23, UTYPE_REAL_TIME 		},
	{"SVR", 5, 24, UTYPE_REAL_TIME 		},
	{"SVR", 5, 25, UTYPE_MERGE 			},
	{"SVR", 5, 26, UTYPE_REAL_TIME 		},
	{"SVR", 5, 27, UTYPE_REAL_TIME 		},
	{"SVR", 5, 28, UTYPE_REAL_TIME 		},
	{"SVR", 5, 29, UTYPE_REAL_TIME 		},
	{"SVR", 5, 34, UTYPE_REAL_TIME 		},
	{"SVR", 5, 35, UTYPE_REAL_TIME 		}
};

int ic_host_init(int port);
int ic_host_deinit(void);

uint8_t check_message(const unsigned char *message, size_t len);
int 	parse_message(const unsigned char *message, size_t len);
int 	filter_message(const unsigned char *message, size_t len);
int 	print_message(const unsigned char *message, size_t len);
int 	get_upload_mode(IC_ALARM_ITEM * pitem);

void *  handle_clnt(void * arg); 

void cleanup(int signo);
void print_buf(const unsigned char *s, unsigned int len);

static struct ic_server_info g_serv_info; 
static struct ic_server_info *psrv_info = &g_serv_info;

int main(int argc, char *argv[])
{
	int port = DEFAULT_PORT;

	// 读取环境变量中设置的端口值
	char *HOST_PORT = getenv("IC_HOST_PORT");
	if ( NULL != HOST_PORT) {
		port = atoi(HOST_PORT);
	}
	printf("current port value: %d\n", port);

	signal(SIGTERM, cleanup);
	signal(SIGINT,  cleanup);

	int ret = ic_host_init(port);
	if (ret != 0) {
		printf("ic_host_init() error\n" );
		return -1;
	}

	pthread_t		thread_id;
	int 			clnt_sock;
	struct sockaddr_in 	clnt_addr;
	socklen_t 		clnt_addr_sz;
	
	while ( !psrv_info->should_stop ) {
		clnt_addr_sz = sizeof(clnt_addr);
		clnt_sock = accept(psrv_info->serv_sock, (struct sockaddr*)&clnt_addr,
				 &clnt_addr_sz);
		if(-1 == clnt_sock) {
			printf("fail to accept socket. error info:%s\n", strerror(errno));
			continue;
		}
	
		pthread_mutex_lock(&psrv_info->mutex);
		psrv_info->clnt_socks[psrv_info->clnt_cnt++] = clnt_sock;
		pthread_mutex_unlock(&psrv_info->mutex);

		pthread_create(&thread_id, NULL, handle_clnt, (void *)&clnt_sock);
		pthread_detach(thread_id);
		printf("connected client from: %s:%d, cfd:%d\n", 
			inet_ntoa(clnt_addr.sin_addr), htons(clnt_addr.sin_port), clnt_sock);	
	}

	printf("ic host server is exiting......\n");
	while (psrv_info->clnt_cnt > 0) {
		sleep(2);
		printf("current client count[%d]...\n", psrv_info->clnt_cnt );
	}

	ic_host_deinit();

	printf("主线程退出\n");
	return 0;

}

void print_buf(const unsigned char *s, unsigned int len)
{
	int i = 0;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			printf("\n[0x%04x]  ", i);
		}
		printf("%02x ",s[i]);
	}
	printf("\n");	
}


void cleanup(int signo)
{
	psrv_info->should_stop = 1;
}

int ic_host_init(int port)
{	
	psrv_info->should_stop  = 0;
	psrv_info->clnt_cnt 	= 0;
	
	pthread_mutex_init(&psrv_info->mutex, NULL);

	// 调用socket函数创建套接字
	memset(&psrv_info->clnt_socks, 0, sizeof(psrv_info->clnt_socks));
	psrv_info->serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(-1 == psrv_info->serv_sock) {
		printf("fail to create socket. error info:%s\n", strerror(errno));
		return -1;
	}
	//fcntl(psrv_info->serv_sock, F_SETFL, O_NONBLOCK);

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	// 调用bind函数分配IP地址和端口号
	if( -1 == bind(psrv_info->serv_sock, (struct sockaddr*)&serv_addr, 
				sizeof(serv_addr)) ) {
		printf("fail to bind socket. error info:%s\n", strerror(errno));
		close(psrv_info->serv_sock);
		return -1;
	}

	// 监听端口的连接请求
	if( -1 == listen(psrv_info->serv_sock, SOMAXCONN) ) {
		printf("fail to listen socket. error info:%s\n", strerror(errno));
		close(psrv_info->serv_sock);
		return -1;
	}

	printf("服务器启动，正在监听端口[%d]的连接请求......\n", port);
	return 0;
}

int ic_host_deinit(void)
{
	close(psrv_info->serv_sock);
	pthread_mutex_destroy(&g_serv_info.mutex);
	return 0;
}

void* handle_clnt(void* arg) 
{
	int clnt_sock = *((int *)arg);
	unsigned char message[BUFFER_SIZE] = {0};
	
	while (1) {
		if ( psrv_info->should_stop ) break;

		// 接收报文头部
		size_t len = 0, recv_len = 0, want_len = MSG_HEAD_LEN;
		while ((len = recv(clnt_sock, message + recv_len, want_len, 0)) > 0) {
			if (len < want_len) {
				recv_len += len;
				want_len -= len;	
				continue;
			}		
			break;
		}
		if (len == 0) {
			printf("head-->client shutdown link!\n");
			break;
		}
		else if (len < 0) {
			printf("socket receive header fail, len:%zu, cfd:%d!, errors:%s\n", 
				len, clnt_sock, strerror(errno));
			break;
		}

		if (MSG_HEAD_FLAG != message[0]) {
			printf("The message head flag [%d] isn't [%d], check error!\n", 
				message[0], MSG_HEAD_FLAG);
		} 

		if (MTYPE_INFO_UPLOAD != message[1]) {
			printf("The message head type [%d] isn't [%d], check error!\n", 
				message[1], MTYPE_INFO_UPLOAD);
		} 

		uint32_t tmp_len, msg_len; 
		memcpy(&tmp_len, message+4, sizeof(uint32_t));
		if ((msg_len = ntohl(tmp_len)) <= 0) {
			printf("The message content len [%d] error!\n", msg_len);
			break;
		}


		// 接收报文内容
		recv_len = 0;
		want_len = msg_len + MSG_TAIL_LEN;
		if (want_len > BUFFER_SIZE) {
			printf("The message content len [%zu] is larger than default len [%d]\n", 
				want_len, BUFFER_SIZE);
			break;
		}

		int ret = 0;
		while ((len = recv(clnt_sock, message + recv_len, want_len, 0)) > 0) {
			if (len < want_len) {
				recv_len += len;
				want_len -= len;	
				continue;
			}
			break;
		}
		if (len == 0) {
			printf("content-->client shutdown link!\n");
			break;
		}
		else if (len < 0) {
			printf("socket receive content fail, len:%zu, cfd:%d!, errors:%s\n", 
				len, clnt_sock, strerror(errno));
			break;
		}

		// 报文接收完整，进行处理.........
		print_buf(message, msg_len + MSG_TAIL_LEN);
	
		ret = check_message(message, msg_len + MSG_TAIL_LEN);
		if (ret != 0) {
			printf("check_message() error\n" );
			break;
		}
		
		ret = parse_message(message, msg_len + MSG_TAIL_LEN);
		if (ret != 0) {
			printf("parse_message() error\n" );
			break;
		}

	}

	// 移除断开的连接或者出错的连接
	pthread_mutex_lock(&psrv_info->mutex);
	for (int i = 0; i < psrv_info->clnt_cnt; i++) {
		if (clnt_sock != psrv_info->clnt_socks[i]) 
			continue;

		while (i++ < psrv_info->clnt_cnt-1)	
			psrv_info->clnt_socks[i-1] = psrv_info->clnt_socks[i];  
		psrv_info->clnt_cnt--;
		break;
	}
	pthread_mutex_unlock(&psrv_info->mutex);

	// 断开连接，关闭套接字
	close(clnt_sock); 	
	return NULL;
}

// 获取日志的上传模式
int get_upload_mode(IC_ALARM_ITEM * pitem)
{
	if (NULL == pitem) {
		printf("get_upload_mode() arg invalid\n" );
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

// 打印收到的报文
int print_message(const unsigned char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_HOST_FILTER, "a+");
	if (NULL == fp) {
		printf("fopen() errors:%s\n", strerror(errno));
		return -1;
	}
	
	//fputs((char *)message, fp);
	fwrite(message, sizeof(unsigned char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}


// 校验报文内容
uint8_t check_message(const unsigned char *message, size_t len) 
{
	size_t msg_len = len - MSG_TAIL_LEN;
	
	// 报文尾
	uint8_t tail_flag = message[len-1];
	if (MSG_TAIL_FLAG != tail_flag) {
		printf("The message tail flag [%d] isn't [%d], check error!\n", 
			tail_flag, MSG_TAIL_FLAG);
		return -1;
	} 	

	// 内容校验和
	uint8_t checksum = message[0];
	for (int i = 1; i < msg_len; i++) {
		checksum ^= message[i];		
	}
	printf("checksum: [%d]-[%d]-->[%d]\n", message[0], message[msg_len-1], checksum);

	if (message[len-2] != checksum) {
		printf("The message checksum [%d]---[%d] isn't equal!\n", 
				checksum, message[len-2]);
		//return -1;		
	}

	return 0;
}


// 解析报文内容
int parse_message(const unsigned char *message, size_t len) 
{
	int ret = 0;
	char strmsg[BUFFER_SIZE+1] = {0};
	memcpy(strmsg, message, len-MSG_TAIL_LEN);
	
	// 输出报文内容
	print_message(message, len-MSG_TAIL_LEN);	
	
	// 过滤处理.......
	ret = filter_message(message, len-MSG_TAIL_LEN);	
	if (ret < 0) {
		printf("the message format is wrong!!!\n");
		printf("message: [%s]\n", strmsg);
	}
	printf("ret[%d]-message[%s]\n", ret, strmsg);
	
	// 采集接口上传
#if HAVE_BASE_H
	ret = pub_device_msg(PUB_NAME, strmsg);
	if (ret != 0) {
		printf("pub_device_msg() error[%d]!!!\n", ret);
		return -1;
	} 
#endif

	// 告警接口上传
	if (ret == UTYPE_MERGE || ret == UTYPE_MERGE) {
		;
	}
	
	return 0;
}

// 报文内容过滤规则
int filter_message(const unsigned char *message, size_t len)
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
			printf("alarm format[%s] error\n", alarm);
			return -1;
		}

		if (strlen(date) != 10) {
			printf("date format[%s] error\n", date);
			return -1;
		}

		if (strlen(time) != 8) {
			printf("time format[%s] error\n", time);
			return -1;
		}

		if (strncmp(dtype, DTYPE_HOST, strlen(dtype))) {
			printf("device type format[%s] error\n", dtype);
			return -1;
		}

		IC_ALARM_ITEM alarm_item;
		memcpy(alarm_item.dtype, dtype, sizeof(alarm_item.dtype));
		alarm_item.ltype = ltype;
		alarm_item.stype = stype;
		ret = get_upload_mode(&alarm_item);
		if (ret < 0) {
			printf("get_upload_mode() error\n");
			return -1;
		}
		
		return ret;
	}

	return -1;
}



