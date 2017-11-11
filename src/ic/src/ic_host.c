/** @file ic_host.c **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <sys/select.h>
#include <semaphore.h>
#include <pthread.h>

#include "ic_public.h"

#define MAX_IP_LEN		(15)
#define	FILTER_LEN		(64)
#define MAX_CLNT_NUM	(256)
#define BUFFER_SIZE 	(2048)
#define DEFAULT_PORT	(8800)

#define MSG_HEAD_LEN	(8)
#define MSG_TAIL_LEN	(2)
#define MSG_HEAD_FLAG	(0x55)
#define MSG_TAIL_FLAG	(0xAA)

#define DTYPE_HOST		"SVR"
#define DEVICE_TYPES	"FW FID BID SVR SW VEAD"
#define IC_HOST_FILTER 	"/var/log/ic_host_filter.log"

#define	MSG_FILTER_OK	0
#define	MSG_NEED_ALARM	1
#define MSG_NEED_CHANGE 2

#define FALSE	0
#define TRUE	1

typedef struct packet_format {
	uint8_t		head_flag;
	uint16_t	msg_len;
	uint8_t 	*msg;
	uint8_t		checksum;
	uint8_t		tail_flag;
} PacketFormat;

typedef struct msg_ctrl_format {
	uint8_t		str_ip[MAX_IP_LEN+1];
	uint8_t 	msg_type;
	uint16_t 	msg_arg;
	uint8_t 	payload[BUFFER_SIZE];
	uint32_t 	real_len;
} Msg_Ctrl;

struct ic_server_info {
	int 		serv_sock;
	int 		should_stop;
	fd_set  	sock_sets;
	int			fd_max;
	pthread_t   thread_test;
};

typedef struct ic_client_info {
	int  clnt_sock;
	uint8_t str_ip[MAX_IP_LEN+1];
	int  is_block;
	int  send_enable;
	int  recv_enable;
	uint8_t send_buffer[BUFFER_SIZE];
	size_t	send_len;
	uint8_t recv_buffer[BUFFER_SIZE];
	size_t  recv_len;
	pthread_mutex_t mutex;
	sem_t	semwait;
} IC_Clnt_Info;

enum query_flag {
    QF_FD = 0x1,  /* fd查询 */
    QF_IP = 0x2   /* ip查询 */
};

enum mtype_option {
    MTYPE_INFO_UPLOAD 		= 0x1,	/* 采集信息上报 */
    MTYPE_ARG_CHECK 		= 0x2,	/* 参数查看 */
    MTYPE_ARG_SETTING 		= 0x3,  /* 参数设置 */
    MTYPE_BASELING_CHECK  	= 0x4,	/* 启动基线核查 */
    MTYPE_NETWORK_DISCON 	= 0x5	/* 启动主动断网       */
};

enum arg_option {
    ARG_LIST_NET_CONN = 0x1,	/* 网络连接白名单 */
    ARG_LIST_SRV_PORT = 0x2,	/* 服务端口白名单 */
    ARG_LIST_KEY_FILE = 0x3, 	/* 关键文件/目录清单*/
    ARG_CYCLE_DEVICE  = 0x4,	/* 光驱设备检测周期 */
    ARG_CYCLE_ILLPORT = 0x5		/* 非法端口检测周期 */
};

int ic_host_init();
int ic_host_deinit(void);
int host_ctrl_opr(const Msg_Ctrl *msg_ctrl, Msg_Ctrl *rmsg_ctrl);
void* ctrl_fun_test(void* arg);

static void 
log_host(int level, const char *msg, ...);
static void 
cleanup(int signo);
static void 
print_buf(const uint8_t *buf, size_t len);
static int 
handle_clnt_request(int      	  sock);
static int 
select_read_socks(int          read_sock);
static int 
select_write_socks(int          write_sock);

static int 
add_clnt_info(int fd, const char *ip);
static IC_Clnt_Info * 
get_clnt_info(int query_flag, int fd, const char *ip);


static int 
process_ic_msg(int sock, const uint8_t *msg, size_t len);
static int 
process_uplink_msg(int sock, const uint8_t *msg, size_t len);
static int 	
parse_uplink_msg(const uint8_t *msg, size_t len, Msg_Ctrl *msg_ctrl);
static int 
check_msg(const uint8_t *msg, size_t len);
static int 
filter_msg(const uint8_t *msg, size_t len);
static int 
change_msg(uint8_t *msg, size_t len);
static int
print_msg(const uint8_t *msg, size_t len);
static int 
process_downlink_msg(const Msg_Ctrl *msg_ctrl, IC_Clnt_Info *clnt_info);


static int	g_clnt_count = 0;
static struct ic_client_info g_clnt_info[MAX_CLNT_NUM];

static struct ic_server_info g_serv_info; 
static struct ic_server_info *psrv_info = &g_serv_info;
int main(int argc, char *argv[])
{
	int ret = ic_host_init();
	if (ret != 0) {
		log_host(LOG_ERR, "ic_host_init() error");
		return -1;
	}

	fd_set read_socks, write_socks;			
	struct timeval	timout;	
	while ( !psrv_info->should_stop ) {
		
		read_socks  = psrv_info->sock_sets;
		write_socks = psrv_info->sock_sets;
		timout.tv_sec = 5;
		timout.tv_usec = 5000;

		int sock_num = select(psrv_info->fd_max+1, &read_socks, &write_socks, 0, &timout);
		if (sock_num == -1) {
			log_host(LOG_ERR, "select() error[%d], info:%s", errno, strerror(errno));
			break;
		}
		if (sock_num == 0) {
			continue;
		}

		for (int fd_idx = 0; fd_idx < psrv_info->fd_max+1; fd_idx++) {
			
			if ( FD_ISSET(fd_idx, &read_socks) ) {
				if ((ret = select_read_socks(fd_idx)) < 0) {
					log_host(LOG_ERR, "select_read_socks() error" );
					//continue;
				}				
			}
			if ( FD_ISSET(fd_idx, &write_socks) ) {
				if ((ret = select_write_socks(fd_idx)) < 0) {
					log_host(LOG_ERR, "select_write_socks() error" );
					//continue;
				}									
			}	
		}
		
	}

	ic_host_deinit();
	log_host(LOG_NOTICE, "ic host server has exited......");
	return 0;

}

int ic_host_init()
{
	open_syslog("ic", LOG_CONS | LOG_PID, LOGGER_TYPE);

	int port = DEFAULT_PORT;

	// 读取环境变量中设置的端口值
	char *HOST_PORT = getenv("IC_HOST_PORT");
	if ( NULL != HOST_PORT) {
		port = atoi(HOST_PORT);
	}
	log_host(LOG_NOTICE, "current port value: %d", port);

	signal(SIGTERM, cleanup);
	signal(SIGINT,  cleanup);

	for (int i=0; i < MAX_CLNT_NUM; i++) {
		pthread_mutex_init(&g_clnt_info[i].mutex, NULL);
		
		if (sem_init(&g_clnt_info[i].semwait, 0, 0) < 0) {
			log_host(LOG_ERR, "sem_init() error[%s]", strerror(errno));
			return -1;
		}
	}

	psrv_info->should_stop  = 0;
	
	// 调用socket函数创建套接字
	psrv_info->serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(-1 == psrv_info->serv_sock) {
		log_host(LOG_ERR, "fail to create socket. error info:%s", strerror(errno));
		return -1;
	}

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	// 调用bind函数分配IP地址和端口号
	if( -1 == bind(psrv_info->serv_sock, (struct sockaddr*)&serv_addr, 
				sizeof(serv_addr)) ) {
		log_host(LOG_ERR, "fail to bind socket. error info:%s", strerror(errno));
		close(psrv_info->serv_sock);
		return -1;
	}

	// 监听端口的连接请求
	if( -1 == listen(psrv_info->serv_sock, SOMAXCONN) ) {
		log_host(LOG_ERR, "fail to listen socket. error info:%s", strerror(errno));
		close(psrv_info->serv_sock);
		return -1;
	}

	FD_ZERO(&psrv_info->sock_sets);
	FD_SET(psrv_info->serv_sock, &psrv_info->sock_sets);
	psrv_info->fd_max = psrv_info->serv_sock;

	// 创建测试线程
	pthread_create(&psrv_info->thread_test, NULL, ctrl_fun_test, (void *)&psrv_info->serv_sock);

	log_host(LOG_NOTICE, "服务器启动，正在监听端口[%d]的连接请求......", port);
	return 0;
}

int ic_host_deinit(void)
{
	for (int i = 0; i < g_clnt_count; i++) {
		if (TRUE == g_clnt_info[i].is_block) {
			// wake up thread.......
			sem_post(&g_clnt_info[i].semwait);			
		}		
	}

	for (int i = 0; i < psrv_info->fd_max+1; i++) {
		if ( FD_ISSET(i, &psrv_info->sock_sets) ) {
			FD_CLR(i, &psrv_info->sock_sets); 
			close(i);
			log_host(LOG_DEBUG, "close socket[%d].....", i);
		}
	}

	for (int i = 0; i < MAX_CLNT_NUM; i++) {
		sem_destroy( &g_clnt_info[i].semwait );
		pthread_mutex_destroy( &g_clnt_info[i].mutex );
	}
	
	pthread_join(psrv_info->thread_test, NULL);
	return 0;
}

static void 
log_host(int level, const char *msg, ...)
{
	char buf[LOG_MSG_LEN];
	va_list ap;
	va_start(ap, msg);
	vsnprintf(buf, LOG_MSG_LEN, msg, ap);
	va_end(ap);

	syslog(LOGGER_TYPE | level,  "[ic_host] %s",  buf);
}

static int 
add_clnt_info(int fd, const char *ip)
{
	if ( g_clnt_count < MAX_CLNT_NUM ) {
		g_clnt_info[g_clnt_count].clnt_sock = fd;
		memcpy(g_clnt_info[g_clnt_count].str_ip, ip, MAX_IP_LEN);
	} else {
		log_host(LOG_CRIT, "client nums reach UPPER LIMIT");
		return -1;
	}
	
	log_host(LOG_DEBUG, "fd: %d, ip: [%s]", fd, (char *)g_clnt_info[g_clnt_count].str_ip); 
	g_clnt_count++;
	return 0;
}

static IC_Clnt_Info * 
get_clnt_info(int query_flag, int fd, const char *ip)
{
	if (query_flag != QF_FD && query_flag != QF_IP) {
		return NULL;
	}
	
	for (int i = 0 ; i < g_clnt_count; i++) {
		if (query_flag == QF_IP) {
			char *str_ip2 = (char *)g_clnt_info[i].str_ip;
			if (!strncmp(ip, str_ip2, strlen(ip))) {
				return &g_clnt_info[i];
			}
		}
		if (query_flag == QF_FD) {
			if (fd == g_clnt_info[i].clnt_sock) {
				return &g_clnt_info[i];
			}
		}
	}
	
	return NULL;
}

int host_ctrl_opr(const Msg_Ctrl *msg_ctrl, Msg_Ctrl *rmsg_ctrl)
{
	int ret = 0;
	
	if (msg_ctrl == NULL) {
		log_host(LOG_ERR, "host_ctrl_opr() arg invalid");
		return -1;
	}

	char str_ip[MAX_IP_LEN+1] = {0};
	memcpy(str_ip, msg_ctrl->str_ip, MAX_IP_LEN);

	IC_Clnt_Info *pclnt_info;
	pclnt_info = get_clnt_info(QF_IP, 0, str_ip);
	if ( NULL == pclnt_info ) {
		log_host(LOG_ERR, "Maybe the host ip[%s] is not connection", str_ip);
		return -1;
	} 
	log_host(LOG_NOTICE, "host_ctrl_opr, current ip[%s]", str_ip);
	
	pthread_mutex_lock(&pclnt_info->mutex);
	
	// 发送Buffer放入数据
	ret = process_downlink_msg(msg_ctrl, pclnt_info);
	if (ret != 0) {
		log_host(LOG_ERR, "process_downlink_msg() error" );
		return -1;
	}
	pclnt_info->send_enable = TRUE;
	
	log_host(LOG_DEBUG, "put msg into send buffer....");
	
	// 接收Buffer取出数据
	while (FALSE == pclnt_info->recv_enable) {
		if (psrv_info->should_stop) { break; }
	
		// block wait.....
		log_host(LOG_DEBUG, "recv buffer block wait....");
		pclnt_info->is_block = TRUE;
		sem_wait(&pclnt_info->semwait);
		pclnt_info->is_block = FALSE;
	}		
	
	log_host(LOG_DEBUG, "get msg into recv buffer....");
	// 处理接收到数据.....
	// ......
	print_buf(pclnt_info->recv_buffer, pclnt_info->recv_len);
	
	pclnt_info->send_enable = FALSE;
	pclnt_info->recv_enable = FALSE;
	memset(pclnt_info->send_buffer, 0x00, BUFFER_SIZE);
	memset(pclnt_info->recv_buffer, 0x00, BUFFER_SIZE);
	
	pthread_mutex_unlock(&pclnt_info->mutex);
	
	return 0;
}

static void 
print_buf(const uint8_t *buf, size_t len)
{
	int i = 0;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) { printf("\n[0x%04x]  ", i); }
		printf("%02x ",buf[i]);
	}
	printf("\n");	
}

static void 
cleanup(int signo)
{
	psrv_info->should_stop = 1;
	log_host(LOG_NOTICE, "ic host server is exiting......");
}

static int 
handle_clnt_request(int sock) 
{
	int clnt_sock = sock;
	uint8_t msg[BUFFER_SIZE] = {0};
		
	// 接收报文头部
	size_t len = 0, recv_len = 0, want_len = MSG_HEAD_LEN;
	while ((len = recv(clnt_sock, msg + recv_len, want_len, 0)) > 0) {
		if (len < want_len) {
			recv_len += len;
			want_len -= len;	
			continue;
		}		
		break;
	}
	if (len == 0) {
		log_host(LOG_WARNING, "head-->client shutdown link!");
		return 1;
	}
	else if (len < 0) {
		log_host(LOG_WARNING, "socket receive header fail, len:%zu, cfd:%d!, errors:%s", 
			len, clnt_sock, strerror(errno));
		return -1;
	}

	if (MSG_HEAD_FLAG != msg[0]) {
		log_host(LOG_ERR, "The msg head flag [%d] isn't [%d], check error!", 
			msg[0], MSG_HEAD_FLAG);
	} 

	uint32_t tmp_len, msg_len; 
	memcpy(&tmp_len, msg+4, sizeof(uint32_t));
	if ((msg_len = ntohl(tmp_len)) <= 0) {
		log_host(LOG_ERR, "The msg content len [%d] error!", msg_len);
		return -1;
	}

	// 接收报文内容
	recv_len = 0; want_len = msg_len + MSG_TAIL_LEN;
	if (want_len > BUFFER_SIZE) {
		log_host(LOG_ERR, "The msg content len [%zu] is larger than default len [%d]", 
			want_len, BUFFER_SIZE);
		return -1;
	}

	int ret = 0;
	while ((len = recv(clnt_sock, msg + MSG_HEAD_LEN + recv_len, want_len, 0)) > 0) {
		if (len < want_len) {
			recv_len += len;
			want_len -= len;	
			continue;
		}
		break;
	}
	if (len == 0) {
		log_host(LOG_WARNING, "content-->client shutdown link!");
		return 1;
	}
	else if (len < 0) {
		log_host(LOG_ERR, "socket receive content fail, len:%zu, cfd:%d!, errors:%s", 
			len, clnt_sock, strerror(errno));
		return -1;
	}

	// 报文接收完整，进行处理.........
	size_t total_len = MSG_HEAD_LEN + msg_len + MSG_TAIL_LEN;

	//log_host(LOG_DEBUG, "The msg head type[%02x]!\n", msg[1]);	
	//print_buf(msg, total_len);

	/* Note: 
     * 1. 采集报文和控制报文分开处理
     * 2. 采集报文放入采集buffer, 控制报文放入控制buffer
	 */
	if (MTYPE_INFO_UPLOAD == msg[1]) {	
		ret = process_ic_msg(clnt_sock, msg, total_len);
		if (ret != 0) {
			log_host(LOG_ERR, "process_ic_msg() error" );
			return -1;
		}
	} else {
		ret = process_uplink_msg(clnt_sock, msg, total_len);
		if (ret != 0) {
			log_host(LOG_ERR, "process_uplink_msg() error" );
			return -1;
		}
	}
 	
	return 0;
}

static int 
select_read_socks(int          read_sock)
{
	int 				ret;
	struct sockaddr_in 	clnt_addr;
	socklen_t 			clnt_addr_sz;
	int 				clnt_sock;

	if ( read_sock == psrv_info->serv_sock ) { // connect request
		clnt_addr_sz = sizeof(clnt_addr);
		clnt_sock = accept(psrv_info->serv_sock, (struct sockaddr*)&clnt_addr,
				 	&clnt_addr_sz);
		if(-1 == clnt_sock) {		
			log_host(LOG_ERR, "fail to accept socket. error info:%s", strerror(errno));
			return -1;
		}	
		
		FD_SET(clnt_sock, &psrv_info->sock_sets);
		if (clnt_sock > psrv_info->fd_max) { 
			psrv_info->fd_max = clnt_sock;
		}
	
		log_host(LOG_NOTICE, "connected client from: %s:%d, cfd:%d", 
			inet_ntoa(clnt_addr.sin_addr), htons(clnt_addr.sin_port), clnt_sock);
		
		ret = add_clnt_info(clnt_sock, inet_ntoa(clnt_addr.sin_addr));
		if (ret != 0) {
			log_host(LOG_ERR, "add_clnt_info() error");
			return -1;
		}
		
	}
	else {	// read request
	
		if ((ret = handle_clnt_request(read_sock)) < 0) {
			log_host(LOG_ERR, "handle_clnt_request() error" );
			psrv_info->should_stop = 1;
			return -1;
		}
		if ( ret == 1 ) {
			//close request for short connection
			FD_CLR(read_sock, &psrv_info->sock_sets);
			close(read_sock);
			log_host(LOG_ERR, "close socket[%d].....", read_sock);
		}
	}

	return 0;
}

static int 
select_write_socks(int          write_sock)
{
	int ret = 0;
	
	IC_Clnt_Info *pclnt_info;
	pclnt_info = get_clnt_info(QF_FD, write_sock, "");
	if ( NULL == pclnt_info ) {
		log_host(LOG_ERR, "Maybe the fd[%d] is disconnection", write_sock);
		return -1;
	} 
	if (!pclnt_info->send_enable) {
		return 0;
	}
	
	log_host(LOG_DEBUG, "server-->client, fd:[%d], ip:[%s]", write_sock, 
			(char*)pclnt_info->str_ip );
	
	ret = send( pclnt_info->clnt_sock, 
				pclnt_info->send_buffer, 
				pclnt_info->send_len, MSG_NOSIGNAL); 	
	if (-1 == ret) {
		log_host(LOG_ERR, "fail send socket. fd:%d, error_info:%s", write_sock, strerror(errno));
		return -1;
	}
	pclnt_info->send_enable = FALSE;
	
	log_host(LOG_DEBUG, "fd:%d, send_enable[%d]", write_sock, pclnt_info->send_enable); 		
	return 0;
}


// 处理采集报文
static int 
process_ic_msg(int sock, const uint8_t *msg, size_t len)
{
	if ( len < (MSG_HEAD_LEN + MSG_TAIL_LEN) || len > BUFFER_SIZE ) {
		log_host(LOG_ERR, "process_ic_msg() args are invalid[%zu]", len);
		return -1;
	}
	
	int ret = 0;

	// 报文校验
	ret = check_msg(msg, len);
	if (ret != 0) {
		log_host(LOG_ERR, "check_msg() error" );
		return -1;
	}

	// 报文解析	
	Msg_Ctrl msg_ctrl;
	memset(&msg_ctrl, 0x00, sizeof(msg_ctrl));
	ret = parse_uplink_msg(msg, len, &msg_ctrl);
	if (ret != 0) {
		log_host(LOG_ERR, "parse_uplink_msg() error" );
		return -1;
	}

	// 过滤处理.......
	ret = filter_msg(msg_ctrl.payload, msg_ctrl.real_len); 
	if (ret < 0) {
		log_host(LOG_ERR, "the msg format is wrong!!!");
		log_host(LOG_ERR, "msg: [%s]", msg_ctrl.payload);
	}
	//log_host(LOG_DEBUG, "ret[%d]-msg[%s]", ret, msg_ctrl.payload);

	// 个别数据改变.......
	if ( MSG_NEED_CHANGE == ret ) {
		ret = change_msg(msg_ctrl.payload, msg_ctrl.real_len); 
		if (ret < 0) {
			log_host(LOG_ERR, "change_msg() error" );
			//return -1;
		}
	}

	// 输出报文内容
	print_msg( msg_ctrl.payload, msg_ctrl.real_len );	
	
	// 采集接口上传
#if HAVE_BASE_H
	ret = pub_device_msg(PUB_NAME, (char *)msg_ctrl.payload);
	if (ret != 0) {
		log_host(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
		return -1;
	} 
#endif

	return 0;
}


// 处理上行报文
static int 
process_uplink_msg(int sock, const uint8_t *msg, size_t len)
{
	if ( len < (MSG_HEAD_LEN + MSG_TAIL_LEN) || len > BUFFER_SIZE ) {
		log_host(LOG_ERR, "process_uplink_msg() args are invalid[%zu]", len);
		return -1;
	}

	int ret = 0;
	
	IC_Clnt_Info *pclnt_info;
	pclnt_info = get_clnt_info(QF_FD, sock, "");
	if ( NULL == pclnt_info ) {
		log_host(LOG_ERR, "Can not find fd[%d] in g_clnt_info...", sock);
		return -1;
	} 

	memcpy(pclnt_info->recv_buffer, msg, len);
	pclnt_info->recv_len = len;
	
	if ( !pclnt_info->recv_enable ) {
		pclnt_info->recv_enable = TRUE;
		
		// wake up thread.......
		ret = sem_post(&pclnt_info->semwait);
		if (-1 == ret) {
			log_host(LOG_ERR, "sem_post() error, error_info:%s", strerror(errno));
			return -1;
		}
	}

	return 0;
}


// 解析上行报文
static int 	
parse_uplink_msg(const uint8_t *msg, size_t len, Msg_Ctrl *msg_ctrl)
{
	if ( len > BUFFER_SIZE ) {
		log_host(LOG_ERR, "the len [%zu] is larger than MAX BUFFER SIZE[%d]", 
			len, BUFFER_SIZE);
		return -1;
	}
		
	// 打印消息
	//print_buf(msg, len);

	// 报文类型
	msg_ctrl->msg_type = msg[1];

	// 报文参数
	uint16_t tmp_arg;
	memcpy(&tmp_arg, msg+2, sizeof(uint16_t));
	msg_ctrl->msg_arg = ntohs(tmp_arg);

	// 内容长度
	uint32_t tmp_len; 
	memcpy(&tmp_len, msg+4, sizeof(uint32_t));
	msg_ctrl->real_len = ntohl(tmp_len);

	// 内容
	memcpy(&msg_ctrl->payload, msg+MSG_HEAD_LEN, msg_ctrl->real_len);
	return 0;
}


// 打印收到的报文
static int 
print_msg(const uint8_t *msg, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_HOST_FILTER, "a+");
	if (NULL == fp) {
		log_host(LOG_ERR, "fopen() errors:%s\n", strerror(errno));
		return -1;
	}
	
	//fputs((char *)msg, fp);
	fwrite(msg, sizeof(uint8_t), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}


// 校验报文内容
static int 
check_msg(const uint8_t *msg, size_t len) 
{	
	// 报文尾
	uint8_t tail_flag = msg[len-1];
	if (MSG_TAIL_FLAG != tail_flag) {
		log_host(LOG_ERR, "The msg tail flag [%02X] isn't [%02X], check error!", 
			tail_flag, MSG_TAIL_FLAG);
		return -1;
	} 	

	size_t msg_len = len-MSG_HEAD_LEN-MSG_TAIL_LEN;
	
	// 内容校验和
	uint8_t checksum = msg[MSG_HEAD_LEN];
	for (int i = 1; i < msg_len; i++) {
		checksum ^= msg[MSG_HEAD_LEN+i];		
	}

	if (msg[len-2] != checksum) {
		log_host(LOG_ERR, "The msg checksum [%d]---[%d] isn't equal!", 
				checksum, msg[len-2]);
		//return -1;		
	}

	return 0;
}


// 报文内容过滤规则
static int 
filter_msg(const uint8_t *msg, size_t len)
{
	int ret = 0;
	char alarm[FILTER_LEN]  = {0};
	char date[FILTER_LEN]  	= {0};
	char time[FILTER_LEN]	= {0};
	char dname[FILTER_LEN]	= {0};
	char dtype[FILTER_LEN]	= {0};
	int  ltype, stype;
	
	ret = sscanf((const char *)msg, 
				"%64s %64s %64s %64s %64s %d %d", 
				alarm, date, time, dname, dtype, &ltype, &stype);
	if (!(ret == EOF || ret <= 0) && ret == 7) {
		if (strlen(alarm) != 3 	||
			alarm[0] != '<' 	|| 
			alarm[2] != '>' 	|| 
			!(alarm[1] >='0' && alarm[1]<='3')) {
			log_host(LOG_ERR, "alarm format[%s] error", alarm);
			return -1;
		}

		if (strlen(date) != 10) {
			log_host(LOG_ERR, "date format[%s] error", date);
			return -1;
		}

		if (strlen(time) != 8) {
			printf("time format[%s] error\n", time);
			return -1;
		}

		if (strncmp(dtype, DTYPE_HOST, strlen(dtype))) {
			log_host(LOG_ERR, "device type format[%s] error", dtype);
			return -1;
		}

		if (stype < 17) {
			return MSG_NEED_CHANGE;
		}
		
		return 0;
	}

	return -1;
}


static int 
change_msg(uint8_t *msg, size_t len) 
{
	int  index = 0;

	char tmp_msg[BUFFER_SIZE] = {0};
	memcpy(tmp_msg, msg, len);
	//log_host(LOG_DEBUG, "msg-change-before, len[%zu], msg[%s]", len, (char *)msg);

	char *pch, *pch2;
	pch = pch2 = strtok(tmp_msg, " ");
	while (pch != NULL) {			
		if ( ++index == 7 ) { 
			if ( atol(pch) >= 17 ) return 0;
			else pch2 = pch;	
		}	

		if ( index == 8 ) { 
			memset (msg + (pch2-tmp_msg), ' ', pch-pch2);		 
			memmove(msg + (pch2-tmp_msg), "4", 1); 	
			break;
		}	
		pch = strtok(NULL, " ");
	} 

	//log_host(LOG_DEBUG, "msg-change-end, len[%zu], msg[%s]", len, (char*)msg);
	return 0;
}

// 处理下行报文
static int 
process_downlink_msg(const Msg_Ctrl *msg_ctrl, IC_Clnt_Info *clnt_info) 
{
	if ( NULL == msg_ctrl || NULL == clnt_info) {
		log_host(LOG_ERR, "process_downlink_msg() args are illegal");
		return -1;
	}
	
	size_t pack_len = msg_ctrl->real_len + MSG_HEAD_LEN + MSG_TAIL_LEN;
	if ( pack_len > BUFFER_SIZE) {
		log_host(LOG_ERR, "packet len %zu is larger than MAX BUFFER SIZE %d", 
			pack_len, BUFFER_SIZE);	
		return -1;
	}
	clnt_info->send_len = pack_len;

	uint8_t* str_pack = clnt_info->send_buffer;
	memset(str_pack, 0x00, BUFFER_SIZE);

	// 报文头[ 报文标识(1)+报文类型(1)+参数(2)+报文内容长度(4) ]
	str_pack[0] = MSG_HEAD_FLAG;
	str_pack[1] = msg_ctrl->msg_type;

	// 参数
	uint16_t msg_arg = htons(msg_ctrl->msg_arg);
	memcpy(str_pack+2, &msg_arg, sizeof(uint16_t));
	
	// 报文内容长度
	uint32_t msg_len = htonl(msg_ctrl->real_len);
	memcpy(str_pack+4, &msg_len, sizeof(msg_len));

	//log_host(LOG_DEBUG, "str_pack00:[%"PRIu8"]-[%"PRIu16"]-[%"PRIu16"]\n", 
	//		str_pack[0], len, msg_len);

	// 报文内容
	memcpy(str_pack+MSG_HEAD_LEN, msg_ctrl->payload, msg_ctrl->real_len);
	
	// 内容校验和
	uint8_t checksum = msg_ctrl->payload[0];
	for (int i = 1; i < msg_ctrl->real_len; i++) {
		checksum ^= msg_ctrl->payload[i];		
	}
	
	// 报文尾[ 校验和(1)+报文尾(1) ]
	str_pack[pack_len-2] = checksum;	
	str_pack[pack_len-1] = MSG_TAIL_FLAG;
	
	print_buf(str_pack, pack_len);
	//log_host(LOG_DEBUG, "checksum: [%d]-[%d]-->[%d]\n", 
	//	msg_ctrl->payload[0], msg_ctrl->payload[msg_ctrl->real_len-1], checksum);
	log_host(LOG_DEBUG, "message: %*s", (int)msg_ctrl->real_len, msg_ctrl->payload);

	return 0;
}


// 测试控制函数
void* ctrl_fun_test(void* arg) 
{
	int ret = 0;

while ( !psrv_info->should_stop ) {

	/*
	for (int i=0; i < g_clnt_count; i++) {
		
		char *str_ip = (char*)g_clnt_info[i].str_ip;
		if (strlen(str_ip) == 0) {
			continue;
		}	

		Msg_Ctrl msg_ctrl, rmsg_ctrl;
		memset(&msg_ctrl, 0x00, sizeof(msg_ctrl));

		// 参数查看.....
		memcpy(msg_ctrl.str_ip, g_clnt_info[i].str_ip, MAX_IP_LEN);
		msg_ctrl.msg_type = MTYPE_ARG_CHECK;
		msg_ctrl.msg_arg  = ARG_LIST_NET_CONN;
		msg_ctrl.real_len = 0;
		memset(msg_ctrl.payload, 0x00, sizeof(msg_ctrl.payload));  

		log_host(LOG_DEBUG, "host_ctrl_opr() start......");
		ret = host_ctrl_opr(&msg_ctrl, &rmsg_ctrl);
		if (ret != 0) {
			printf("host_ctrl_opr() error\n" );
			break;
		}
		log_host(LOG_DEBUG,  "host_ctrl_opr() end......");
		sleep(10);
	} */

	sleep(2);

}

	return NULL;
}


