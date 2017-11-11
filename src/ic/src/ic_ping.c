/** @file ic_ping.h **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#include "ic_public.h"

#define PING_TIMES		5
#define HOST_IP_SZ		64
#define MAX_CMD_SZ    	256 
#define BUFFER_SZ		128
#define MAX_BUFFER_SZ	1024

#define BUFFER_COUNT		200
#define MAX_THREAD_COUNT	50
#define DEFAULT_PING_TIME   20

#define DTYPE_PING		"PI"
#define IC_PING_FILE 	"/var/log/ic_ping.log"

#define PING_HOST_SUCC  	0
#define PING_HOST_FAIL  	1
#define NETWORK_UNREACH   	2	

struct process_info {
	int 	count;
	char *	pindex[10];
};

struct message_info {
	int 	count;
	char    buffer[BUFFER_COUNT][BUFFER_SZ+1];
};

struct ic_hosts_info {
	int 	thread_cnt;
	int 	exit_cnt;
	int 	should_stop;
	int 	b_block;
	int 	b_upload_exit;
	char ** hosts;
	int 	host_cnt;
	pthread_t * pthread_id;
	pthread_t   thread_up;
	pthread_mutex_t mutex;
	sem_t		semwait;
};

static struct process_info  * pprocess_info;
static struct ic_hosts_info   g_host_info; 
static struct message_info    g_message_info;

int ic_ping_init(void);
int ic_ping_deinit(void);

void* handle_hosts(void* arg);
void* upload_hosts(void* arg);
int ping_host(const char *host, int len);
int gen_message(const char *host, int result);
int print_message(const char *message, size_t len);

static void 
log_ping(int level, const char *msg, ...);


int main(int argc, char *argv[])
{
	int res = 0;
	res = ic_ping_init();
	if ( res < 0 ) {
		log_ping(LOG_ERR, "ic_network_init() error");
		exit(-1);
	}	

	while ( 1 ) {
		char c = getchar();
		//log_ping(LOG_NOTICE, "get %c", c );
		if ('q' == c) { break; }
	}

	g_host_info.should_stop = 1;
	while (g_host_info.exit_cnt != g_host_info.thread_cnt) {
		sleep(2);
		log_ping(LOG_NOTICE, "thread exit count[%d]...", g_host_info.exit_cnt);	
	}
	g_host_info.b_upload_exit = 1;
	
	res = ic_ping_deinit();
	if ( res < 0 ) {
		log_ping(LOG_ERR, "ic_ping_deinit() error");
		exit(-1);
	}

	return 0;
}

int ic_ping_init(void)
{
	int ret = 0;
	open_syslog("ic", LOG_CONS | LOG_PID, LOGGER_TYPE);

	memset(&g_host_info, 0x00, sizeof(g_host_info));

	char *IC_HOST_IPS = getenv("HOST_IPS");
	if ( NULL == IC_HOST_IPS) {
		log_ping(LOG_ERR, "getenv() error[%s]", strerror(errno));
		return -1;
	}
	
	// 获取主机数
	size_t lines = 0;
	ret = GetFileLines(IC_HOST_IPS, &lines);	
	if ( ret < 0) {
		log_ping(LOG_ERR, "GetFileLines() error");
		return -1;
	}	
	
	g_host_info.host_cnt   = lines;
	g_host_info.thread_cnt = (lines < MAX_THREAD_COUNT ? lines : MAX_THREAD_COUNT);
	log_ping(LOG_INFO, "host_cnt[%d]--thread_cnt[%d]", g_host_info.host_cnt, g_host_info.thread_cnt);

	// 线程对应数组信息
	pprocess_info = (struct process_info *)malloc(g_host_info.thread_cnt * sizeof(struct process_info));
	if ( NULL == pprocess_info ) {
		log_ping(LOG_ERR, "pprocess_info malloc() error");
		return -1;
	}

	// 主机数据存入buffer
	g_host_info.hosts = (char **)malloc( g_host_info.host_cnt * sizeof(char*) );
	if ( NULL == g_host_info.hosts ) {
		log_ping(LOG_ERR, "g_host_info.hosts malloc() error");
		return -1;
	}
	
	FILE *fp = fopen(IC_HOST_IPS, "r");
	if (NULL == fp) {
		log_ping(LOG_ERR, "fopen() %s error info:%s", IC_HOST_IPS, strerror(errno));
		return -1;
	}

	int index = 0, index2 = -1;
	char buffer[HOST_IP_SZ+1] = {0};
	while ( index < g_host_info.host_cnt ) {
		if (fgets(buffer, HOST_IP_SZ, fp) == NULL) {
			break;
		}
		
		EraseInValidChar(buffer);
		Trim2(buffer);
		g_host_info.hosts[index] = strdup(buffer);

		int cur_thread_index = index % g_host_info.thread_cnt;
		if ( cur_thread_index == 0) {
			index2++;	
		}		
		pprocess_info[cur_thread_index].pindex[index2] = g_host_info.hosts[index];
		pprocess_info[cur_thread_index].count = (index2 + 1);
		
		index++;
	}	
	fclose(fp);

/*
	// test info.......
	for(int i = 0; i < g_host_info.thread_cnt; i++) {
		printf( "thread_cnt[%d]:\n", i );
		for ( int j=0; j < (pprocess_info+i)->count; j++) {
			printf("%s\n", (pprocess_info+i)->pindex[j]);
		}
		printf("\n\n");
	}	
*/

	g_host_info.should_stop = 0;
	pthread_mutex_init(&g_host_info.mutex, NULL);
	
	if (sem_init(&g_host_info.semwait, 0, 0) < 0) {
		log_ping(LOG_ERR, "sem_init() error[%s]", strerror(errno));
		return -1;
	}
	
	// 创建ping处理线程
	g_host_info.pthread_id = (pthread_t *)malloc(sizeof(pthread_t) * g_host_info.thread_cnt);
	if ( NULL == g_host_info.pthread_id ) {
		log_ping(LOG_ERR, "g_host_info.pthread_id malloc() error");
		return -1;
	} 
	memset(g_host_info.pthread_id, 0x00, sizeof(pthread_t) * g_host_info.thread_cnt);

	for(int i = 0; i < g_host_info.thread_cnt; i++) {
		pthread_create( &g_host_info.pthread_id[i], NULL, handle_hosts, (void *)(pprocess_info+i) );
	}

	// 创建数据上传线程
	pthread_create(&g_host_info.thread_up, NULL, upload_hosts, (void *)&g_message_info);

	return 0;
}


int ic_ping_deinit(void)
{
	for(int i = 0; i < g_host_info.thread_cnt; i++) {
		pthread_join( g_host_info.pthread_id[i], NULL );
	}
	sleep(2);
	
	pthread_join( g_host_info.thread_up, NULL );

	sem_destroy( &g_host_info.semwait );
	pthread_mutex_destroy( &g_host_info.mutex );

	safeFree( g_host_info.pthread_id );
	safeFree( pprocess_info );

	for(int i = 0; i < g_host_info.host_cnt; i++) {
		safeFree(g_host_info.hosts[i]);
	}
	safeFree( g_host_info.hosts );
	
	return 0;
}

static void log_ping(int level, const char *msg, ...)
{
	char buf[LOG_MSG_LEN];
	va_list ap;
	va_start(ap, msg);
	vsnprintf(buf, LOG_MSG_LEN, msg, ap);
	va_end(ap);

	syslog( LOGGER_TYPE | level,  "[ic_ping] %s",  buf);
}

void* handle_hosts(void* arg) 
{
	struct process_info * processinfo = (struct process_info *)arg;

	int ret = 0;
	while ( !g_host_info.should_stop ) {
		for (int i = 0; i < processinfo->count; i++) {
			ret = ping_host(processinfo->pindex[i], strlen(processinfo->pindex[i]));
			if (ret < 0) {
				log_ping(LOG_ERR,  "ping_host() error");
				break;
			}
			
			// 上传ping的结果......
			gen_message(processinfo->pindex[i], ret);
		}		
		sleep(DEFAULT_PING_TIME);
	}
	
	pthread_mutex_lock(&g_host_info.mutex);
	g_host_info.exit_cnt++;	
	pthread_mutex_unlock(&g_host_info.mutex);	
	
	return NULL;
}


void* upload_hosts(void* arg) 
{
	while ( !g_host_info.b_upload_exit ) {

		if (g_message_info.count < BUFFER_COUNT) {
			sleep(2); continue;
		}
		
		for (int i = 0; i < g_message_info.count; i++) {
			// 打印消息.....
			print_message(g_message_info.buffer[i], strlen(g_message_info.buffer[i]));	
		
			// 采集接口上传
			#if HAVE_BASE_H
			int  ret = 0;
			ret = pub_device_msg(PUB_NAME, g_message_info.buffer[i]);
			if (ret != 0) {
				log_ping(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
				return NULL;
			} 
			#endif
		}

		memset(&g_message_info, 0x00, sizeof(g_message_info));
		// wake up thread.......
		sem_post(&g_host_info.semwait);
		
		//g_host_info.should_stop = 1;
		//log_ping(LOG_DEBUG, "current ping finished......");
		//return NULL;
	}


	// 处理线程全部退出之后，剩余未长传的数据进行上传........
	for (int i = 0; i < g_message_info.count; i++) {
		// 打印消息.....
		print_message(g_message_info.buffer[i], strlen(g_message_info.buffer[i]));	
	
		// 采集接口上传
		#if HAVE_BASE_H
		int  ret = 0;
		ret = pub_device_msg(PUB_NAME, g_message_info.buffer[i]);
		if (ret != 0) {
			log_ping(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
			return NULL;
		} 
		#endif
	}
	memset(&g_message_info, 0x00, sizeof(g_message_info));

	log_ping(LOG_NOTICE, "upload thread exit......");
	return NULL;
}


int ping_host(const char *host, int len)
{
	int ret = 0;
	if (NULL == host || len > MAX_CMD_SZ) {
		log_ping(LOG_ERR, "ping_host args invalid");	
		return -1;
	}

	char strHosts[MAX_CMD_SZ+1] = {0};
	//memcpy(strHosts, host, sizeof(strHosts)-1);
	memcpy(strHosts, host, strlen(host)+1);

	char strCmd[MAX_CMD_SZ+1] = {0};
	snprintf( strCmd, sizeof(strCmd),
		"ping -c %d %s",
		PING_TIMES,
		Trim2(strHosts) );
	//log_ping(LOG_DEBUG,  "strCmd[%s]", strCmd );

	char buffer[MAX_BUFFER_SZ+1] = {0};
	ret = ExeSysCmd2(strCmd, buffer, sizeof(buffer));
	if (ret != 0) {
		log_ping(LOG_ERR, "ExeSysCmd2() error.");
		return -1;
	}

	// 分析命令返回结果......
	//printf("buffer: [%s]\n", buffer);	
	if (strlen(buffer) == 0 ) {
		log_ping(LOG_ERR, "connect: Network is unreachable ");	
		return NETWORK_UNREACH;
	}
	
	char strsub[MAX_BUFFER_SZ+1] = {0};
	snprintf(strsub, sizeof(strsub), 
		"%d packets transmitted,", PING_TIMES);

	char *pch, *pch2;
	pch = strstr(buffer, strsub);
	if (NULL == pch) {
		log_ping(LOG_ERR, "parse cmd error[%s]", buffer);
		return -1;	
	}
	pch += strlen(strsub);

	pch2 = strchr(pch+1, '\n');
	if (NULL == pch2) {
		log_ping(LOG_ERR, "parse cmd error[%s]", pch);
		return -1;	
	}
	snprintf(strCmd, sizeof(strCmd), "%*s", 
		(int)(pch2-pch), pch);		

	int recv;
	char filter1[MAX_CMD_SZ+1], filter2[MAX_CMD_SZ+1];
	ret = sscanf(strCmd, "%d %s %s", &recv, filter1, filter2);
	if ( ret != 3) {
		log_ping(LOG_ERR, "sscanf parse cmd error[%s]", strCmd);	
		return -1;
	}

	//log_ping(LOG_DEBUG, "recv[%d], filter1[%s], filter2[%s]", 
	//	recv, filter1, filter2);

	if ( recv <= 0 || !strncmp(filter2, "100%", 2)) {
		return PING_HOST_FAIL;
	}

	return PING_HOST_SUCC;
}	


// 生成消息
int gen_message(const char *host, int result)

{
	char datetime[19+1] = {0};
	char *ptime = Get19DateTime(GetNowDateTime());
	memcpy(datetime, ptime, sizeof(datetime));

	int warn_level  = 2;	
	int log_type	= 1;
	int log_stype	= 3;
	const char *device_name = "NARI"; 	// 设备名称怎么获得?.......

	warn_level = (result == 0 ? 2: 1);

	char buffer[MAX_BUFFER_SZ+1] = {0};

	snprintf(buffer, sizeof(buffer), 
			"<%d> %s %s %s %d %d %s %d\n", 
			 warn_level, 
			 ptime, 
			 device_name, 
			 DTYPE_PING, 
			 log_type, 
			 log_stype,
			 host, 
			 result );	

	pthread_mutex_lock(&g_host_info.mutex);
	
	while (g_message_info.count >= BUFFER_COUNT) {
		// block wait.....
		log_ping(LOG_DEBUG, "thread_block.....");
		g_host_info.b_block = 1;
		sem_wait(&g_host_info.semwait);
		log_ping(LOG_DEBUG, "thread_block release.....");
		g_host_info.b_block = 0;
	}
	
	g_message_info.count++;	
	memcpy(g_message_info.buffer[g_message_info.count-1], buffer, BUFFER_SZ);
	//log_ping(LOG_DEBUG,  "g_message_info.count[%d]", g_message_info.count );
	
	pthread_mutex_unlock(&g_host_info.mutex);
	return 0;
}


// 打印收到的消息
int print_message(const        char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_PING_FILE, "a+");
	if (NULL == fp) {
		log_ping(LOG_ERR, "fopen() errors:%s\n", strerror(errno));
		return -1;
	}
	
	fputs((char *)message, fp);
	//fwrite(message, sizeof(char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}


