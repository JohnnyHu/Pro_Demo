#ifndef _BASE_H_
#define _BASE_H_

#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<time.h>
#include<hiredis/hiredis.h>
#include<json/json.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "re_cache.h"

#ifdef __cplusplus
}
#endif


#define sms_strncpy(dst_str, src_str, dst_str_len) do {\
	if(dst_str_len > 0) {\
		strncpy((dst_str), (src_str), (dst_str_len)-1);\
		(dst_str)[(dst_str_len)-1] = '\0';\
	}\
}while(0)

#define OK 0
#define ERROR -1

#define IP "127.0.0.1"
#define PORT 6514

#define WARN_LIST "warn:msg:list"
#define PUB_NAME "Dev_MSG"
#define SUB_NAME "Dev_MSG"
#define BUF_LEN   1024*1024*3
#define SMALL_BUF_LEN 1014
struct ntp_info {
	char mast_mast_ip[16];
	char mast_slav_ip[16];
	char slav_mast_ip[16];
	char slav_slav_ip[16];
	int port;
	int time;
	int status;/*off is 0,on is 1*/
	int id;
};

struct net_info{
	int id;
	char name[8];
	char ip[16];
	char mask[16];
};

struct route_info{	
	int id;
	int status;/*off is 0,on is 1*/
	char dest_ip[16];
	char gate_ip[16];
	char dest_mask[16];	
};

struct comm_info{
	int id;
    int tcp_port;
    int syslog_port;
	int snmp_port;
	int master_port;
	int agent_port;
	char master_ip[16];
	char serv_ip1[16];
	char serv_ip2[16];
};

struct event_info{
    char cpu_limit[8];
    char mem_limit[8];
	int trf_limit;
	int id;
	int login_limit;
	int merg_time;
};

/*Free the memory which was both malloced and not NULL.*/
int free_mem(char* buf);

/*Pub the collected device message to redis server,the second arg should be "PUB_NAME".*/
int pub_device_msg(char *name, char *msg);

int logd_syslog_send(char *msg);

/*To put warning message into redis,the first arg should be "WARN_LIST".*/
int set_warn_msg(char *name, char *buf, int msg_len);

/*Get warning message from redis.*/
char *get_warnmsg_by_count(int *len, int count);
char *get_warnmsg_by_time(int *len, time_t *start, time_t *end);
char *get_warnmsg_by_time_and_count(int *len, int count, time_t *start, time_t *end);

/*Set config into redis.*/
int set_net_config(char *name,  struct net_info* tmp);
int set_rout_config(int id, struct route_info* tmp);
int set_ntp_config(struct ntp_info *p);
int set_comm_config(struct comm_info* tmp);
int set_event_config(struct event_info* tmp);

/*Get the count of net or route which in redis.If want to get the count of net,the first arg key
	should be "net_config",else the value should be "route_config". */
int get_count(char *key, int* count);

/*Get config from redis.*/
int get_ntp_config(struct ntp_info *ntp);
int get_event_config(struct event_info *event);
int get_comm_config(struct comm_info *comm);
int get_net_config(struct net_info **net);
int get_route_config(struct route_info **route);

#endif
