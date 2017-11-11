/** @file ic_network.c **/

/************************************************
 * 网口索引[ifIndex]		: 1.3.6.1.2.1.2.2.1.1
 * 网口描述[ifDescr]		: 1.3.6.1.2.1.2.2.1.2
 * 网口类型[ifType] 		: 1.3.6.1.2.1.2.2.1.3
 * 网口状态[ifOperStatus]	: 1.3.6.1.2.1.2.2.1.8
 ************************************************
 * 端口号[dot1dBasePort] : 1.3.6.1.2.1.17.1.4.1.1
 * 端口号与网口索引的映射: 1.3.6.1.2.1.17.1.4.1.2
 **** dot1dTpFdbTable ****
 * MAC地址信息				: 1.3.6.1.2.1.17.4.3.1.1
 * MAC地址的端口索引			: 1.3.6.1.2.1.17.4.3.1.2
 * MAC地址的端口状态			: 1.3.6.1.2.1.17.4.3.1.3 
**/

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>

#include "ic_public.h"

#define MAX_COUNT		100
#define BUFFER_SZ		512
#define MAX_BUFFER_SZ	1024
#define MAC_ADDR_LEN	(6*4)

#define DEFAULT_NET_TIME	5		// 5秒钟
#define DEFAULT_MAC_TIME	60		// 60秒钟
//#define DEFAULT_MAC_TIME	3600	// 60分钟

/*
#define AUTH_PROTOCOL_MD5	"MD5"
#define AUTH_PROTOCOL_SHA	"SHA"
#define PRIV_PROTOCOL_DES	"DES"
#define PRIV_PROTOCOL_AES	"AES"
#define SEC_LEVEL_AP		"authPriv"
#define SEC_LEVEL_ANOP		"authNoPriv"
#define SEC_LEVEL_NOANOP	"noAuthNoPriv"
*/

#define DTYPE_NETWORK		"SW"
#define DEVICE_TYPES		"FW FID BID SVR SW VEAD"
#define IC_NETWORK_FILE 	"/var/log/ic_network.log"

enum secur_level {
    SEC_LEVEL_AP = 1,
    SEC_LEVEL_ANOP = 2,
    SEC_LEVEL_NOANOP = 3
};
enum auth_protocol {
    AUTH_PROTOCOL_MD5 = 1,
    AUTH_PROTOCOL_SHA = 2
};
enum priv_protocol {
    PRIV_PROTOCOL_DES = 1,
    PRIV_PROTOCOL_AES = 2
};
typedef struct query_host {
	char 	name[BUFFER_SZ+1];
	int		version;
	char 	community[BUFFER_SZ+1];
	char 	user[BUFFER_SZ+1];
	enum secur_level   sec_level;
	enum auth_protocol auth_proto;
	enum priv_protocol priv_proto;
	char	auth_passwd[BUFFER_SZ+1];
	char	priv_passwd[BUFFER_SZ+1];
	time_t	net_seconds;
	time_t	mac_seconds;
}QUERY_HOST;

typedef struct query_variable {
	char 	name[BUFFER_SZ+1];
	oid 	varoid[MAX_OID_LEN];
	size_t 	varoid_len;
}QUERY_VARIABLE;

typedef struct session {
	struct snmp_session 	*sess;		
	struct query_variable 	*cur_var;
} SESSION;

// 网口关系表 
typedef struct IF_Relation {
	int 	index;				// 网口索引  
	char	desc[BUFFER_SZ+1];	// 网口描述
	int 	type;				// 网口类型
	int 	status;				// 网口状态
} IF_RELATIONS;

// 端口关系表 
typedef struct Port_Relation {
	int		port;				// 端口号[索引]
	int		if_index;			// 与网口的映射
	int 	status;				// 端口状态
} PORT_RELATIONS;

// MAC地址关系表
typedef struct mac_Relation {
	int		port;				// 端口号[索引]
	char 	mac[MAC_ADDR_LEN+1];// MAC地址
	oid 	varoid[MAX_OID_LEN];
	size_t 	varoid_len;
}MAC_RELATIONS;

// 待查询的网口数据 
static QUERY_VARIABLE query_variables[] = {
	{ "1.3.6.1.2.1.2.2.1.1" },
	{ "1.3.6.1.2.1.2.2.1.2" },
	{ "1.3.6.1.2.1.2.2.1.3" },
	{ "1.3.6.1.2.1.2.2.1.8" },
	{ ""				    }
};

// 待查询的端口数据 
static QUERY_VARIABLE query_variables2[] = {
	{ "1.3.6.1.2.1.17.1.4.1.1" },
	{ "1.3.6.1.2.1.17.1.4.1.2" },
	{ ""				       }
};

// 待查询的MAC数据 
static QUERY_VARIABLE query_variables3[] = {
	{ "1.3.6.1.2.1.17.4.3.1.1" },
	{ "1.3.6.1.2.1.17.4.3.1.2" },
	{ "1.3.6.1.2.1.17.4.3.1.3" },
	{ ""				       }
};

// 网口表-端口表-MAC表计数
static size_t g_if_count 	= 0;
static size_t g_port_count 	= 0;
static size_t g_mac_count 	= 0;

static IF_RELATIONS 	if_relations[MAX_COUNT];
static PORT_RELATIONS 	port_relations[MAX_COUNT];
static MAC_RELATIONS 	mac_relations[MAX_COUNT*10];

static size_t g_host_count = 0;
static QUERY_HOST * g_pquery_host = NULL; 

int ic_network_init(void);
int ic_network_deinit(void);
int read_host_info_syn(void);

int print_message(
				const char * message, size_t len); 

int gen_message_netsatus(
				IF_RELATIONS	 ifs[],   size_t len_if,
				PORT_RELATIONS   ports[], size_t len_port);

int gen_message_macbind(
				PORT_RELATIONS ports[], size_t len_port, 
				MAC_RELATIONS  macs[],  size_t len_mac );

static int parse_network_info(const char *record, QUERY_HOST *qhost);
static int assign_val(int index, char *str, QUERY_HOST *qhost);
static int set_session_val(const QUERY_HOST *qhost, struct snmp_session *session);
static void log_net(int level, const char *msg, ...);

static int comp(const void *a, const void *b)
{
	return ((MAC_RELATIONS *)a)->port - ((MAC_RELATIONS *)b)->port;
}

int ic_network_init(void)
{
	int ret = 0;
	open_syslog("ic", LOG_CONS | LOG_PID, LOGGER_TYPE);

	// 读取配置文件信息
	char *NETWORK_INFO = getenv("NETWORK_INFO");
	if ( NULL == NETWORK_INFO) {
		log_net(LOG_ERR, "getenv() error[%s]", strerror(errno));
		return -1;
	}	

	ret = GetFileLines(NETWORK_INFO, &g_host_count);	
	if ( ret < 0) {
		log_net(LOG_ERR, "GetFileLines() error");
		return -1;
	}	
	log_net(LOG_INFO, "[%s]--lines: %zu", NETWORK_INFO, g_host_count);

	g_pquery_host = (QUERY_HOST *)malloc(sizeof(QUERY_HOST) * g_host_count);
	if ( NULL == g_pquery_host ) {
		log_net(LOG_ERR,  "g_pquery_host malloc() error");
		return -1;
	} 
	memset(g_pquery_host, 0x00, sizeof(QUERY_HOST) * g_host_count);
	
	FILE *fp = fopen(NETWORK_INFO, "r");
	if (NULL == fp) {
		log_net(LOG_ERR, "fopen() %s error info:%s", NETWORK_INFO, strerror(errno));
		return -1;
	}	

	int index = 0;
	QUERY_HOST * pquery_host = g_pquery_host;
	char record[BUFFER_SZ+1] = {0};
	while (fgets(record, sizeof(record), fp) != NULL) {
		if (strlen(Trim2(record)) == 0) continue;
		if (++index > g_host_count) break;
	
		ret = parse_network_info(record, pquery_host);	
		if ( ret < 0) {
			log_net(LOG_ERR, "parse_network_info() error");
			fclose(fp);
			return -1;
		}
		
		pquery_host++; 
	}
	fclose(fp);

	/* Win32: init winsock */
	SOCK_STARTUP;

	/* initialize library */
	init_snmp("ic_network");

	struct query_variable *qvar = query_variables;
	/* parse the query_variables */
	while (qvar->name[0]) {
		qvar->varoid_len = sizeof(qvar->varoid)/sizeof(qvar->varoid[0]);
		if (!read_objid(qvar->name, qvar->varoid, &qvar->varoid_len)) {
			snmp_perror("read_objid() error");
			log_net(LOG_ERR, "qvar->name[%s]", qvar->name);
			exit(1);
		}
		qvar++;
	}

	qvar = query_variables2;
	/* parse the query_variables */
	while (qvar->name[0]) {
		qvar->varoid_len = sizeof(qvar->varoid)/sizeof(qvar->varoid[0]);
		if (!read_objid(qvar->name, qvar->varoid, &qvar->varoid_len)) {
			snmp_perror("read_objid() error");
			log_net(LOG_ERR, "qvar->name[%s]", qvar->name);
			exit(1);
		}
		qvar++;
	}

	qvar = query_variables3;
	/* parse the query_variables */
	while (qvar->name[0]) {
		qvar->varoid_len = sizeof(qvar->varoid)/sizeof(qvar->varoid[0]);
		if (!read_objid(qvar->name, qvar->varoid, &qvar->varoid_len)) {
			snmp_perror("read_objid() error");
			log_net(LOG_ERR, "qvar->name[%s]", qvar->name);
			exit(1);
		}
		qvar++;
	}

	struct query_host *hp;
	for (hp = g_pquery_host; hp->name[0]; hp++) {
		time(&hp->net_seconds);
		time(&hp->mac_seconds);
	}

	return 0;
}

int ic_network_deinit(void)
{

	/* cleanup */
	SOCK_CLEANUP;

	safeFree(g_pquery_host);
	return 0;
}

static void log_net(int level, const char *msg, ...)
{
	char buf[LOG_MSG_LEN];
	va_list ap;
	va_start(ap, msg);
	vsnprintf(buf, LOG_MSG_LEN, msg, ap);
	va_end(ap);
	syslog( LOGGER_TYPE | level,  "[ic_network] %s",  buf);
}


/* 同步获取Agent信息 */
int read_host_info_syn(void)
{
	int res = 0;
	static int b_print = 0;
	
	struct query_host *hp;
	for (int i = 0; i < g_host_count; i++ ){
		hp = g_pquery_host + i;

		time_t cur_seconds;
		time(&cur_seconds);

		int b_net = 0,  b_mac = 0;
		long interval = cur_seconds - hp->net_seconds;
		if (interval > DEFAULT_NET_TIME) {
			b_net = 1;
			hp->net_seconds = cur_seconds;
		}
		
		interval = cur_seconds - hp->mac_seconds;
		if (interval > DEFAULT_MAC_TIME) {
			b_mac = 1;
			hp->mac_seconds = cur_seconds;
		}
		
		struct snmp_session 	sess;
		struct snmp_session 	*psess;
		//struct query_variable	*qvar;

		/* 始化session */
		snmp_sess_init(&sess);	
		res = set_session_val(hp, &sess);
		if ( res < 0 ) {
			log_net(LOG_ERR, "set_session_val() error");
			return -1;
		}			

		/* open a session */
		if (!(psess = snmp_open(&sess))) {
			snmp_perror("snmp_open");
			continue;
		}

		g_if_count   = 0;
		g_port_count = 0;
		g_mac_count	 = 0;
		
		i = 0;
		netsnmp_variable_list *vars = NULL;

		// #################################查询网口表############################
		memset(&if_relations, 0x00, sizeof(if_relations));

		// 查询索引......
		netsnmp_variable_list *var_index = NULL;
		snmp_varlist_add_variable( &var_index, 
						query_variables[0].varoid, 
						query_variables[0].varoid_len,
						ASN_NULL, NULL,  0);
		netsnmp_query_walk( var_index, psess );		

		for (vars=var_index, i=0; vars && i<MAX_COUNT; 
						vars=vars->next_variable, i++) {

			if_relations[i].index = *(vars->val.integer);
			//printf("value: %d\n", if_relations[i].index);
			//print_variable(vars->name, vars->name_length, vars);
			g_if_count++;
		}
		if (var_index) {snmp_free_varbind(var_index); var_index = NULL;}
		

		// 网口描述......
		netsnmp_variable_list *var_desc = NULL;
		snmp_varlist_add_variable( &var_desc, 
						query_variables[1].varoid, 
						query_variables[1].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_desc, psess );		

		for (vars=var_desc, i=0; vars && i<g_if_count; 
						vars=vars->next_variable, i++) {
			memcpy( if_relations[i].desc, 
					vars->val.string, 
					sizeof(if_relations[i].desc)-1 );	
			//print_variable(vars->name, vars->name_length, vars);
		}
		if (var_desc) {snmp_free_varbind(var_desc); var_desc = NULL;}


		// 网口类型......		
		netsnmp_variable_list *var_type = NULL;
		snmp_varlist_add_variable( &var_type, 
						query_variables[2].varoid, 
						query_variables[2].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_type, psess );		

		for ( vars=var_type, i=0; vars && i<MAX_COUNT; 
						vars=vars->next_variable, i++) {

			if_relations[i].type = *(vars->val.integer);
			//print_variable(vars->name, vars->name_length, vars);
		}
		if (var_type) {snmp_free_varbind(var_type); var_type = NULL;}


		// 网口状态......
		netsnmp_variable_list *var_stat = NULL;
		snmp_varlist_add_variable( &var_stat, 
						query_variables[3].varoid, 
						query_variables[3].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_stat, psess );		

		for ( vars=var_stat, i=0; vars && i<MAX_COUNT; 
						vars=vars->next_variable, i++ ) {
							
			if_relations[i].status = *(vars->val.integer);
			//print_variable(vars->name, vars->name_length, vars);
		}
		if (var_stat) {snmp_free_varbind(var_stat); var_stat = NULL;}


		// #################################查询端口表############################
		memset(&port_relations, 0x00, sizeof(port_relations));
		
		// 端口号......
		netsnmp_variable_list *var_port = NULL;
		snmp_varlist_add_variable( &var_port, 
						query_variables2[0].varoid, 
						query_variables2[0].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_port, psess );	
		
		for (vars=var_port, i=0; vars && i<MAX_COUNT; 
						vars=vars->next_variable, i++) {
							
			port_relations[i].port =  *(vars->val.integer); 
			//print_variable(vars->name, vars->name_length, vars);
			g_port_count++;
		}
		if (var_port) { snmp_free_varbind(var_port); var_port = NULL; }
		
		// 与网口的映射......
		netsnmp_variable_list *var_mapping = NULL;
		snmp_varlist_add_variable( &var_mapping, 
						query_variables2[1].varoid, 
						query_variables2[1].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_mapping, psess );	
		
		for (vars=var_mapping, i=0; vars && i < g_port_count; 
						vars=vars->next_variable, i++) {
							
			port_relations[i].if_index =  *(vars->val.integer); 
			
			// test function....
			//printf("type: %d\n", vars->type);
			//print_variable(vars->name, vars->name_length, vars);
			//print_value(vars->name, vars->name_length, vars);
			
			//char buf[BUFFER_SZ] = {0};
			//snprint_value(buf, BUFFER_SZ, vars->name, vars->name_length, vars);
			//printf("%s", buf);
		}
		if (var_mapping) { snmp_free_varbind(var_mapping); var_mapping = NULL; }
		
		// 端口状态......
		//......
		

		// #################################查询MAC表############################
		memset(&mac_relations, 0x00, sizeof(mac_relations));

 		// Mac地址--->OID映射
		netsnmp_variable_list *var_mac = NULL;
		snmp_varlist_add_variable( &var_mac, 
						query_variables3[0].varoid, 
						query_variables3[0].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_mac, psess );	
		
		for (vars=var_mac, i=0; vars && i < MAX_COUNT*10; 
						vars=vars->next_variable, i++) {

			memmove(&mac_relations[i].varoid, 
					vars->name, 
					vars->name_length*sizeof(oid));	
			mac_relations[i].varoid_len = vars->name_length;
			
			snprint_hexstring(mac_relations[i].mac, sizeof(mac_relations[i].mac), 
					vars->val.bitstring, vars->val_len); 
			
			Trim(mac_relations[i].mac);
			for ( char *cp = mac_relations[i].mac; *cp; cp++ ) {
				if(*cp == ' ') { *cp = ':'; };
			}

			//print_variable(vars->name, vars->name_length, vars);
			//printf("buf: %s\n", mac_relations[i].mac);		
			g_mac_count++;	
		}
		if (var_mac) { snmp_free_varbind(var_mac); var_mac = NULL; }


 		// Mac地址--->Port号
		netsnmp_variable_list *var_mac_port = NULL;
		snmp_varlist_add_variable( &var_mac_port, 
						query_variables3[1].varoid, 
						query_variables3[1].varoid_len,
						ASN_NULL, NULL, 0);
		netsnmp_query_walk( var_mac_port, psess );	
		
		for (vars=var_mac_port, i=0; vars && i < g_mac_count; 
						vars=vars->next_variable, i++) {

			mac_relations[i].port = *(vars->val.integer); 
			//print_variable(vars->name, vars->name_length, vars);
		}
		if (var_mac_port) {snmp_free_varbind(var_mac_port); var_mac_port = NULL;}
		
		snmp_close(psess);


		// ###########################打印查询结果################################
		log_net(LOG_DEBUG,  "\n\n网口状态查询结果......");
		log_net(LOG_DEBUG,  "index\t\t type\t\t status\t\t desc\t\t");
		for ( i=0; i < g_if_count; i++ ) {
			log_net(LOG_ERR,  "%d\t\t %d\t\t %d\t\t %s\t\t ",
 					 if_relations[i].index, 
 					 if_relations[i].type,
 					 if_relations[i].status,
 					 if_relations[i].desc
				   );
 		}

		log_net(LOG_DEBUG,  "\n\n端口状态查询结果......");
		log_net(LOG_DEBUG,  "port\t\t if_index\t\t status\t\t ");
		for ( i=0; i < g_port_count; i++ ) {
			log_net(LOG_DEBUG,  "%d\t\t %d\t\t %d\t\t ",
 					 port_relations[i].port, 
 					 port_relations[i].if_index,
 					 port_relations[i].status
				   );
 		}

		log_net(LOG_DEBUG, "\n\nMAC状态查询结果......\n");
		log_net(LOG_DEBUG, "port\t\t  mac\t\t\n");
		qsort(mac_relations, g_mac_count, sizeof(MAC_RELATIONS), comp);
		for ( i=0; i < g_mac_count; i++ ) {
			log_net(LOG_DEBUG, "%d\t\t %s\t\t \n",
 					 mac_relations[i].port, 
 					 mac_relations[i].mac
				   );
 		}

		if (0 == b_print || b_net == 1) {
			gen_message_netsatus(if_relations, g_if_count, 
								port_relations, g_port_count);
		}

		if (0 == b_print || b_mac == 1) {
			gen_message_macbind(port_relations, g_port_count,
								mac_relations, g_mac_count);
		}
	
	}

	b_print = 1;
	return 0;
}


// 生成消息--->采集-网口状态
int gen_message_netsatus(
				IF_RELATIONS	 ifs[],   size_t len_if,
				PORT_RELATIONS   ports[], size_t len_port)
{
	char datetime[19+1] = {0};
	char *ptime = Get19DateTime(GetNowDateTime());
	memcpy(datetime, ptime, sizeof(datetime));

	int warn_level  = 2;	
	int log_type	= 1;
	int log_stype	= 2;
	const char *device_name = "NARI"; 	// 设备名称怎么获得?.......

	char buffer[MAX_BUFFER_SZ+1] = {0};
	char interfaces[BUFFER_SZ+1] = {0};
	char status[10+1] = {0};

	for ( int i = 0; i < len_port; i++ ) {
		if (ports[i].port == 0 ) {
			continue;
		}
		
		int j = 0;
		for ( j = 0; j < len_if; j++ ) {
			if (ifs[j].index == ports[i].if_index) {
				ports[i].status = ifs[j].status;
				break;
			}
		} 
		if (j >= len_if) { printf( "find index error\n"); }

		snprintf( status, sizeof(status), "%d-%d ", 
 				 ports[i].port,
 				 ports[i].status );	
		strncat(interfaces, status, strlen(status));
	}
	
	snprintf(buffer, sizeof(buffer), 
			"<%d> %s %s %s %d %d %s\n", 
			 warn_level, 
			 ptime, 
			 device_name, 
			 DTYPE_NETWORK, 
			 log_type, 
			 log_stype,
			 interfaces);	

	// 打印消息.....
	print_message(buffer, strlen(buffer));

	// 采集接口上传
	// .......
#if HAVE_BASE_H
	int  ret = 0;
	ret = pub_device_msg(PUB_NAME, buffer);
	if (ret != 0) {
		log_net(LOG_ERR, "pub_device_msg() error[%d]!!!\n", ret);
		return -1;
	} 
#endif	


	return 0;
}


// 生成消息--->采集-绑定端口号
int gen_message_macbind(
				PORT_RELATIONS ports[], size_t len_port, 
				MAC_RELATIONS  macs[],  size_t len_mac )
{
	char datetime[19+1] = {0};
	char *ptime = Get19DateTime(GetNowDateTime());
	memcpy(datetime, ptime, sizeof(datetime));

	int warn_level  = 2;	
	int log_type	= 1;
	int log_stype	= 3;
	const char *device_name = "NARI"; 	// 设备名称怎么获得?.......

	char buffer[MAX_BUFFER_SZ+1] = {0};
	char interfaces[BUFFER_SZ+1]  = {0};
	char strmac[BUFFER_SZ+1] = {0};

	int i = 0, flag = 0, pre_port = 0;
	for ( i = 0; i < len_mac; i++ ) {

		if ( pre_port != macs[i].port ) {
			flag = 0;
		}
		
		if (flag == 0) {
			snprintf(strmac, sizeof(strmac), " %d %s", 
					 macs[i].port,
					 macs[i].mac);	
			strncat(interfaces, strmac, strlen(strmac));
			flag = 1;
		}
		else {
			snprintf(strmac, sizeof(strmac), "&%s", 
					  macs[i].mac);	
			strncat(interfaces, strmac, strlen(strmac));
		}

		pre_port = macs[i].port;
	}


	snprintf(buffer, sizeof(buffer), 
			"<%d> %s %s %s %d %d %s\n", 
			 warn_level, 
			 ptime, 
			 device_name, 
			 DTYPE_NETWORK, 
			 log_type, 
			 log_stype,
			 interfaces);	

	// 打印消息.....
	print_message(buffer, strlen(buffer));

	// 采集接口上传
#if HAVE_BASE_H
	int  ret = 0;
	ret = pub_device_msg(PUB_NAME, buffer);
	if (ret != 0) {
		log_net(LOG_ERR, "pub_device_msg() error[%d]!!!", ret);
		return -1;
	} 
#endif	

	return 0;
}


// 打印收到的消息
int print_message(const        char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(IC_NETWORK_FILE, "a+");
	if (NULL == fp) {
		log_net(LOG_ERR, "fopen() errors:%s", strerror(errno));
		return -1;
	}
	
	fputs((char *)message, fp);
	//fwrite(message, sizeof(char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}

//ip|@|version|@|community|@|user|@|sec_level|@|auth_proto|@|priv_proto|@|auth_passwd|@|priv_passwd|@|
static int parse_network_info(const char *record, QUERY_HOST *qhost)
{
	if (NULL == record || NULL == qhost) {
		log_net(LOG_ERR, "parse_network_info() has invalided argument");
		return -1;
	}

	size_t len  = 0; 
	size_t index = 0;

	const char *pstr = record;
	const char *pindex = NULL;

	char *flag = "|@|";
	char buf[BUFFER_SZ+1] = {0};

	do {
		++index;
		pindex = strstr( pstr, flag );
		if ( NULL == pindex ) {
			snprintf( buf, BUFFER_SZ, "%s", pstr );
			assign_val( index, buf, qhost );	
			break;
		}
		
		size_t cur_len = pindex - pstr + 1;
		len = cur_len < BUFFER_SZ ? cur_len : BUFFER_SZ;
		snprintf( buf, len, "%s", pstr);
		
		assign_val( index, buf, qhost );	

		pstr = pindex + 3;
	} while ( NULL != pindex );

	log_net(LOG_ERR, "name=[%s],version=[%d],community=[%s],user=[%s],sec_level=[%d],"
			"auth_proto=[%d],priv_proto=[%d],auth_passwd=[%s],priv_passwd=[%s]\n",
			qhost->name,
			qhost->version,
			qhost->community,
			qhost->user,
			qhost->sec_level,
			qhost->auth_proto,
			qhost->priv_proto,
			qhost->auth_passwd,
			qhost->priv_passwd
		);

	return 0;
}
static int assign_val( int index, char *str, QUERY_HOST *qhost )
{
	int nvalue = atoi(str);

	if ( 1 == index ) 
		memcpy(qhost->name, str, sizeof(qhost->name)-1 );	
	else if ( 2 == index )
		qhost->version = nvalue;
	else if ( 3 == index )
		memcpy(qhost->community, str, sizeof(qhost->community)-1 );	
	else if ( 4 == index )
		memcpy(qhost->user, str, sizeof(qhost->user)-1 );	
	else if ( 5 == index )
		qhost->sec_level = (enum secur_level)nvalue;
	else if ( 6 == index )
		qhost->auth_proto = (enum auth_protocol)nvalue;
	else if ( 7 == index )
		qhost->priv_proto = (enum priv_protocol)nvalue;
	else if ( 8 == index )
		memcpy(qhost->auth_passwd, str, sizeof(qhost->auth_passwd)-1);	
	else if ( 9 == index )
		memcpy(qhost->priv_passwd, str, sizeof(qhost->priv_passwd)-1);	

	return 0;
}

static int set_session_val(const QUERY_HOST *qhost, struct snmp_session *session)
{
	if (NULL == qhost || NULL == session) {
		log_net(LOG_ERR, "set_session_val() has invalided argument");
		return -1;
	}

	session->peername = strdup(qhost->name);
	if (qhost->version == 2) {  
		// snmp-v2版本
		session->version		= SNMP_VERSION_2c;
		session->community		= (u_char *)strdup(qhost->community);
		session->community_len	= strlen((char *)session->community);
	}
	else if (qhost->version == 3) { 
		// snmp-v3版本
		session->version = SNMP_VERSION_3;
		session->peername = strdup(qhost->name);
		session->securityName = strdup(qhost->user);
		session->securityNameLen = strlen(qhost->user);

		session->securityLevel = (qhost->sec_level==SEC_LEVEL_AP ? SNMP_SEC_LEVEL_AUTHPRIV : 
			(qhost->sec_level==SEC_LEVEL_ANOP ? SNMP_SEC_LEVEL_AUTHNOPRIV : SNMP_SEC_LEVEL_NOAUTH));

		if (qhost->auth_proto == AUTH_PROTOCOL_MD5) {
			session->securityAuthProto = usmHMACMD5AuthProtocol;
			session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
		} else if (qhost->auth_proto == AUTH_PROTOCOL_SHA) {
			session->securityAuthProto = usmHMACSHA1AuthProtocol;
			session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
		}

		if (qhost->priv_proto == PRIV_PROTOCOL_AES) {
			session->securityPrivProto = usmAESPrivProtocol;
			session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
		} else if (qhost->priv_proto == PRIV_PROTOCOL_DES) {
			session->securityPrivProto = usmDESPrivProtocol;
			session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
		}

		if ( qhost->auth_passwd ) {
		if (session->securityAuthProto == NULL) {
			/*
			 * get .conf set default 
			 */
			const oid	   *def =
				get_default_authtype(&session->securityAuthProtoLen);
			session->securityAuthProto =
				snmp_duplicate_objid(def, session->securityAuthProtoLen);
		}
		if (session->securityAuthProto == NULL) {
#ifndef NETSNMP_DISABLE_MD5
			/*
			 * assume MD5
			 */
			session->securityAuthProto =
				snmp_duplicate_objid(usmHMACMD5AuthProtocol,
									 USM_AUTH_PROTO_MD5_LEN);
			session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
#else
			session->securityAuthProto =
				snmp_duplicate_objid(usmHMACSHA1AuthProtocol,
									 USM_AUTH_PROTO_SHA_LEN);
			session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
#endif
		}

		session->securityAuthKeyLen = USM_AUTH_KU_LEN;
		if (generate_Ku(session->securityAuthProto,
						session->securityAuthProtoLen,
						(u_char *)qhost->auth_passwd, strlen(qhost->auth_passwd),
						session->securityAuthKey,
						&session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
			//snmp_perror(argv[0]);
			log_net(LOG_ERR, 
					"Error generating a key (Ku) from the supplied authentication pass phrase.");
			return (NETSNMP_PARSE_ARGS_ERROR);
		}
		}

		if ( qhost->priv_passwd ) {
		if (session->securityPrivProto == NULL) {
            /*
             * get .conf set default 
             */
            const oid      *def =
                get_default_privtype(&session->securityPrivProtoLen);
            session->securityPrivProto =
                snmp_duplicate_objid(def, session->securityPrivProtoLen);
        }
        if (session->securityPrivProto == NULL) {
            /*
             * assume DES 
             */
#ifndef NETSNMP_DISABLE_DES
            session->securityPrivProto =
                snmp_duplicate_objid(usmDESPrivProtocol,
                                     USM_PRIV_PROTO_DES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#else
            session->securityPrivProto =
                snmp_duplicate_objid(usmAESPrivProtocol,
                                     USM_PRIV_PROTO_AES_LEN);
            session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#endif

        }	
		
		session->securityPrivKeyLen = USM_PRIV_KU_LEN;				
		if (generate_Ku(session->securityAuthProto,
						session->securityAuthProtoLen,
						(u_char *) qhost->priv_passwd, strlen(qhost->priv_passwd),
						session->securityPrivKey,
						&session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
			//snmp_perror(argv[0]);
			log_net(LOG_ERR, 
					"Error generating a key (Ku) from the supplied privacy pass phrase");
			return (NETSNMP_PARSE_ARGS_ERROR);
		}
		}
	}

	return 0;
}

int main(int argc, char ** argv)
{
	int res = 0;
	res = ic_network_init();
	if ( res < 0 ) {
		log_net(LOG_ERR, "ic_network_init() error");
		exit(-1);
	}

	int flag = 0;
	while (1) {
		res = read_host_info_syn();
		if ( res < 0 ) {
			log_net(LOG_ERR, "read_host_info_syn() error");
			break;
		}

		sleep(3);
		//if (++flag == 3) break;
	} 
	
	res = ic_network_deinit();
	if ( res < 0 ) {
		log_net(LOG_ERR, "ic_network_deinit() error");
		exit(-1);
	}
	
	return 0;
} 

