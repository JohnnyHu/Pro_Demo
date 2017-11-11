/** @file ic_host_client.h **/
/*
 * Note: 客户端主要两个功能：
 * 1. 上传采集信息
 * 2. 回复服务端的控制消息
 * 3. ./ic_host_client 192.168.1.21 8800
**/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <pthread.h>
#include "Utility.h"

#define BUFFER_SIZE     (2048)
#define MESSAGE_SIZE    (1024)

#define MSG_HEAD_LEN    (8)
#define MSG_TAIL_LEN    (2)
#define MSG_HEAD_FLAG   (0x55)
#define MSG_TAIL_FLAG   (0xAA)

#define MTYPE_INFO_UPLOAD       0x1  /* 采集信息上报 */
#define MTYPE_ARG_CHECK         0x2  /* 参数查看     */
#define MTYPE_ARG_SETTING       0x3  /* 参数设置     */
#define MTYPE_BASELING_CHECK    0x4  /* 启动基线核查 */
#define MTYPE_NETWORK_DISCON    0x5  /* 启动主动断网 */

#define  ENO_SUCCESS          0x0  /* 成功           */
#define  ENO_INNER_ERR        0x1  /* 内部错误       */
#define  ENO_NONSUP_TYPE      0x2  /* 不支持的类型   */
#define  ENO_ARG_ERR          0x3  /* 参数错误       */
#define  ENO_NOEXSIT_OBJ      0x4  /* 对象不存在     */
#define  ENO_UNREACH_OBJ      0x5  /* 对象不可达     */
#define  ENO_FORMAT_ERR       0x6  /* 内容格式错误   */
#define  ENO_STAMP_CMP_ERR    0x7  /* 时间戳比较失败 */
#define  ENO_VERIFY_SIGN_ERR  0x8  /* 验证签名出错   */
#define  ENO_EXEC_CMD_FAIL    0x9  /* 命令执行失败   */

#define DEFAULT_SEND_TIME 60
//#define IC_HOST_LOG   "ic_host.log"

typedef struct packet_format {
    uint8_t     head_flag;
    uint16_t    msg_len;
    uint8_t     *msg;
    uint8_t     checksum;
    uint8_t     tail_flag;
} PacketFormat;

struct ic_client_info {
    int     clnt_sock;
    int     should_stop;
    pthread_t       thread_ctrl;
    pthread_mutex_t thread_mutex;
};

enum arg_option {
    ARG_LIST_NET_CONN = 0x1,    /* 网络连接白名单 */
    ARG_LIST_SRV_PORT = 0x2,    /* 服务端口白名单 */
    ARG_LIST_KEY_FILE = 0x3,    /* 关键文件/目录清单*/
    ARG_CYCLE_DEVICE  = 0x4,    /* 光驱设备检测周期 */
    ARG_CYCLE_ILLPORT = 0x5     /* 非法端口检测周期 */
};

static int 
send_msg(int sock_fd);

static const uint8_t * 
generate_message(const char *message, size_t len);

static int 
process_ctrl_msg(int sock, const unsigned char *msg, size_t len);
static int 
reply_ctrl_msg(int sock, const unsigned char *msg, size_t len);
static const uint8_t * 
gen_arg_check_msg(enum arg_option val, size_t *len);
static int 
change_msg(char *msg, size_t len);


static void* 
handle_clnt(void* arg);

static void 
print_buf(const unsigned char *s, unsigned int len)
{
    int i = 0;
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) { printf("\n[0x%04x]  ", i); }
        printf("%02x ",s[i]);
    }
    printf("\n");   
}

//static struct ic_client_info g_client_info;
int main(int argc, char *argv[])
{
    int serv_sock;
    struct sockaddr_in serv_addr;
    
    if(3 != argc) {
        printf("Usage : %s <IP> <Port> \n", argv[0]);
        exit(1);
    }

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(-1 == serv_sock){
        printf("fail to create socket. error info:%s\n", strerror(errno));
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if( -1 == connect(serv_sock, (struct sockaddr*)&serv_addr,
                      sizeof(serv_addr)) ){
        printf("fail to connect socket. error info:%s\n", strerror(errno));
        close(serv_sock);
        return -1;
    }
    printf("connected server[%s:%s].......\n", argv[1], argv[2]);

    // 创建控制线程
    pthread_t thread_ctrl;
    pthread_create(&thread_ctrl, NULL, handle_clnt, (void *)&serv_sock);    

while (1) {
    int str_len = send_msg(serv_sock);
    if(-1 == str_len){
        printf("fail send_msg() error. error info:%s\n", strerror(errno));
        break;
    }
    sleep(DEFAULT_SEND_TIME);
}

    pthread_join( thread_ctrl, NULL );
    close(serv_sock);
    return 0;
}


// 控制线程处理
static void* handle_clnt(void* arg) 
{
    int serv_sock = *((int *)arg);
    unsigned char message[BUFFER_SIZE] = {0};

    while (1) {
        //if ( pclnt_info->should_stop ) break;

        // 接收报文头部......
        size_t len = 0, recv_len = 0, want_len = MSG_HEAD_LEN;
        while ((len = recv(serv_sock, message + recv_len, want_len, 0)) > 0) {
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
                len, serv_sock, strerror(errno));
            break;
        }

        if (MSG_HEAD_FLAG != message[0]) {
            printf("The message head flag [%d] isn't [%d], check error!\n", 
                message[0], MSG_HEAD_FLAG);
        } 

        uint32_t tmp_len, msg_len; 
        memcpy(&tmp_len, message+4, sizeof(uint32_t));
        if ((msg_len = ntohl(tmp_len)) <= 0) {
            printf("The message content len [%d] error!\n", msg_len);
            //break;
        }

        // 接收报文内容......
        recv_len = 0; want_len = msg_len + MSG_TAIL_LEN;
        if (want_len > BUFFER_SIZE) {
            printf("The message content len [%zu] is larger than default len [%d]\n", 
                want_len, BUFFER_SIZE);
            break;
        }

        int ret = 0;
        while ((len = recv(serv_sock, message + MSG_HEAD_LEN + recv_len, want_len, 0)) > 0) {
            if (len < want_len) {
                recv_len += len; want_len -= len; continue;
            }
            break;
        }
        if (len == 0) {
            printf("content-->client shutdown link!\n");
            break;
        }
        else if (len < 0) {
            printf("socket receive content fail, len:%zu, cfd:%d!, errors:%s\n", 
                len, serv_sock, strerror(errno));
            break;
        }

        // 报文接收完整，进行处理.........
        size_t total_len = MSG_HEAD_LEN + msg_len + MSG_TAIL_LEN;
        ret = process_ctrl_msg(serv_sock, message, total_len);
        if (ret != 0) {
            printf("process_ctrl_msg() error\n" );
            break;
        }
    }

    return NULL;
}


static int 
process_ctrl_msg(int sock, const unsigned char *msg, size_t len)
{
    assert( len >= MSG_HEAD_LEN + MSG_TAIL_LEN );

    int ret = 0;  
	
    // 打印消息
    print_buf(msg, len);

    // 报文参数
    uint16_t tmp_arg, msg_arg;
    memcpy(&tmp_arg, msg+2, sizeof(uint16_t));
    msg_arg = ntohs(tmp_arg);

    // 内容长度
    uint32_t tmp_len, msg_len; 
    memcpy(&tmp_len, msg+4, sizeof(uint32_t));
    msg_len = ntohl(tmp_len);
    
    // 参数查看
    if (MTYPE_ARG_CHECK == msg[1]) {
        if ( msg_arg<ARG_LIST_NET_CONN || msg_arg>ARG_CYCLE_ILLPORT ) {
            printf("msg_arg value[%02x] error!\n", msg_arg);
            return 0;
        }

        size_t msg_len = 0;
        const uint8_t *str_msg;
        str_msg = gen_arg_check_msg(msg_arg, &msg_len); 
        if (NULL == str_msg) {
            printf("gen_arg_check_msg() error\n");
            return -1;
        }       

        ret = reply_ctrl_msg(sock, str_msg, msg_len); 
        if (ret < 0) {
            printf("reply_ctrl_msg() error\n");
            return -1;
        }       
    } 

    // 参数设置
    if (MTYPE_ARG_SETTING == msg[1]) {
        if ( msg_arg<ARG_LIST_NET_CONN || msg_arg>ARG_CYCLE_ILLPORT ) {
            printf("msg_arg error!\n");
            return 0;
        }

        //......        
    } 

    return 0;
}

static int 
reply_ctrl_msg(int sock, const unsigned char *msg, size_t len)
{   
    int ret = send(sock, msg, len, MSG_NOSIGNAL);       
    if(-1 == ret){
        printf("fail send socket. error info:%s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// 生成参数查看报文
static const uint8_t * 
gen_arg_check_msg(enum arg_option val, size_t *len) 
{
    static uint8_t str_pack[BUFFER_SIZE];
    memset(str_pack, 0x00, sizeof(str_pack));

    char strmsg[MESSAGE_SIZE+1] = {0};
    switch ( val ) {
    case ARG_LIST_NET_CONN: 
        memcpy(strmsg, 
            "tcp,192.168.175.132,8800,192.168.1.21,8800\n tcp,192.168.175.132,233,192.168.1.121,233\n", 
            MESSAGE_SIZE);
        break;
    case ARG_LIST_SRV_PORT: 
        memcpy(strmsg, 
            "22,sshd\n25,master\n631,cupsd\n", 
            MESSAGE_SIZE);
        break;
    case ARG_LIST_KEY_FILE: 
        memcpy(strmsg, 
            "/home/sms_one/\n/root/ssdup\n/home/bak/base.sh\n", 
            MESSAGE_SIZE);
        break;
    case ARG_CYCLE_DEVICE:  
        memcpy(strmsg, 
            "300", 
            MESSAGE_SIZE);
        break;
    case ARG_CYCLE_ILLPORT: 
        memcpy(strmsg, 
            "60", 
            MESSAGE_SIZE);
        break;
    default: 
        break;
    }

    uint32_t msg_len = strlen(strmsg);
    size_t pack_len = MSG_HEAD_LEN  + msg_len + MSG_TAIL_LEN;
    if ( pack_len > BUFFER_SIZE) {
        printf("packet len %zu is larger than max send len %d.\n", 
            pack_len, BUFFER_SIZE); 
        return NULL;
    }

    // 报文头[ 报文标识(1)+报文类型(1)+参数(2)+报文内容长度(4) ]
    str_pack[0] = MSG_HEAD_FLAG;
    str_pack[1] = MTYPE_ARG_CHECK;

	// 参数
	uint16_t msg_arg = (msg_len == 0 ? ENO_SUCCESS : ENO_INNER_ERR);
    memset(str_pack+2, htons(msg_arg), sizeof(uint16_t));

    // 报文内容长度
    uint32_t to_msg_len = htonl( msg_len );
    memcpy(str_pack+4, &to_msg_len, sizeof(uint32_t));

    // 报文内容
    memcpy(str_pack+MSG_HEAD_LEN, (uint8_t *)strmsg, msg_len);

    // 内容校验和
    int checksum = strmsg[0];
    for (int i = 1; i < msg_len; i++) {
        checksum ^= strmsg[i];      
    }
    
    // 报文尾[ 校验和(1)+报文尾(1) ]
    str_pack[pack_len-2] = checksum;    
    str_pack[pack_len-1] = MSG_TAIL_FLAG;

    print_buf(str_pack, pack_len);
    //printf("checksum: [%d]-[%d]-->[%d]\n", message[0], message[len-1], checksum);
    printf("message: %*s", (int)msg_len, strmsg );

    *len = pack_len;
    return str_pack;
}


// 生成报文
static const uint8_t * 
generate_message(const char *message, size_t len) 
{
    static uint8_t str_pack[BUFFER_SIZE];
    memset(str_pack, 0x00, sizeof(str_pack));
    
    size_t pack_len = len + MSG_HEAD_LEN + MSG_TAIL_LEN;
    if ( pack_len > BUFFER_SIZE) {
        printf("packet len %zu is larger than max send len %d.\n", 
            pack_len, BUFFER_SIZE); 
        return NULL;
    }
    
    // 报文头[ 报文标识(1)+报文类型(1)+参数(2)+报文内容长度(4) ]
    str_pack[0] = MSG_HEAD_FLAG;
    str_pack[1] = MTYPE_INFO_UPLOAD;

	// 参数
	uint16_t msg_arg = 0x00;
    memset(str_pack+2, htons(msg_arg), sizeof(uint16_t));
    
    // 报文内容长度
    uint32_t msg_len = htonl(len);
    memcpy(str_pack+4, &msg_len, sizeof(msg_len));

    //printf("str_pack00:[%"PRIu8"]-[%"PRIu16"]-[%"PRIu16"]\n", 
    //      str_pack[0], len, msg_len);

    // 报文内容
    memcpy(str_pack+MSG_HEAD_LEN, (uint8_t *)message, len);
    
    // 内容校验和
    uint8_t checksum = message[0];
    for (int i = 1; i < len; i++) {
        checksum ^= message[i];     
    }
    
    // 报文尾[ 校验和(1)+报文尾(1) ]
    str_pack[pack_len-2] = checksum;    
    str_pack[pack_len-1] = MSG_TAIL_FLAG;
    
    //print_buf(str_pack, pack_len);
    //printf("checksum: [%d]-[%d]-->[%d]\n", message[0], message[len-1], checksum);
    //printf("message: %*s", (int)len, message );

    return str_pack;
}

static int 
change_msg(char *msg, size_t len) 
{
	int  index = 0;
	char *ptime = Get19DateTime(GetNowDateTime());

	char tmp_msg[BUFFER_SIZE] = {0};
	memcpy(tmp_msg, msg, len);
	//printf("msg-change-before, len[%zu], msg[%s]\n", len, (char *)msg);

	char *pch, *pch2;
	pch = pch2 = strtok(tmp_msg, " ");
	while (pch != NULL) {			
		if ( ++index == 2 ) { 
			pch2 = pch;	
		}	

		if ( index == 3 ) { 
			memset (msg + (pch2-tmp_msg), ' ', pch-pch2);		 
			memmove(msg + (pch2-tmp_msg), ptime, strlen(ptime)); 	
			break;
		}	
		pch = strtok(NULL, " ");
	} 

	//printf("msg-change-end, len[%zu], msg[%s]\n", len, (char*)msg);
	return 0;
}


static int 
send_msg(int sock_fd)
{
    int ret = 0;
    char *IC_HOST_LOGS = getenv("HOST_LOGS");
    if ( NULL == IC_HOST_LOGS) {
        printf("getenv() error[%s]\n", strerror(errno));
        return -1;
    }
    
    FILE *fp = fopen(IC_HOST_LOGS, "r");
    if (NULL == fp) {
        printf("fopen() %s error info:%s\n", IC_HOST_LOGS, strerror(errno));
        return -1;
    }

    char str[BUFFER_SIZE] = {0};
    const uint8_t *str_packet;
    
    while (fgets(str, sizeof(str), fp) != NULL) {

        ret = change_msg(str, strlen(str));    
        if (0 != ret) {
            printf("change_msg() error\n");
            //break;
        }			
        str_packet = generate_message(str, strlen(str));    
        if (NULL == str_packet) {
            printf("generate_message() error\n");
            break;
        }

        size_t pack_len = strlen(str) + MSG_HEAD_LEN + MSG_TAIL_LEN;
        ret = send(sock_fd, str_packet, pack_len, MSG_NOSIGNAL);        
        if(-1 == ret){
            printf("fail send socket. error info:%s\n", strerror(errno));
			return -1;
        }

        //print_buf(str_packet, pack_len);
        memset(str, 0x00, sizeof(str));
    }

    fclose(fp);
    return 0;
}
