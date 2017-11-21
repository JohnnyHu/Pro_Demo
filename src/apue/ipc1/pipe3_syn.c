/* @file: pipe3_syn.c */
/* 
 * run_example: ./pipe3_syn
 * to_learn:
 * 1. WAIT_XXX调用read读一个字符，在没有读到字符时进行阻塞(休眠等待)
 * 2. 如何在两个进程之间用"管道"的方式来实现同步?
 * 3. 两个进程之间实现同步的方式：信号量和管道有何不同?
 *
 * to_how:
 * 1. 这种同步方式的具体应用场景例程实现方式？
 * 	例程原理：父进程首先往文件中写内容，然后告诉子进程读取内容，子进程
 * 	读取内容之后，也往里面写内容，写完之后，告诉父进程，父进程读取里面内容.
 * 2. 上述例程也可以反过来进行验证。 
 *
 * note:
 * 1. 例程不完美，有待完善
 *  
 */

#include "apue.h"

#include <errno.h>
#define TEST_FILE "syn_test_file.tmp"

static int pfd1[2], pfd2[2];

void TELL_WAIT_L(void) {
	if (pipe(pfd1) < 0 || pipe(pfd2) < 0) {
		err_sys("pipe error");
	}
}

void TELL_PARENT_L(pid_t pid) {
	if (write(pfd2[1], "c", 1) != 1) {
		err_sys("write error");
	}
}

void WAIT_PARENT_L(void) {
	char c;
	if (read(pfd1[0], &c, 1) != 1) {
		err_sys("WAIT_PARENT: read error");
	}

	if (c != 'p') {
		err_quit("WAIT_PARENT: incorrect data");
	}
}

void TELL_CHILD_L(pid_t pid) {
	if (write(pfd1[1], "p", 1) != 1) {
		err_sys("write error");
	}
}

void WAIT_CHILD_L(void) {
	char c;
	errno = 0;
	if (read(pfd2[0], &c, 1) != 1) {
		err_sys("WAIT_CHILD: read error");
	}

	if (c != 'c') {
		err_quit("WAIT_CHILD: incorrect data");
	}
}

// 打印收到的消息
int print_buf() 
{
	FILE *fp = NULL;
	fp = fopen(TEST_FILE, "r");
	if (NULL == fp) {
		printf("fopen() errors:%s\n", strerror(errno));
		return -1;
	}
	
	char  line[MAXLINE];
	while (fgets(line, MAXLINE, fp) != NULL) {
		fputs(line, stdout);	
	}
	putchar('\n');

	if (ferror(fp)) {
		printf("fgets errors:%s\n", strerror(errno));
	}
	
	fclose(fp);
	return 0;
}

int write_message(const char *message, size_t len) 
{
	FILE *fp = NULL;
	fp = fopen(TEST_FILE, "a+");
	if (NULL == fp) {
		printf("fopen() errors:%s\n", strerror(errno));
		return -1;
	}
	
	fputs((char *)message, fp);
	//fwrite(message, sizeof(char), len, fp);
	fflush(fp);
	
	fclose(fp);
	return 0;
}


int main(int argc, char *argv[])
{
	char 	*str_parent = "hello, parent ready!\n";
	char 	*str_child  = "hello, child ready, too!\n";
	
	TELL_WAIT_L();

	pid_t 	pid;
	if ((pid = fork()) < 0) {
		err_sys("fork error");
	}
	else if (pid > 0) {		/* parent */
		close(pfd1[0]);
		close(pfd2[1]);
		
		write_message(str_parent, strlen(str_parent));
		
		TELL_CHILD_L(pid);
		WAIT_CHILD_L();

		printf("count value from child: \n");
		print_buf();	
	}
	else {				/* child */
		close(pfd1[1]);
		close(pfd2[0]);

		WAIT_PARENT_L();
		printf("count value from parent:\n");
		print_buf();	
		
		write_message(str_child, strlen(str_child));
		TELL_PARENT_L(pid);
	}

	exit(0);
}
