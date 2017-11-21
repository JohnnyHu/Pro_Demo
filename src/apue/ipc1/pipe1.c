/* @file: pipe1.c */
/* 
 * run_example: ./pipe2 
 * to_learn:
 * 1. fd[0]为管道的读端，fd[1]为管道的写端
 * 2. 同一个进程里面管道的读写是毫不意义的，两个进程之间的管道组成的IPC才具有实际的意义
 * 3. 当管道的一端被关闭之后，具有怎样的规则？
 *
 * to_how:
 * 1. 多进程同时写管道时的问题？ 如何避免？
 *
 * note:
 * 1. find /usr/include -name  "*.h" |xargs grep -nin "PIPE_BUF"
 *  
 */

#include "apue.h"
#include <limits.h>

int main(int argc, char *argv[])
{
	int 	n;
	int 	fd[2];
	pid_t 	pid;
	char 	line[MAXLINE];
	
	printf("PIPE_BUF: %d\n", PIPE_BUF);

	if (pipe(fd) < 0) {
		err_sys("pipe error");
	}

	if ((pid = fork()) < 0) {
		err_sys("fork error");
	}
	else if (pid > 0) {		/* parent */
		close(fd[0]);
		write(fd[1], "hello world\n", 12);	
	}
	else {					/* child */
		close(fd[1]);	
		n = read(fd[0], line, MAXLINE);
		write(STDOUT_FILENO, line, n);
	}

	exit(0);
}
