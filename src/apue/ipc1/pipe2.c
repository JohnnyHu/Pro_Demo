/* @file: pipe2.c */

/* 
 * run_example: ./pipe2 /var/log/messages
 * to_learn:
 * 1. 读行的标准用法: fgets如何正确使用
 * 2. pipe, fork的用法
 * 3. 如何将管道描述符复制的标准输入或者标准输出：dup2 
 *
 * note:
 *
 */

#include "apue.h"
#include <sys/wait.h>

#define DEF_PAGER "/bin/more"	/* default pager program */

int main(int argc, char *argv[]) 
{
	if (argc != 2) {
		err_quit("usage: a.out <pathname>");
	}

	FILE *fp;
	if ((fp = fopen(argv[1], "r")) == NULL) {
		err_sys("can`t open %s", argv[1]);
	}	

	int fd[2];
	if (pipe(fd) < 0) {
		err_sys("pipe error");
	}
	
	pid_t pid;
	if ((pid = fork()) < 0) {
		err_sys("fork error");
	}
	else if (pid > 0){	/* parent */
		close(fd[0]);	/* close read end */
		
		/* parent copies argv[1] to pipe */
		int   n = 0;
		char  line[MAXLINE];
		while (fgets(line, MAXLINE, fp) != NULL) {
			n = strlen(line);
			if (write(fd[1], line, n) != n) {
				err_sys("write error to pipe");
			}	
		}
		if (ferror(fp)) {
			err_sys("fgets error");
		}
		
		close(fd[1]); 	/* close write end of pipe for reader */
		
		if (waitpid(pid, NULL, 0) < 0) {
			err_sys("waitpid error");
		}
		exit(0);
	} 
	else {
		close(fd[1]);	/* close write end*/

		if (fd[0] != STDIN_FILENO) {
			if (dup2(fd[0], STDIN_FILENO) != STDIN_FILENO) {
				err_sys("dup2 error to stdin");
			}
			//close(fd[0]);  /* Don`t need this after dup2*/
		}
		
		char *pager, *argv0;	
		/* get argument for execl() */	
	 	if ((pager = getenv("PAGER")) == NULL) {
			pager = DEF_PAGER;
		}	

		if ((argv0 = strrchr(pager, '/')) != NULL) {
			argv0++;	/* step past rightmost slash */
		}
		else { argv0 = pager; } /* no slash in pager */

		if (execl(pager, argv0, (char *)0) < 0) {
			err_sys("execl error for %s", pager);
		}
	}
	
	exit(0);
}
