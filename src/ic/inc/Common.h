/** @file Common.h **/

#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <semaphore.h>

#include <stdarg.h>
#include <syslog.h>

/* 当wait 被SIGNAL_QUIET 打断时，wait退出 */
#define SIGNAL_QUIET (SIGUSR1)

/* 检查当前挂起的信号中是否含有特定的信号 */
static int inline check_signal(int sig) {
	sigset_t pendmask;

	if (sigpending(&pendmask) <0)    return -1;
	if (sigismember(&pendmask, sig)) return sig;
	return -1;
}

#define WAIT_QUIT	(1)
#define WAIT_INTR	(-1)
#define WAIT_FAIL	(-100)
static int inline __wait(sem_t* sem)
{
	int ret,sig_recved;
retry:
	ret = sem_wait((sem));
	if ( !ret ) { return 0; }
	
	if (ret < 0 && errno == EINTR) {
		/* 如果是指定的退出信号，则退出wait*/
		sig_recved = check_signal(SIGNAL_QUIET);
		if (sig_recved == SIGNAL_QUIET) {
			printf("received our quit signal:%d. exit wait!\n", sig_recved);
			return WAIT_QUIT;
		}
		goto retry;
	} 
	else if (ret < 0 && errno == EAGAIN) {
		goto retry;
	}
	else {
		printf("sem_wait fail. ret:%x, reason: %s\n", ret, strerror(errno));
		return WAIT_FAIL;
	}
}
static void inline wait(sem_t *sem) {
	(void)__wait(sem);
}
static void inline wakeup(sem_t* sem) {
	sem_post(sem);
}

#define	LOG_MSG_LEN		(2048)
#define LOGGER_TYPE		LOG_LOCAL0
static void inline open_syslog(const char *ident, int option, int facility) {
	openlog(ident, option, facility);
} 	
#endif

