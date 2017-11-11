/** @file Utility.c **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

#include <sys/wait.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include "Utility.h"

/*
 * SaferFree()
 * 更加安全的释放分配的内存
 * @pp 指向内存的指针的指针
 * 注：这里使用指针的指针是允许我们修改传入的指针
 */
void  SaferFree(void **pp)
{
	if (pp != NULL && *pp != NULL) {
		free(*pp);
		*pp = NULL;
	}
}


/*
 * Trim()
 * 去除首尾两端Blank的字符
 * @src 待格式化的字符
 */
void Trim(char *src)
{
        if ( NULL == src ) return;

        char *ori_src = src;
        char *begin = src;
        char *end   = src;

        while ( *(end++) ) {
                ; // Statement is null
        }

        if ( begin == end ) return;

        while ( begin < end &&
                (*begin == ' ' || *begin == '\t') )
                ++begin;

        while ( end > ori_src &&
                ((*end) == '\0' || *end == ' ' || *end == '\t') )
                --end;

        if ( begin > end ) {
                *src = '\0';  return;
        }

        //printf("begin=%1.1s; end=%1.1s\n", begin, end);
        while ( begin != end ) {
                *src++ = *begin++;
        }

        *src++ = *end;
        *src = '\0';

        return;
}


/*
 * Trim2()
 * 去除首尾两端Blank的字符
 * @src 要格式化的字符
 * @return formated src
 */
char *Trim2(char *src)
{
        if ( NULL == src ) return src;

        char *ori_src = src;

        char *begin = src;
        char *end   = src + strlen(src);

        if ( begin == end ) return ori_src;

        while ( begin < end && isblank(*begin) )
                ++begin;

        while ( end > ori_src && (isblank(*end) || !(*end)) )
                --end;

        if ( begin > end ) {
                *src = '\0';  return  ori_src;
        }

        //printf("begin=%1.1s; end=%1.1s\n", begin, end);
        while ( begin != end ) {
                *src++ = *begin++;
        }

        *src++ = *end;
        *src = '\0';

        return ori_src;
}


/*
 * RTrim2()
 * 去除首端Blank的字符
 * @src 要格式化的字符
 * @return formated src
 */
char *RTrim2(char *src)
{
        if ( NULL == src ) return src;

        char *begin = src;
        char *end   = src + strlen(src);

        while ( end > begin && (isblank(*end) || !(*end)) )
                --end;

        *(++end) = '\0';

        return begin;
}


/*
 * LTrim2()
 * 去除尾端Blank的字符
 * @src 要格式化的字符
 * @return formated src
 */
char *LTrim2(char *src)
{
        if ( NULL == src ) return src;

        char *ori_src = src;

        char *begin = src;
        char *end   = src + strlen(src);

        while ( begin < end && isblank(*begin) )
                ++begin;

        if ( begin == end ) {
                *src = '\0';  return  ori_src;
        }

        while ( begin != end ) {
                *src++ = *begin++;
        }

        *src++ = *end;
        *src = '\0';

        return ori_src;
}


/*
 * EraseInValidChar()
 * 去除空字符以外的其他无效字符
 * @src 待处理的字符
 * @return formated src
 */
char * EraseInValidChar(char * src)
{
        if ( NULL == src ) return src;

        size_t len = strlen(src);
        size_t i = 0, j = 0;
        for ( ; i < len; i++ ) {
                if ( isspace(*(src+i)) && !isblank(*(src+i)) ) continue;
                *( src + j ) = *( src + i );
                ++j;
        }

        *( src + j ) = '\0';

        return src;
}

/*
 * strToLower()
 * 大小字符转换成小写
 * @src 要转换的字符
 * @return Translated str
 */

char *strToLower( char *str )
{
        size_t i = 0;
        size_t nlen = strlen(str);
        while ( i < nlen ) {
                if ( isupper(str[i]) )
                        str[i] = tolower(str[i]);
                i++;
        }
        return str;
}

/*
 * strToUpper()
 * 大小字符转换成小写
 * @src 要转换的字符
 * @return Translated str
 */

char *strToUpper( char *str )
{

        size_t i = 0;
        size_t nlen = strlen(str);
        while ( i < nlen ) {
                if ( islower(str[i]) )
                        str[i] = toupper(str[i]);
                i++;
        }

        return str;
}

/*
 * GetNowDate()
 * 获取当前系统日期
 * @Return: Date(YYYYMMDD)
 *
 * NOTE：不可重入函数
 */
char *GetNowDate()
{
        static char sNowDate[8+1];
        memset( sNowDate, 0x00, sizeof(sNowDate) );

        time_t nSeconds;
        if (-1 == time(&nSeconds))
                return sNowDate;

        struct tm * pTM;
        pTM = localtime(&nSeconds);
        snprintf( sNowDate, sizeof(sNowDate), "%04d%02d%02d",
                pTM->tm_year + 1900,
                pTM->tm_mon + 1,
                pTM->tm_mday );

        return sNowDate;
}


/*
 * GetNowDateTime()
 * 获取当前系统日期时间
 * @Return: Date(YYYYMMDDHHMMSS)
 *
 * NOTE：不可重入函数
 */
char *GetNowDateTime()
{
        static char sNowDateTime[14+1];
        memset( sNowDateTime, 0x00, sizeof(sNowDateTime) );

        time_t nSeconds;
        if (-1 == time(&nSeconds))
                return sNowDateTime;

        struct tm *pTM;
        pTM = localtime(&nSeconds);
        snprintf( sNowDateTime, sizeof(sNowDateTime),
                "%04d%02d%02d%02d%02d%02d",
                pTM->tm_year + 1900,
                pTM->tm_mon + 1,
                pTM->tm_mday,
                pTM->tm_hour,
                pTM->tm_min,
                pTM->tm_sec  );

        return sNowDateTime;
}


/*
 * GetOneDateTime()
 * 根据秒数获取日期时间
 * @dstDateTime(YYYYMMDDHHMMSS)
 *
 * NOTE：不可重入函数
 */
char *GetOneDateTime(long int nSeconds )
{
        static char sOneDateTime[14+1];
        memset( sOneDateTime, 0x00, sizeof(sOneDateTime) );

        time_t tSeconds;
        tSeconds = (time_t)nSeconds;
        if (-1 == time(&nSeconds))
                return sOneDateTime;

        struct tm * pTM;
        pTM = localtime(&tSeconds);
        snprintf( sOneDateTime, sizeof(sOneDateTime),
                "%04d%02d%02d%02d%02d%02d",
                pTM->tm_year + 1900,
                pTM->tm_mon + 1,
                pTM->tm_mday,
                pTM->tm_hour,
                pTM->tm_min,
                pTM->tm_sec  );

        return sOneDateTime;
}


/*
 * GetDateSecnods()
 * 给定一个日期转换成对应的秒数
 * @date 基准日期(YYYYMMDD)
 * @return: 日期对应秒数
 *
 */
time_t GetDateSecnods( const char *date )
{
        assert( NULL != date && strlen(date) >= 8 );

        char sYear[4+1], sMon[2+1], sDay[2+1];

        snprintf( sYear, sizeof(sYear), "%4.4s", date   );
        snprintf( sMon,  sizeof(sMon),  "%2.2s", date+4 );
        snprintf( sDay,  sizeof(sDay),  "%2.2s", date+6 );

        struct tm tmDate = { 0 };
        tmDate.tm_year = atoi(sYear) - 1990;
        tmDate.tm_mon  = atoi(sMon) - 1;
        tmDate.tm_mday = atoi(sDay);

        return mktime( &tmDate );
}


/*
 * GetDiffDate()
 * 给定一个日期和间隔天数，获取对应的新日期
 * @srcDate 基准日期(YYYYMMDD)
 * @nDay 间隔天数(正负皆可)
 * @dstDate 获得的新日期(YYYYMMDD)
 *
 * NOTE：不可重入函数
 */
void  GetDiffDate(const char *srcDate, int nDay,  char *dstDate )
{
        assert( NULL != srcDate && strlen(srcDate) >= 8 );

        const int DAYSECONDS = 86400, DATELENGTH = 8;

        //struct tm tmSrcDate = { 0 };

        time_t srcTimeSec = GetDateSecnods( srcDate );
        time_t dstTimeSec = srcTimeSec + nDay * DAYSECONDS;

        struct tm *ptmDstDate;
        ptmDstDate = localtime( &dstTimeSec );

        snprintf( dstDate, DATELENGTH+1, "%04d%02d%02d",
                  ptmDstDate->tm_year + 1990,
                  ptmDstDate->tm_mon + 1,
                  ptmDstDate->tm_mday );

        return;
}


/*
* GetIntervalDays()
 * 给定连个日期日期获取间隔天数
 * @srcDate1 日期1(YYYYMMDD)
 * @srcDate2 日期2(YYYYMMDD)
 * @return: 间隔天数
 *
 */
int  GetIntervalDays( const char *srcDate1, const char *srcDate2 )
{
        assert( NULL != srcDate1 && strlen(srcDate1) >= 8 );
        assert( NULL != srcDate2 && strlen(srcDate2) >= 8 );

        const int DAYSECONDS = 86400;

        time_t timeSec1 = GetDateSecnods( srcDate1 );
        time_t timeSec2 = GetDateSecnods( srcDate2 );

        return (timeSec2 - timeSec1) / DAYSECONDS;
}


/*
 * Get8Time()
 * 给定一个日期hhmmss, 格式化其为：hh:mm:ss
 * @srcTime 源日期(格式hhmmss )
 * @dstTime 新日期(格式hh:mm:ss )
 *
 * NOTE：不可重入函数
 */
char *Get8Time( const char * srcTime )
{
        static char dstTime[8+1];
        memset(dstTime, 0x00, sizeof(dstTime) );

        if( NULL == srcTime || strlen(srcTime) < 6 )
                return dstTime;

        snprintf( dstTime, sizeof(dstTime),
                "%2.2s:%2.2s:%2.2s",
                srcTime,
                srcTime+2,
                srcTime+4 );

        return dstTime;
}

/*
 * Get10Date()
 * 给定一个日期YYYYMMDD, 格式化其为：YYYX/MM/DD
 * @srcDate 源日期(格式YYYYMMDD)
 * @dstDate 新日期(格式YYYY/MM/DD)
 *
 * NOTE：不可重入函数
 */
char *Get10Date( const char * srcDate )
{
        static char dstDate[10+1];
        memset(dstDate, 0x00, sizeof(dstDate) );

        if( NULL == srcDate || strlen(srcDate) < 8 )
                return dstDate;

        snprintf( dstDate, sizeof(dstDate),
                "%4.4s/%2.2s/%2.2s",
                srcDate,
                srcDate+4,
                srcDate+6 );

        return dstDate;
}

/*
 * Get10Date2()
 * 给定一个日期YYYYMMDD, 格式化其为：YYYX/MM/DD
 * @srcDate 源日期(格式YYYYMMDD)
 * @dstDate 新日期(格式YYYY-MM-DD)
 *
 * NOTE：不可重入函数
 */
char *Get10Date2( const char * srcDate )
{
        static char dstDate[10+1];
        memset(dstDate, 0x00, sizeof(dstDate) );

        if( NULL == srcDate || strlen(srcDate) < 8 )
                return dstDate;

        snprintf( dstDate, sizeof(dstDate),
                "%4.4s-%2.2s-%2.2s",
                srcDate,
                srcDate+4,
                srcDate+6 );

        return dstDate;
}


/*
 * Get19DateTime()
 * 给定一个日期YYYYMMDDHHMMSS, 格式化其为：
 * YYYY-MM-DD HH:MM:SS
 * @srcDateTime 源日期(格式YYYYMMDDHHMMSS)
 * @dstDateTime 新日期(格式YYYY-MM-DD HH:MM:SS)
 *
 * NOTE：不可重入函数
 */
char *Get19DateTime(const char *srcDateTime )
{
        static char dstDateTime[19+1];
        memset( dstDateTime, 0x00, sizeof(dstDateTime) );

        if( NULL == srcDateTime || strlen(srcDateTime) < 14 )
                return dstDateTime;

        snprintf( dstDateTime, sizeof(dstDateTime),
                "%4.4s-%2.2s-%2.2s %2.2s:%2.2s:%2.2s",
                srcDateTime,
                srcDateTime+4,
                srcDateTime+6,
                srcDateTime+8,
                srcDateTime+10,
                srcDateTime+12 );

        return dstDateTime;
}

/*
 * Get23DateTime()
 * 给定一个日期YYYYMMDDHHMMSSNNN, 格式化其为：
 * YYYY-MM-DD HH:MM:SS:NNN
 * @srcDateTime 源日期(格式YYYYMMDDHHMMSSNNN)
 * @dstDateTime 新日期(格式YYYY-MM-DD HH:MM:SS:NNN)
 *
 * NOTE：不可重入函数
 */
char * Get23DateTime( const char *srcDateTime )
{
        static char dstDateTime[23+1];
        memset( dstDateTime, 0x00, sizeof(dstDateTime) );

         if( NULL == srcDateTime || strlen(srcDateTime) < 17 )
                return dstDateTime;

        snprintf( dstDateTime, sizeof(dstDateTime),
                "%4.4s-%2.2s-%2.2s %2.2s:%2.2s:%2.2s:%3.3s",
                srcDateTime,
                srcDateTime+4,
                srcDateTime+6,
                srcDateTime+8,
                srcDateTime+10,
                srcDateTime+12,
                srcDateTime+14 );

        return dstDateTime;
}


/*
 * mkdirs()
 * 给定一个目录路径，递归检查和创建该目录
 * @pathname 要创建的目录
 *
 * NOTE：成功返回0，失败返回errno的值
 */
int mkdirs(const char *pathname)
{
        if ( NULL==pathname || strlen(pathname)==0 )
                return -1;

        char path[PATH_MAX+1] = {0};
        char tmppath[PATH_MAX+1] = {0};

        memcpy( path, pathname, sizeof(path)-1 );
        if ( *(path+strlen(path)) != '/' ) {
                strncat(path, "/", 1);
        }

        const char *pch = path;
        int i = 0;
        for ( ; *(pch+i) != '\0'; ++i ) {
                if (*(pch+i) != '/') { continue; }
                snprintf(tmppath, i+2, "%s", pch);

                /* access() need replace other.*/
                if (access(tmppath, F_OK) == 0)
                        continue;

                /* 创建目录组有：读、写、执行权限，
                 * 其他 执行权限 */
                errno = 0;
                if ( mkdir(tmppath, S_IRWXU | S_IRWXG | S_IXOTH) != 0 &&
                     errno != EEXIST ) {
                        return errno;
                }
        }

        return 0;
}


/*
 * CreateFile()
 * 创建生成空文件
 * @pfile 文件全路径
 *
 * NOTE：成功返回0，失败返回errno的值
 */
int CreateFile(const char *pfile)
{
        FILE *pFile = fopen(pfile, "w");
        if ( NULL == pFile ) {
                return errno;
        }

        fclose(pFile);
        return 0;
}


/*
 * CreateFile()
 * 删除文件
 * @pfile 文件全路径
 *
 * NOTE：成功返回0，失败返回-1
 */
int DeleteFile( const char *dir, const char *name )
{
        char  fileName[FILENAME_MAX+1] = {0};
        snprintf( fileName,
                  sizeof(fileName),
                  "%s/%s",
                  dir, name );

        int nRes = remove( fileName );
        if ( 0 != nRes ) {
                printf( "remove() error[%d], strerror(%s)",
                        nRes, strerror(errno) );
                return -1;
        }

        return 0;
}


/*
 * GetTmpName()
 * 获得临时文件名
 * @name 文件全路径
 * @suffix nane添加后缀
 *
 * NOTE：(不可重入函数)
 */
char *GetTmpName( const char *name, const char *suffix )
{
        static char tmpName[FILENAME_MAX];
        memset( tmpName, 0x00, sizeof(tmpName) );

        snprintf( tmpName,
                  sizeof(tmpName),
                  "%s%s",
                  name, suffix );

        return tmpName;
}


/*
 * AppendRecord()
 * 添加记录到文件中
 * @name 文件全路径
 * @buffer 记录内容
 * @length buffer的长度
 *
 * NOTE：成功返回0，失败返回-1
 */
int AppendRecord(const char *pfile, const char *buffer, size_t length)
{
        FILE *pFile = fopen(pfile, "a");
        if (NULL == pFile) {
                printf( "file[%s] open error\n", pfile);
                return -1;
        }

        size_t count = fwrite(buffer, sizeof(char), length, pFile);
        fclose(pFile);

        if (count != length) {
                printf( "file[%s] wite error\n", pfile);
                return -1;
        }

        return 0;
}


/*
 * GetFileStatus()
 * 获取文件状态
 * @path 文件的路径
 * @name 文件名
 *
 */
int GetFileStatus( const char *path, const char *name )
{
        char  fileName[FILENAME_MAX+1] = {0};
        snprintf( fileName, sizeof(fileName),
                  "%s/%s",
                  path, name );

        /* Note:
         * 1. 文件状态正常，返回0
         * 2. 文件为空，    返回1
         * 1. 文件不存在，  返回2 */

        errno = 0;
        struct stat statbuf;
        int nRes = stat( fileName, &statbuf );
        if ( nRes == -1  && errno != ENOENT) {
                printf("stat() error[%d], strerror(%s)\n",
                        nRes, strerror(errno) );
                return -1;
        }

        if ( errno == ENOENT ) {
                return 2;
        }

        if ( (size_t)statbuf.st_size == 0 ) {
                return 1;
        }

        return 0;
}


/*
 * GetFileSize()
 * 获取文件大小(字节)
 * @filename 文件的全路径
 * @pSize 文件的大小
 *
 * NOTE：成功返回0，失败返回errno的值
 */
int GetFileSize( const char *fileName, size_t *pSize )
{
        struct stat statbuf;
        int nRes = stat( fileName, &statbuf );
        if ( 0 != nRes ) {
                return errno;
        }

        *pSize = (size_t)statbuf.st_size;
        return 0;
}


/*
 * GetFileLines()
 * 获取文件行数
 * @filename 文件的全路径
 * @pSize 文件行数
 *
 * NOTE：成功返回0，
 */
int GetFileLines( const char *fileName, size_t *pLines )
{
        char command[200+1];
        snprintf( command, sizeof(command),
                "wc -l %s",
                fileName );

        typedef void(*sighander_t)(int);
        sighander_t oldhander = signal( SIGCHLD, SIG_DFL );

        FILE *fp = popen( command, "r" );
        if ( NULL == fp ) {
                printf(  "popen() error.\n" );
                return -1;
        }

        #define MAX_SIZE 1024
        size_t nRes = 0;
        char buffer[MAX_SIZE+1]={0};

        /*
        while ( ( nRes = fread(buffer, sizeof(char),
                MAX_SIZE, fp) ) > 0 ) {
                buffer[nRes-1] = '\0';

                printf("Result: %s\n", buffer );
        }
        pclose( fp );
        */

        if ( ( nRes = fread(buffer, sizeof(char),
                MAX_SIZE, fp) ) > 0 ) {
                buffer[nRes-1] = '\0';
        }

        if ( -1 == pclose(fp) ) {
                printf( "pclose() error[%d],strerror[%s].\n",
                        errno, strerror(errno) );
                return -1;
        }

        signal( SIGCHLD, oldhander );

        char keys[] = " -+";
        size_t nPos = strcspn( buffer, keys );
        memmove( buffer, buffer, nPos+1 );

        *pLines = atol( buffer );
        return 0;
}

#if 0
/* Examine a wait() status using the W* macros */
static int printWaitStatus(const char *msg, int status)
{
        if (msg != NULL) {
                printf(  "%s", msg );
        }

        if (WIFEXITED(status)) {
                printf( "child exited, status=%d, ", WEXITSTATUS(status) );
                return 0;

        } else if (WIFSIGNALED(status)) {
                printf(  "child killed by signal %d (%s)",
                        WTERMSIG(status), strsignal(WTERMSIG(status)) );
#ifdef WCOREDUMP        /* Not in SUSv3, may be absent on some systems */
                if (WCOREDUMP(status))
                printf( " (core dumped)");
#endif
                printf(  "\n" );
                return -1;

        } else if (WIFSTOPPED(status)) {
                printf( "child stopped by signal %d (%s)\n",
                         WSTOPSIG(status), strsignal(WSTOPSIG(status)) );

#ifdef WIFCONTINUED     /* SUSv3 has this, but older Linux versions and
                           some other UNIX implementations don't */
        } else if (WIFCONTINUED(status)) {
                printf(  "child continued\n" );
#endif
                return -1;
        } else {            /* Should never happen */
                printf( "what happened to this child? (status=%x)\n",
                        (unsigned int) status );
        }

        return -1;
}
#endif

/*
 * ExeSysCmd()
 * 执行系统命令
 * @ cmd 要执行的命令
 */
int ExeSysCmd( const char *cmd )
{
        int nRes = 0;
        //printf( "Cmd:[%s].\n", cmd );

        typedef void(*sighander_t)(int);
        sighander_t oldhander = signal( SIGCHLD, SIG_DFL );

        FILE *fp = popen( cmd, "r");
        if ( NULL == fp ) {
                printf("popen() error[%d],strerror[%s].\n",
                        errno, strerror(errno) );
                return -1;
        }

        // Read stream until EOF
        char pathname[PATH_MAX] = {0};
        while ( fgets( pathname, PATH_MAX, fp ) != NULL ) {
                printf( "%s", pathname );
        }

        nRes = pclose( fp );
        if ( -1 == nRes ) {
                printf( "pclose() error[%d],strerror[%s].\n",
                        errno, strerror(errno) );
                return -1;
        }

        signal( SIGCHLD, oldhander );

        return 0;
}


/*
 * ExeSysCmd2()
 * 执行系统命令
 * @ cmd要执行的命令
 * @ buffer命令返回的buffer,
 * @ buffer对应的长度
 */
int ExeSysCmd2( const char *cmd, char *buffer, size_t len )
{
        int nRes = 0;
        //printf( "Cmd:[%s].\n", cmd );

        typedef void(*sighander_t)(int);
        sighander_t oldhander = signal( SIGCHLD, SIG_DFL );

        FILE *fp = popen( cmd, "r");
        if ( NULL == fp ) {
                printf( "popen() error[%d],strerror[%s].\n",
                         errno, strerror(errno) );
                return -1;
        }


        /* Read stream until EOF */
        size_t  nIndex = 0, nLen = 0;
        char strRes[PATH_MAX] = {0};
        while ( fgets( strRes, PATH_MAX, fp ) != NULL ) {

                /* printf( LOG_KEY, "%s", strRes ); */
                if ( nIndex >= len -1 ) {
                        printf("Buffer is too small, Ignore the data in the back!\n");
                        continue;
                }

                nLen = ( strlen(strRes) > len-nIndex-1 ?
                         (len-nIndex-1) : strlen(strRes) );

                strncat( buffer+nIndex, strRes, nLen );
                nIndex += nLen;
        }
        *(buffer+nIndex) = '\0';

        nRes = pclose( fp );
        if ( -1 == nRes ) {
                printf( "pclose() error[%d],strerror[%s].\n",
                         errno, strerror(errno) );
                return -1;
        }

        signal( SIGCHLD, oldhander );
        return 0;
}
