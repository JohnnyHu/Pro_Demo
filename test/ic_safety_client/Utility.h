/** @file Utility.h **/

#ifndef __UTILITY_H
#define __UTILITY_H

void   SaferFree(void **pp);
#define safeFree(p) SaferFree((void**)&(p))

void   Trim(char *);
char * Trim2(char *);
char * Rtrim2(char *);
char * Ltrim2(char *);

char * EraseInValidChar( char *);

char * strToLower(char *);
char * strToUpper(char *);

char * GetNowDate();
char * GetNowDateTime();
char * GetOneDateTime(long int );
void   GetDiffDate(const char *, int , char *);
char * Get10Date(const char *); 
char * Get8Time(const char *);
char * Get10Date2(const char *);
char * Get19DateTime(const char *);
char * Get23DateTime(const char *);

char * GetTmpName(const char *, const char *);

int mkdirs(const char *);

int CreateFile(const char *);
int DeleteFile(const char *, const char *);

int AppendRecord(const char *, const char *, size_t);

int GetFileStatus( const char *path, const char *name );
int GetFileSize(const char *, size_t *);
int GetFileLines(const char *, size_t *);

int ExeSysCmd ( const char *cmd );
int ExeSysCmd2( const char *cmd, char *buffer, size_t len );

#endif

