/**
 * some utils.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <assert.h>
#include <stdio.h>

/**
 * @brief split left=right with delim(=)
 * @return 0 sucess -1 line[0] == '#'
 * @note left and right are trimed.
 */
int split_line( char* line, char** left, char** right, const char delim);
/**
 * @brief clear beging space(ignore) and ending space(ignore)
 */
char* strtrim(char* str, const char* ignore);
int get_file_size(const char *pszFilePath);
int dtstr2time(const char *pszDate);

typedef struct LogFile 
{
	int nLevel;
	FILE* pFile;
	time_t tmPre;
	char szCurDate[11];
	char szFileName[1024];
} LogFileDef;

enum LOG_LEVEL { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL, LOG_FIX };

int open_log(int nLevel, const char *pszFolder, LogFileDef *pLogFile);
int logmsg(int level, const char* fmt, ... );
int log_data_items(const char* fmt, ... );
int log_drop_data(const char* fmt, ... );
int is_log_drop_data();
int is_log_data_items();

int file_log_level();
void open_all_log(int nLevel);
void close_all_log();
void CheckLogFullDays(const char *pszFolder, int nFullDays);

#define LOG_DROP_DATA(...) \
	do{ log_drop_data("[%s:%d]\t" "%s\t%s\t%s\t %s\t %s\t %s\t%s", __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOG_DATA_ITEMS(...) \
	do{ log_data_items("[%s:%d]\t" "%s\t%s\t %s\t %s\t%d\t%d\t%d\t%s", __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGTRACE0(msg) \
	do{ if(file_log_level()<=LOG_TRACE) logmsg(LOG_TRACE, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGDEBUG0(msg) \
	do{ if(file_log_level()<=LOG_DEBUG) logmsg(LOG_DEBUG, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGINFO0(msg) \
	do{ if(file_log_level()<=LOG_INFO) logmsg(LOG_INFO, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGWARN0(msg) \
	do{ if(file_log_level()<=LOG_WARN) logmsg(LOG_WARN, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGERROR0(msg) \
	do{ if(file_log_level()<=LOG_ERROR) logmsg(LOG_ERROR, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGFATAL0(msg) \
	do{ if(file_log_level()<=LOG_FATAL) logmsg(LOG_FATAL, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGFIX0(msg) \
	do{ if(file_log_level()<=LOG_FIX) logmsg(LOG_FIX, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGTRACE(fmt, ...) \
	do{ if(file_log_level()<=LOG_TRACE) logmsg(LOG_TRACE, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGDEBUG(fmt, ...) \
	do{ if(file_log_level()<=LOG_DEBUG) logmsg(LOG_DEBUG, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGINFO(fmt, ...) \
	do{ if(file_log_level()<=LOG_INFO) logmsg(LOG_INFO, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGWARN(fmt, ...) \
	do{ if(file_log_level()<=LOG_WARN) logmsg(LOG_WARN, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGERROR(fmt, ...) \
	do{ if(file_log_level()<=LOG_ERROR) logmsg(LOG_ERROR, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGFATAL(fmt, ...) \
	do{ if(file_log_level()<=LOG_FATAL) logmsg(LOG_FATAL, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGFIX(fmt, ...) \
	do{ if(file_log_level()<=LOG_FIX) logmsg(LOG_FIX, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

void print_bt();

#define ASSERT(x) do{ \
	if (!(x)) { \
		logmsg(LOG_FATAL, "[%s:%d] " #x); \
		abort(); \
	} \
}while(0);

struct queue_t;

// fixed length queue
struct queue_t* init_queue(size_t size);
int push_queue(struct queue_t* queue, const void* p);	///< success return > -1;
void* pop_queue(struct queue_t* queue);
size_t len_queue(struct queue_t* queue);
void* get_queue(struct queue_t* queue, size_t index);
void destory_queue(struct queue_t* queue);

size_t count_char(const char* str, const char c);
char* GetValue(const char* confname, const char* name, char* value, size_t len);

char* strlwr(char *str);

int64_t htonll(int64_t n);
int64_t ntohll(int64_t n);

int code_convert(char *from_charset, char *to_charset, char *inbuf, int inlen, char *outbuf, int outlen);
int u2g(char *inbuf, int inlen, char *outbuf, int outlen);
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen);

#endif

