/**
 * some utils.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <assert.h>

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

enum LOG_LEVEL { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

/** @brief success return 0 **/
int open_log(const char* logfile, int level);
/** @brief success return >0 */
int logmsg(int level, const char* fmt, ... );
int loglevel();

void close_log();

#define LOGTRACE0(msg) \
	do{ if(loglevel()<=LOG_TRACE) logmsg(LOG_TRACE, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGDEBUG0(msg) \
	do{ if(loglevel()<=LOG_DEBUG) logmsg(LOG_DEBUG, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGINFO0(msg) \
	do{ if(loglevel()<=LOG_INFO) logmsg(LOG_INFO, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGWARN0(msg) \
	do{ if(loglevel()<=LOG_WARN) logmsg(LOG_WARN, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGERROR0(msg) \
	do{ if(loglevel()<=LOG_ERROR) logmsg(LOG_ERROR, "[%s:%d] %s", __FILE__, __LINE__, msg); } while (0)

#define LOGFATAL0(msg) \
	do{ if(loglevel()<=LOG_FATAL) { fprintf(stderr, "[%s:%d] %s", __FILE__, __LINE__, msg); \
		logmsg(LOG_FATAL, "[%s:%d] %s", __FILE__, __LINE__, msg); } } while (0)

#define LOGTRACE(fmt, ...) \
	do{ if(loglevel()<=LOG_TRACE) logmsg(LOG_TRACE, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGDEBUG(fmt, ...) \
	do{ if(loglevel()<=LOG_DEBUG) logmsg(LOG_DEBUG, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGINFO(fmt, ...) \
	do{ if(loglevel()<=LOG_INFO) logmsg(LOG_INFO, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGWARN(fmt, ...) \
	do{ if(loglevel()<=LOG_WARN) logmsg(LOG_WARN, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGERROR(fmt, ...) \
	do{ if(loglevel()<=LOG_ERROR) logmsg(LOG_ERROR, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); } while (0)

#define LOGFATAL(fmt, ...) \
	do{ if(loglevel()<=LOG_FATAL) { fprintf(stderr, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__); \
		logmsg(LOG_FATAL, "[%s:%d] " fmt, __FILE__, __LINE__, __VA_ARGS__);} } while (0)

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
void* pop_queue_wait(struct queue_t* queue);
size_t len_queue(struct queue_t* queue);
void* get_queue(struct queue_t* queue, size_t index);
void destory_queue(struct queue_t* queue);

size_t count_char(const char* str, const char c);
char* GetValue(const char* confname, const char* name, char* value, size_t len);

char* strlwr(char *str);	// str2low

int64_t htonll(int64_t n);
int64_t ntohll(int64_t n);

int code_convert(char *from_charset, char *to_charset, char *inbuf, int inlen, char *outbuf, int outlen);
int u2g(char *inbuf, int inlen, char *outbuf, int outlen);
int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen);

#endif

