#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <execinfo.h>
#include <errno.h>
#include <limits.h>

#include <utils.h>

static const char* UTIL_SPACES = " \r\n\t";

char* strtrim(char* str, const char* ignore)
{
	if (str == NULL) return NULL;

	// const char* ignore = " \r\n\t";
	size_t j, k;
	j = k = 0;

	// clean right
	while (str[k] != '\0')
	{
		if (strchr(ignore, str[k++]) == NULL) {
			j = k;
		}
	}
	str[j] = '\0';
	if (str[0]=='\0' || strchr(ignore, str[0])==NULL) return str;	// empty or first litter is not ignore.

	// clean left
	j = k = 0;
	while (strchr(ignore, str[k])!=NULL) { ++k; }
	while (str[k] != '\0')
	{
		str[j++] = str[k++];
	}
	str[j] = '\0';
	return str;
}
int split_line( char* line, char** left, char** right, const char delim)
{
	if (line == NULL) return -1;
	
	char* wall = strchr(line, '#');
	if (wall != NULL) *wall = '\0';

	char* equal = strchr(line, delim);
	if (equal == NULL) return -1;

	*left = line;
	*right = equal + 1;
	*equal = '\0';
	strtrim(*left, UTIL_SPACES);
	strtrim(*right, UTIL_SPACES);
	return 0;
}

/** @brief if exist path, return 1. noexist return 0. */
int exist_file(const char* path)
{
	struct stat _stat;
	int nErr = stat(path, &_stat);
	
	return (nErr == 0) ? 1 : 0;
}

int get_file_size(const char *pszFilePath)
{
	assert(pszFilePath != NULL);
	
	int nFilesize = -1;
	struct stat statbuff;
	if(stat(pszFilePath, &statbuff) == 0)
	{
	    nFilesize = statbuff.st_size;
	}
	
	return nFilesize;
}  

int dtstr2time(const char *pszDate)
{ 
	int rs = -1;
	time_t t;
	int year=0, month=0, day=0, hour=0, minute=0, second=0;
	sscanf(pszDate, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second);
	
	if (year<0 || month<0 || day<0 || hour<0 || minute<0 || second<0)
		return -1;

	if (hour>23 || second>60 || minute>60)
		return -1;

	if (month==0 || day==0)
		return -1;
	
	if (month<=12 && day<=31)
	{ 
		if (year%400==0 && month==2 && day<=29)
			rs = 1;
		else if (year%100 !=0 && year%4==0 && month==2 && day<=29) 
	   		rs = 1;
		else if ((month==1||month==3||month==5||month==7||month==8||month==10||month==12) && day<=31)
			rs = 1;
		else if ((month==4||month==6||month==9||month==11) && day<=30)
			rs = 1;
		else if (month==2 && day<=28)
			rs = 1;
		else
			return -1;
	}

	if (1 == rs)
	{
		struct tm stm = {0};
		stm.tm_year = year - 1900;
		stm.tm_mon = month - 1;
		stm.tm_mday = day;
		stm.tm_hour = hour;
	    stm.tm_min = minute;
	    stm.tm_sec = second;
		t = mktime(&stm);
	}
	else
		return -1;
	
	return t;
}
/////////// LOG
static char *_logfile = NULL;
static FILE *_logfd = NULL;
static size_t LOG_LENGTH_MAX = 64 * 1024 * 1024;
static pthread_mutex_t _loglock = PTHREAD_MUTEX_INITIALIZER;
static int _level = 0;

inline int loglevel()
{
	return _level;
}

int open_log(const char* logfile, int level)
{
	assert(level>=0 && level<=LOG_FATAL);

	_level = level;
	if (logfile==NULL || logfile[0]=='\0') {
		_logfd = stderr;
		return 0;
	}
	_logfile = strdup(logfile);
	_logfd = fopen(logfile, "a");
	if (_logfile==NULL || _logfd==NULL) {
		fprintf(stderr, "[ERROR] cant create log file.\n");
		if (_logfd ==NULL) _logfd =stderr;
		return -1;
	}
	return 0;
}
///< not thread safe.
int logmsg(int level, const char* fmt, ... )
{
	static const char* _LOG_LEVEL[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };

	assert(level>-1 && level<sizeof(_LOG_LEVEL)/sizeof(_LOG_LEVEL[0]));
	assert(_logfd != NULL);

	if (level < _level) return 0;

	time_t now = time(NULL);
	struct tm t;
	char timebuf[30];
	strftime(timebuf, sizeof(timebuf), "%F %T", localtime_r(&now, &t));

	int nErr = pthread_mutex_lock(&_loglock);
	if (nErr != 0) perror("[ERROR] cannt lock _loglock.");

	va_list ap;
	va_start(ap, fmt);

	fprintf(_logfd, "%s %s: ", timebuf, _LOG_LEVEL[level]);
	//fprintf(stdout, "%s %s: ", timebuf, _LOG_LEVEL[level]);
	int nRet = vfprintf(_logfd, fmt, ap);
	//vfprintf(stdout, fmt, ap);
	fprintf(_logfd, "\n");
	//fprintf(stdout, "\n");

	va_end(ap);

	if (_logfd!=stderr && ftell(_logfd)>=LOG_LENGTH_MAX) {
		char* filename = (char*)calloc(1,strlen(_logfile) + 3);
		if (filename != NULL) {
			sprintf(filename, "%s.1", _logfile);
			if (exist_file(filename)) unlink(filename);
			fclose(_logfd);
			rename(_logfile, filename);
			_logfd = fopen(_logfile, "a");
			if (_logfd == NULL) _logfd = stderr;
			free(filename);
		}
	}
	if (_logfd==stderr && _logfile!=NULL) {
		_logfd = fopen(_logfile, "a");
		if (_logfd == NULL) _logfd = stderr;
	}
	nErr = pthread_mutex_unlock(&_loglock);
	if (nErr != 0) perror("[ERROR] cannt unlock log_lock.");
	fflush(stdout);
	return nRet;
}

void close_log()
{	// dont need to care.
	if (_logfd != stderr) {
		fclose(_logfd);
		_logfd = stderr;
	}
	free(_logfile);
	_logfile = NULL;
}

void print_bt()
{
	void* frameptr[20];
	int nFrames = backtrace(frameptr, 20);
	backtrace_symbols_fd(&frameptr[2], nFrames-2, STDERR_FILENO);
}


////////// fixed-length queue
struct _queue_fixed
{
	unsigned max_size;
	unsigned size;
	unsigned head;
	unsigned tail;
	pthread_mutex_t lock;
	const void* points[0];
};

struct queue_t* init_queue(size_t size)
{
	assert(size < INT_MAX);
	struct _queue_fixed* queue = calloc(1,sizeof(struct _queue_fixed) + size*sizeof(void*));
	if (queue == NULL) return NULL;
	
	pthread_mutex_init(&queue->lock, NULL);
	queue->size = 0;
	queue->max_size = size;
	queue->head = queue->tail = 0;
	return (struct queue_t*)queue;
}
// success reutrn > -1;
int push_queue(struct queue_t* queue, const void* p)
{
	struct _queue_fixed* _queue = (struct _queue_fixed*)queue;
	int _head = -1;
	
	pthread_mutex_lock(&_queue->lock);
	if (_queue->size < _queue->max_size) {
		_head = _queue->head++;
		if (_queue->head == _queue->max_size) _queue->head = 0;
		_queue->points[_head] = p;
		++_queue->size;
	}
	pthread_mutex_unlock(&_queue->lock);
	return _head;
}
size_t len_queue(struct queue_t* queue)
{
	struct _queue_fixed* _queue = (struct _queue_fixed*)queue;
	return _queue->size;
}
void* get_queue(struct queue_t* queue, size_t index)
{
	struct _queue_fixed* _queue = (struct _queue_fixed*)queue;
	if (index >= _queue->size) return NULL;
	size_t pos = _queue->tail + index;
	if (pos>=_queue->max_size) pos -= _queue->max_size;
	return (void*)_queue->points[pos];
}
void* pop_queue(struct queue_t* queue)
{
	struct _queue_fixed* _queue = (struct _queue_fixed*)queue;

	void *p = NULL;
	pthread_mutex_lock(&_queue->lock);
	if (_queue->size > 0) {
		--_queue->size;
		p = (void*)_queue->points[_queue->tail++];
		if (_queue->tail == _queue->max_size) _queue->tail = 0;
	}
	pthread_mutex_unlock(&_queue->lock);
	return p;
}
void destory_queue(struct queue_t* queue)
{
	struct _queue_fixed* _queue = (struct _queue_fixed*)queue;
	pthread_mutex_destroy(&_queue->lock);
	free(queue);
}
///////////////////////end  queue

size_t count_char(const char* str, const char c)
{
	if (str == NULL) return 0;
	size_t count = 0;
	while (*str) {
		if (*str++ != c) continue;
		++count;
	}
	return count;
}

char* strlwr(char *str)
{
	if (NULL == str)
		return str;

	char *pTmp = str;
	while (*pTmp != '\0')
	{
		if (*pTmp >= 'A' && *pTmp <= 'Z')
			*pTmp += 32;

		pTmp++;
	}

	return str;
}

int64_t htonll(int64_t n)
{
	return (((int64_t)htonl(n)) << 32) | htonl(n >> 32);
}

int64_t ntohll(int64_t n)
{
	return (((int64_t)ntohl(n)) << 32) | ntohl(n >> 32);
}

