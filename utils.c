#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <execinfo.h>
#include <errno.h>
#include <limits.h>
#include <iconv.h>
#include <dirent.h>
#include <utils.h>

extern const char* CONFIG_PATH;
static int g_drop_data_log_func_on = 0;
static int g_data_items_log_func_on = 0;
static time_t g_ddl_starttime = 0;
static time_t g_ddl_endtime = 0;
static time_t g_dil_starttime = 0;
static time_t g_dil_endtime = 0;

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


#define LOG_FOLDER "./agent_log/"
#define DROP_DATA_LOG_FOLDER "./drop_data_log/"
#define DATA_ITEMS_LOG_FOLDER "./data_items_log/"

static LogFileDef g_fileLog = {0, NULL, 0, 0, {0}, {0}};
static LogFileDef g_fileDropDataLog = {0, NULL, 0, 0, {0}, {0}};
static LogFileDef g_fileDataItemsLog = {0, NULL, 0, 0, {0}, {0}};

static int g_nLogDays = 15;
static size_t LOG_LENGTH_MAX = 256 * 1024 * 1024;

static pthread_mutex_t _loglock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _loglock_dropdata = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t _loglock_dataitems = PTHREAD_MUTEX_INITIALIZER;

inline int file_log_level()
{
	return g_fileLog.nLevel;
}

int LogFileFilter(const struct dirent *dp)
{
    if (strstr(dp->d_name, ".log") != NULL)
    {
       return 1;
    }
   
    return 0;
}  

int open_log(int nLevel, const char *pszFolder, LogFileDef *pLogFile)
{
	assert((nLevel >= 0) && (nLevel <= LOG_FATAL));

	if (access(pszFolder, F_OK) != 0)
		if (mkdir(pszFolder, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0)
			return -1;
		
	pLogFile->nLevel = nLevel;

	char szFileSize[10] = {0};
	GetValue(CONFIG_PATH, "log_file_size", szFileSize, 7);
	int nFileSize = atoi(szFileSize);
	pLogFile->nMaxSize = ((nFileSize < 10) || (nFileSize > 1024)) ? LOG_LENGTH_MAX : (nFileSize * 1024 * 1024);
	
	strcpy(pLogFile->szFileName, pszFolder);

	time_t now = time(NULL);
	struct tm t = {0};
	pLogFile->tmPre = now;
	strftime(pLogFile->szCurDate, sizeof(pLogFile->szCurDate), "%Y-%m-%d", localtime_r(&now, &t));
	strcat(pLogFile->szFileName, pLogFile->szCurDate);
	strcat(pLogFile->szFileName, ".log");
	int nFileExist = exist_file(pLogFile->szFileName);
	
	pLogFile->pFile = fopen(pLogFile->szFileName, "a");
	if (NULL == pLogFile->pFile) 
	{
		printf("Fail to create log file %s.\n", pLogFile->szFileName);
		return -2;
	}

	if ((strcmp(pszFolder, DROP_DATA_LOG_FOLDER) == 0) && (0 == nFileExist))
	{
		fprintf(pLogFile->pFile, "日志时间\t文件行\t读者IP\t服务器IP\t丢弃类型\t组包开始时间\t最后组包时间\t会话丢弃时间\t请求URL\n");
	}

	if ((strcmp(pszFolder, DATA_ITEMS_LOG_FOLDER) == 0) && (0 == nFileExist))
	{
		fprintf(pLogFile->pFile, "日志时间\t文件行\t读者IP\t服务器IP\t组包开始时间\t组包完成时间\t组包耗时(ms)\t内容大小\t状态值\t请求URL\n");
	}
	
	return 0;
}

void open_all_log(int nLevel)
{
	open_log(nLevel, LOG_FOLDER, &g_fileLog);

	char szDropDataLogFunc[10] = {0};
	GetValue(CONFIG_PATH, "drop_data_log_func", szDropDataLogFunc, 6);
	if (strcmp(szDropDataLogFunc, "true") == 0)
		g_drop_data_log_func_on = 1;

	if (g_drop_data_log_func_on)
	{
		char szStartTime[30] = {0};
		char szEndTime[30] = {0};
		GetValue(CONFIG_PATH, "drop_data_log_starttime", szStartTime, 25);
		GetValue(CONFIG_PATH, "drop_data_log_endtime", szEndTime, 25);
		g_ddl_starttime = dtstr2time(szStartTime);
		g_ddl_endtime = dtstr2time(szEndTime);

		int nRs = 1;
		if (g_ddl_starttime > 0 && g_ddl_endtime > 0 && g_ddl_endtime <= g_ddl_starttime)
		{
			nRs = 0;
			printf("Drop Data Log Function:OFF (End Time less than Start Time)\n");
		}
		else if (g_ddl_endtime > 0 && g_ddl_endtime <= time(NULL))
		{
			nRs = 0;
			printf("Drop Data Log Function:OFF (End Time less than Current Time)\n");
		}
		
		if (nRs)
		{
			struct tm tmStart = {0}, tmEnd = {0};
			char szStarttime[30] = "Ignore";
			char szEndtime[30] = "Ignore";
			if (g_ddl_starttime > 0)
				strftime(szStarttime, sizeof(szStarttime), "%F %T", localtime_r(&g_ddl_starttime, &tmStart));

			if (g_ddl_endtime > 0)
				strftime(szEndtime, sizeof(szEndtime), "%F %T", localtime_r(&g_ddl_endtime, &tmEnd));

			printf("Drop Data Log Function:ON (Start Time:%s; End Time:%s)\n", szStarttime, szEndtime);
			open_log(0, DROP_DATA_LOG_FOLDER, &g_fileDropDataLog);
		}
		else
			g_drop_data_log_func_on = 0;
	}
	else
		printf("Drop Data Log Function:OFF\n");
	
	char szDataItemsLogFnnc[10] = {0};
	GetValue(CONFIG_PATH, "data_items_log_func", szDataItemsLogFnnc, 6);
	if (strcmp(szDataItemsLogFnnc, "true") == 0)
		g_data_items_log_func_on = 1;

	if (g_data_items_log_func_on)
	{
		char szStartTime[30] = {0};
		char szEndTime[30] = {0};
		GetValue(CONFIG_PATH, "data_items_log_starttime", szStartTime, 25);
		GetValue(CONFIG_PATH, "data_items_log_endtime", szEndTime, 25);
		g_dil_starttime = dtstr2time(szStartTime);
		g_dil_endtime = dtstr2time(szEndTime);

		int nRs = 1;
		if (g_dil_starttime > 0 && g_dil_endtime > 0 && g_dil_endtime <= g_dil_starttime)
		{
			nRs = 0;
			printf("Data Items Log Function:OFF (End Time less than Start Time)\n");
		}
		else if (g_dil_endtime > 0 && g_dil_endtime <= time(NULL))
		{
			nRs = 0;
			printf("Data Items Log Function:OFF (End Time less than Current Time)\n");
		}

		if (nRs)
		{
			struct tm tmStart = {0}, tmEnd = {0};
			char szStarttime[30] = "Ignore";
			char szEndtime[30] = "Ignore";
			if (g_dil_starttime > 0)
				strftime(szStarttime, sizeof(szStarttime), "%F %T", localtime_r(&g_dil_starttime, &tmStart));

			if (g_dil_endtime > 0)
				strftime(szEndtime, sizeof(szEndtime), "%F %T", localtime_r(&g_dil_endtime, &tmEnd));

			printf("Data Items Log Function:ON (Start Time:%s; End Time:%s)\n", szStarttime, szEndtime);
			open_log(0, DATA_ITEMS_LOG_FOLDER, &g_fileDataItemsLog);
		}
		else
			g_data_items_log_func_on = 0;
	}
	else
		printf("Data Items Log Function:OFF\n");
}

int is_log_drop_data()
{
	if (!g_drop_data_log_func_on)
		return 0;

	time_t now = time(NULL);
	if ((g_ddl_starttime <= now) && ((g_ddl_endtime >= now) || (g_ddl_endtime < 0)))
		return 1;

	return 0;		
}

int is_log_data_items()
{
	if (!g_data_items_log_func_on)
		return 0;

	time_t now = time(NULL);
	if ((g_dil_starttime <= now) && ((g_dil_endtime >= now) || (g_dil_endtime < 0)))
		return 1;

	return 0;		
}

int logmsg(int level, const char* fmt, ... )
{
	static const char* _LOG_LEVEL[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "FIX" };
	assert(level >= 0 && level < sizeof(_LOG_LEVEL)/sizeof(_LOG_LEVEL[0]));

	if (level < g_fileLog.nLevel) 
		return 0;
	
	int nErr = pthread_mutex_lock(&_loglock);
	if (nErr != 0) 
		perror("[ERROR] Fail to lock _loglock.");

	if (NULL == g_fileLog.pFile) 
	{
		if (open_log(g_fileLog.nLevel, LOG_FOLDER, &g_fileLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock log_lock.");
			
			return -1;
		}
	}
	
	time_t now = time(NULL);
	struct tm t = {0};
	char timebuf[30] = {0};
	localtime_r(&now, &t);
	strftime(timebuf, sizeof(timebuf), "%F %T", &t);

	//Check if next day
	char szTmpDate[11] = {0};
	strftime(szTmpDate, sizeof(szTmpDate), "%Y-%m-%d", &t);
	if (strcmp(szTmpDate, g_fileLog.szCurDate) != 0)
	{
		char szBakFileName[512] = {0};
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&g_fileLog.tmPre, &t));
		sprintf(szBakFileName, "%s%s_%s.log", LOG_FOLDER, g_fileLog.szCurDate, szHM);

		int nLevel = g_fileLog.nLevel;
		fclose(g_fileLog.pFile);
		rename(g_fileLog.szFileName, szBakFileName);

		CheckLogFullDays(LOG_FOLDER, g_nLogDays);
		
		g_fileLog.pFile = NULL;
		g_fileLog.tmPre = 0;
		memset(g_fileLog.szCurDate, 0, sizeof(g_fileLog.szCurDate));
		memset(g_fileLog.szFileName, 0, sizeof(g_fileLog.szFileName));
		if (open_log(nLevel, LOG_FOLDER, &g_fileLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock log_lock.");
			
			return -1;
		}
	}
	g_fileLog.tmPre = now;
	
	va_list ap;
	va_start(ap, fmt);

	fprintf(g_fileLog.pFile, "%s %s: ", timebuf, _LOG_LEVEL[level]);
	int nRet = vfprintf(g_fileLog.pFile, fmt, ap);
	fprintf(g_fileLog.pFile, "\n");
	
	va_end(ap);

	if (ftell(g_fileLog.pFile) >= g_fileLog.nMaxSize) 
	{
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&now, &t));
		
		char szBakFileName[512] = {0};
		sprintf(szBakFileName, "%s%s_%s.log", LOG_FOLDER, g_fileLog.szCurDate, szHM);

		fclose(g_fileLog.pFile);
		rename(g_fileLog.szFileName, szBakFileName);

		g_fileLog.pFile = NULL;
		g_fileLog.tmPre = 0;
		memset(g_fileLog.szCurDate, 0, sizeof(g_fileLog.szCurDate));
		memset(g_fileLog.szFileName, 0, sizeof(g_fileLog.szFileName));
		open_log(g_fileLog.nLevel, LOG_FOLDER, &g_fileLog);
	}
	
	nErr = pthread_mutex_unlock(&_loglock);
	if (nErr != 0) 
		perror("[ERROR] Fail to unlock log_lock.");
	
	fflush(stdout);
	return nRet;
}

int log_drop_data(const char* fmt, ... )
{
	int nErr = pthread_mutex_lock(&_loglock_dropdata);
	if (nErr != 0) 
		perror("[ERROR] Fail to lock _loglock_dropdata.");

	if (NULL == g_fileDropDataLog.pFile) 
	{
		if (open_log(g_fileDropDataLog.nLevel, DROP_DATA_LOG_FOLDER, &g_fileDropDataLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock_dropdata);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock loglock_dropdata.");
			
			return -1;
		}
	}
	
	time_t now = time(NULL);
	struct tm t = {0};
	char timebuf[30] = {0};
	localtime_r(&now, &t);
	strftime(timebuf, sizeof(timebuf), " %F %T", &t);

	//Check if next day
	char szTmpDate[11] = {0};
	strftime(szTmpDate, sizeof(szTmpDate), "%Y-%m-%d", &t);
	if (strcmp(szTmpDate, g_fileDropDataLog.szCurDate) != 0)
	{
		char szBakFileName[512] = {0};
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&g_fileDropDataLog.tmPre, &t));
		sprintf(szBakFileName, "%s%s_%s.log", DROP_DATA_LOG_FOLDER, g_fileDropDataLog.szCurDate, szHM);

		int nLevel = g_fileDropDataLog.nLevel;
		fclose(g_fileDropDataLog.pFile);
		rename(g_fileDropDataLog.szFileName, szBakFileName);

		CheckLogFullDays(DROP_DATA_LOG_FOLDER, g_nLogDays);
		
		g_fileDropDataLog.pFile = NULL;
		g_fileDropDataLog.tmPre = 0;
		memset(g_fileDropDataLog.szCurDate, 0, sizeof(g_fileDropDataLog.szCurDate));
		memset(g_fileDropDataLog.szFileName, 0, sizeof(g_fileDropDataLog.szFileName));
		if (open_log(nLevel, DROP_DATA_LOG_FOLDER, &g_fileDropDataLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock_dropdata);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock loglock_dropdata.");
			
			return -1;
		}
	}
	g_fileDropDataLog.tmPre = now;

	va_list ap;
	va_start(ap, fmt);

	fprintf(g_fileDropDataLog.pFile, "%s\t", timebuf);
	int nRet = vfprintf(g_fileDropDataLog.pFile, fmt, ap);
	fprintf(g_fileDropDataLog.pFile, "\n");
	
	va_end(ap);

	if (ftell(g_fileDropDataLog.pFile) >= g_fileDropDataLog.nMaxSize) 
	{
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&now, &t));
		
		char szBakFileName[512] = {0};
		sprintf(szBakFileName, "%s%s_%s.log", DROP_DATA_LOG_FOLDER, g_fileDropDataLog.szCurDate, szHM);

		fclose(g_fileDropDataLog.pFile);
		rename(g_fileDropDataLog.szFileName, szBakFileName);

		g_fileDropDataLog.pFile = NULL;
		g_fileDropDataLog.tmPre = 0;
		memset(g_fileDropDataLog.szCurDate, 0, sizeof(g_fileDropDataLog.szCurDate));
		memset(g_fileDropDataLog.szFileName, 0, sizeof(g_fileDropDataLog.szFileName));
		open_log(g_fileDropDataLog.nLevel, DROP_DATA_LOG_FOLDER, &g_fileDropDataLog);
	}
	
	nErr = pthread_mutex_unlock(&_loglock_dropdata);
	if (nErr != 0) 
		perror("[ERROR] Fail to unlock loglock_dropdata.");
	
	fflush(stdout);
	return nRet;
}

int log_data_items(const char* fmt, ... )
{
	int nErr = pthread_mutex_lock(&_loglock_dataitems);
	if (nErr != 0) 
		perror("[ERROR] Fail to lock _loglock_dataitems.");

	if (NULL == g_fileDataItemsLog.pFile) 
	{
		if (open_log(g_fileDataItemsLog.nLevel, DATA_ITEMS_LOG_FOLDER, &g_fileDataItemsLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock_dataitems);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock loglock_dataitems.");
			
			return -1;
		}
	}
	
	time_t now = time(NULL);
	struct tm t = {0};
	char timebuf[30] = {0};
	localtime_r(&now, &t);
	strftime(timebuf, sizeof(timebuf), " %F %T", &t);

	//Check if next day
	char szTmpDate[11] = {0};
	strftime(szTmpDate, sizeof(szTmpDate), "%Y-%m-%d", &t);
	if (strcmp(szTmpDate, g_fileDataItemsLog.szCurDate) != 0)
	{
		char szBakFileName[512] = {0};
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&g_fileDataItemsLog.tmPre, &t));
		sprintf(szBakFileName, "%s%s_%s.log", DATA_ITEMS_LOG_FOLDER, g_fileDataItemsLog.szCurDate, szHM);

		int nLevel = g_fileDataItemsLog.nLevel;
		fclose(g_fileDataItemsLog.pFile);
		rename(g_fileDataItemsLog.szFileName, szBakFileName);

		CheckLogFullDays(DATA_ITEMS_LOG_FOLDER, g_nLogDays);
		
		g_fileDataItemsLog.pFile = NULL;
		g_fileDataItemsLog.tmPre = 0;
		memset(g_fileDataItemsLog.szCurDate, 0, sizeof(g_fileDataItemsLog.szCurDate));
		memset(g_fileDataItemsLog.szFileName, 0, sizeof(g_fileDataItemsLog.szFileName));
		if (open_log(nLevel, DATA_ITEMS_LOG_FOLDER, &g_fileDataItemsLog) < 0)
		{
			nErr = pthread_mutex_unlock(&_loglock_dataitems);
			if (nErr != 0) 
				perror("[ERROR] Fail to unlock loglock_dataitems.");
			
			return -1;
		}
	}
	g_fileDataItemsLog.tmPre = now;

	va_list ap;
	va_start(ap, fmt);

	fprintf(g_fileDataItemsLog.pFile, "%s\t", timebuf);
	int nRet = vfprintf(g_fileDataItemsLog.pFile, fmt, ap);
	fprintf(g_fileDataItemsLog.pFile, "\n");
	
	va_end(ap);

	if (ftell(g_fileDataItemsLog.pFile) >= g_fileDataItemsLog.nMaxSize) 
	{
		char szHM[5] = {0};
		memset(&t, 0, sizeof(t));
		strftime(szHM, sizeof(szHM), "%H%M", localtime_r(&now, &t));
		
		char szBakFileName[512] = {0};
		sprintf(szBakFileName, "%s%s_%s.log", DATA_ITEMS_LOG_FOLDER, g_fileDataItemsLog.szCurDate, szHM);

		fclose(g_fileDataItemsLog.pFile);
		rename(g_fileDataItemsLog.szFileName, szBakFileName);

		g_fileDataItemsLog.pFile = NULL;
		g_fileDataItemsLog.tmPre = 0;
		memset(g_fileDataItemsLog.szCurDate, 0, sizeof(g_fileDataItemsLog.szCurDate));
		memset(g_fileDataItemsLog.szFileName, 0, sizeof(g_fileDataItemsLog.szFileName));
		open_log(g_fileDataItemsLog.nLevel, DATA_ITEMS_LOG_FOLDER, &g_fileDataItemsLog);
	}
	
	nErr = pthread_mutex_unlock(&_loglock_dataitems);
	if (nErr != 0) 
		perror("[ERROR] Fail to unlock loglock_dataitems.");
	
	fflush(stdout);
	return nRet;
}

void close_all_log()
{
	if (g_fileLog.pFile != NULL) 
		fclose(g_fileLog.pFile);

	if (g_fileDataItemsLog.pFile != NULL) 
		fclose(g_fileDataItemsLog.pFile);

	if (g_fileDropDataLog.pFile != NULL) 
		fclose(g_fileDropDataLog.pFile);
}

void CheckLogFullDays(const char *pszFolder, int nFullDays)
{
	if (0 == nFullDays)
		return;
	
	struct dirent** pDent;
	int nCount = 0;
	nCount = scandir(pszFolder,
                     &pDent,
                     LogFileFilter,
                     alphasort);

	char szDate[11] = {0};
	char szFirstDate[11] = {0};
	char szLatestDate[11] = {0};
	int nDays = 0;
	if (nCount > 0)
    {
    	for (int i = 0; i < nCount; i++)
		{
			char* pszLatestFileName = strdup(pDent[i]->d_name);
			if (strstr(pszLatestFileName, ".log") != NULL)
			{
				if (szFirstDate[0] == '\0')
					strncpy(szFirstDate, pszLatestFileName, 10);
					
				strncpy(szLatestDate, pszLatestFileName, 10);
				if (strcmp(szDate, szLatestDate) != 0)
				{
					strcpy(szDate, szLatestDate);
					nDays++;
				}
			}
			
			free(pszLatestFileName);
		}
		
		while (nCount--)
		{
			free(pDent[nCount]);
		}
		free(pDent);
    }

	if (nDays >= nFullDays)
	{
		char szDelFile[512] = {0};
		sprintf(szDelFile, "rm %s%s*.log", pszFolder, szFirstDate);
		//unlink(szDelFile);
		system(szDelFile);
	}
}

void print_bt()
{
	void *frameptr[10];
	char **pStrings;
	int nFrames = backtrace(frameptr, 10);
	pStrings = backtrace_symbols(frameptr, nFrames);
	if (pStrings != NULL)
	{
		for (int i = 0; i < nFrames; i++)
		{
			LOGERROR("%s", pStrings[i]);
		}
		free(pStrings);
		pStrings = NULL;
	}
	
	//backtrace_symbols_fd(frameptr, nFrames, STDERR_FILENO);
}

////////// fixed-length queue
struct _queue_fixed
{
	volatile unsigned max_size;
	volatile unsigned size;
	volatile unsigned head;
	volatile unsigned tail;
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

int code_convert(char *from_charset, char *to_charset, char *inbuf, int inlen, char *outbuf, int outlen)
{  
	iconv_t cd;
	char **pin = &inbuf;
	char **pout = &outbuf;

	cd = iconv_open(to_charset, from_charset);
	if (0 == cd)  
	{
		LOGERROR("iconv_open error, %s", strerror(errno));
		return -1;
	}

	memset(outbuf, 0, outlen);
	if (iconv(cd, pin, &inlen, pout, &outlen) == -1)  
	{
		LOGERROR("iconv error, %s", strerror(errno));
		return -1;
	}

	iconv_close(cd);
	return 0;
}  

int u2g(char *inbuf, int inlen, char *outbuf, int outlen)
{  
	return code_convert("utf-8","gb2312", inbuf, inlen, outbuf, outlen);
}  

int g2u(char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{  
	return code_convert("gb2312", "utf-8", inbuf, inlen, outbuf, outlen);
}  


