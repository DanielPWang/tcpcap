#ifndef __CACHE_FILE_H__
#define __CACHE_FILE_H__

#include <stdint.h>

//#define _LARGEFILE64_SOURCE 
//#define _FILE_OFFSET_BITS 64
#define CACHE_FILE_FOLDER "./cachefiles/"
#define DEFAULT_FILE_SIZE (1024*1024*1024*2)
#define FILE_HEAD_LEN 31

typedef struct CacheFile 
{
	FILE* pFile;
	char szFileName[1024];
	char szVersion[5];
	uint64_t nFileSize;
	uint64_t nReadOffset;
	uint64_t nWriteOffset;
	int nReadCount;
	int nWriteCount;
	int nFirstWriteFlag;
} CacheFileDef;

void SetCacheFileSize(int nSize);
int IsCacheFullDays(int nFullDays);
int IsReadEnd(CacheFileDef* pCacheFile);
int IsWriteFull(CacheFileDef* pCacheFile);
int GetCacheFileVersion(CacheFileDef* pCacheFile, char* pszVersion);
int GetLatestCacheFile(CacheFileDef* pCacheFile);
int GetNewCacheFileName(char* pszFileName);
int CreateNewCacheFile(CacheFileDef* pCacheFile);
int GetCacheFileForWrite(CacheFileDef* pCacheFile);
int ReadNextCacheRecord(CacheFileDef* pCacheFile, char** pBuffer);
int WriteNextCacheRecord(CacheFileDef* pCacheFile, const char* pBuffer, int nLen);
int CleanCacheFile(CacheFileDef* pCacheFile, int bIsDel);
int FileFilter(const struct dirent *dp);


#endif

