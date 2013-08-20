#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <assert.h>
#include <utils.h>
#include <errno.h>
#include <cache_file.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

static uint64_t g_nCacheFileSize = DEFAULT_FILE_SIZE;

void SetCacheFileSize(int nSize)
{
	g_nCacheFileSize = nSize * 1024 * 1024;
}

int IsCacheFullDays(int nFullDays)
{
	assert(nFullDays > 0);
	
	struct dirent** pDent;
	int nCount = 0;
	nCount = scandir(CACHE_FILE_FOLDER,
                     &pDent,
                     FileFilter,
                     alphasort);

	char szDate[11] = {0};
	int nDays = 0;
	if (nCount > 0)
    {
    	char szLatestDate[11] = {0};
    	for (int i = nCount-1; i >= 0; i--)
		{
			char* pszLatestFileName = strdup(pDent[i]->d_name);
			if (strncmp(pszLatestFileName, "acf", 3) == 0)
			{
				strncpy(szLatestDate, pszLatestFileName+4, 10);
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
	
	return (nDays > nFullDays);
}

int IsReadEnd(CacheFileDef* pCacheFile)
{
	assert (pCacheFile != NULL && pCacheFile->pFile != NULL);

	int nRs = 0;
	if (pCacheFile->nReadCount == pCacheFile->nWriteCount)
		nRs = 1;
	
	return nRs;
}

int IsWriteFull(CacheFileDef* pCacheFile)
{
	assert (pCacheFile != NULL && pCacheFile->pFile != NULL);
	
	int nRs = 0;
	if (pCacheFile->nFileSize >= g_nCacheFileSize)
		nRs = 1;
	
	return nRs;
}

int GetCacheFileVersion(CacheFileDef* pCacheFile, char* pszVersion)
{
	assert (pCacheFile != NULL && pCacheFile->pFile != NULL && pszVersion != NULL);

	int nRs = 0;
	char szCacheFileFlag[4] = {0};
	rewind(pCacheFile->pFile);
	if (fread(szCacheFileFlag, sizeof(char), 3, pCacheFile->pFile) == 3)
	{
		if (strncmp(szCacheFileFlag, "acf", 3) == 0)
		{
			if (fread(pszVersion, sizeof(char), 4, pCacheFile->pFile) != 4)
			{
				nRs = -3;
			}
		}
		else
		{
			nRs = -2;
		}
	}
	else
	{
		nRs = -1;
	}
	
	return nRs;
}

int GetLatestCacheFile(CacheFileDef* pCacheFile)
{
	assert (pCacheFile != NULL);

	int nRs = -1;
	struct dirent** pDent;
	int nCount = 0;
	nCount = scandir(CACHE_FILE_FOLDER,
                     &pDent,
                     FileFilter,
                     alphasort);

	if (nCount > 0)
    {
    	char szLatestDate[11] = {0};
		char* pszLatestFileName = NULL;
		for (int i = nCount-1; i >= 0; i--)
		{
			pszLatestFileName = strdup(pDent[i]->d_name);
			if (strncmp(pszLatestFileName, "acf", 3) == 0)
			{
				char szPathFile[512] = {0};
				strcpy(pCacheFile->szFileName, pszLatestFileName);
				sprintf(szPathFile, "%s%s", CACHE_FILE_FOLDER, pCacheFile->szFileName);
				pCacheFile->pFile = fopen(szPathFile, "rb+");
				if (pCacheFile->pFile != NULL)
				{
					if (GetCacheFileVersion(pCacheFile, pCacheFile->szVersion) == 0)
					{
						if (strcmp(pCacheFile->szVersion, "v1.0") == 0)
						{
							fread(&pCacheFile->nWriteCount, sizeof(int), 1, pCacheFile->pFile);
							fread(&pCacheFile->nReadCount, sizeof(int), 1, pCacheFile->pFile);
							fread(&pCacheFile->nReadOffset, sizeof(uint64_t), 1, pCacheFile->pFile);
							fread(&pCacheFile->nWriteOffset, sizeof(uint64_t), 1, pCacheFile->pFile);
							fseeko(pCacheFile->pFile, 0, SEEK_END);
							pCacheFile->nFileSize = ftello(pCacheFile->pFile);
							nRs = 0;
						}
						else
						{
							CleanCacheFile(pCacheFile, 0);
						}
					}
					else
					{
						CleanCacheFile(pCacheFile, 0);
					}
				}
				else
				{
					CleanCacheFile(pCacheFile, 0);
				}

				if (0 == nRs)
				{
					free(pszLatestFileName);
					break;
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
	
	return nRs;
}

int GetNewCacheFileName(char* pszFileName)
{
	assert (pszFileName != NULL);
	
	struct dirent** pDent;
	int nCount = 0;
	nCount = scandir(CACHE_FILE_FOLDER,
                     &pDent,
                     FileFilter,
                     alphasort);

	int nNum = 1;
	char szCurDate[11] = {0};
	time_t now = time(NULL);
	struct tm t;
	strftime(szCurDate, sizeof(szCurDate), "%Y-%m-%d", localtime_r(&now, &t));
    if (nCount > 0)
    {
    	char szLatestDate[11] = {0};
		for (int i = nCount-1; i >= 0; i--)
		{
			char* pszLatestFileName = strdup(pDent[i]->d_name);
			if (strncmp(pszLatestFileName, "acf", 3) == 0)
			{
				char szNum[5] = {0};
				strncpy(szLatestDate, pszLatestFileName+4, 10);
				if (strcmp(szCurDate, szLatestDate) == 0)
				{
					strncpy(szNum, 
						    pszLatestFileName+15,
						    (strchr(pszLatestFileName, '.') - pszLatestFileName)-15);

					nNum = atoi(szNum) + 1;
				}

				free(pszLatestFileName);
				break;
			}
			
			free(pszLatestFileName);
		}
		
		while (nCount--)
		{
			free(pDent[nCount]);
		}
		free(pDent);
    }

	sprintf(pszFileName, "acf_%s_%d.cache", szCurDate, nNum);
	
	return 0;
}

int CreateNewCacheFile(CacheFileDef* pCacheFile)
{
	assert (pCacheFile != NULL);

	int nRs = 0;
	CleanCacheFile(pCacheFile, 0);
	if (access(CACHE_FILE_FOLDER, F_OK) != 0)
		if (mkdir(CACHE_FILE_FOLDER, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0)
			nRs = -1;
	
	if ((0 == nRs) && (GetNewCacheFileName(pCacheFile->szFileName) == 0))
	{
		char szPathFile[512] = {0};
		sprintf(szPathFile, "%s%s", CACHE_FILE_FOLDER, pCacheFile->szFileName);
		pCacheFile->pFile = fopen(szPathFile, "wb");
		if (NULL == pCacheFile->pFile) 
		{
			CleanCacheFile(pCacheFile, 0);
			nRs = -2;
		}
		else
		{
			char szFlag[4] = "acf";
			char szVersion[5] = "v1.0";
			int nReadCount = 0;
			int nWriteCount = 0;
			uint64_t nOffset = 0;	
			strcpy(pCacheFile->szVersion, "v1.0");
			pCacheFile->nFileSize = FILE_HEAD_LEN;
			nRs = -3;
			if (fwrite(szFlag, sizeof(char), 3, pCacheFile->pFile) == 3)
				if (fwrite(szVersion, sizeof(char), 4, pCacheFile->pFile) == 4)
					if (fwrite(&nWriteCount, sizeof(int), 1, pCacheFile->pFile) == 1)
						if (fwrite(&nReadCount, sizeof(int), 1, pCacheFile->pFile) == 1)
							if (fwrite(&nOffset, sizeof(uint64_t), 1, pCacheFile->pFile) == 1)
								if (fwrite(&nOffset, sizeof(uint64_t), 1, pCacheFile->pFile) == 1)
									nRs = 0;					
		}
	}
	
	return nRs;
}

int GetCacheFileForWrite(CacheFileDef* pCacheFile)
{
	assert (pCacheFile != NULL);

	int nRs = 0;
	if (GetLatestCacheFile(pCacheFile) == 0)
	{
		char szCurDate[11] = {0};
		time_t now = time(NULL);
		struct tm t;
		strftime(szCurDate, sizeof(szCurDate), "%Y-%m-%d", localtime_r(&now, &t));

		if (strncmp(szCurDate, pCacheFile->szFileName+4, 10) != 0)
		{
			nRs = CreateNewCacheFile(pCacheFile);
		}
		else
		{
			if (IsWriteFull(pCacheFile))
			{
				nRs = CreateNewCacheFile(pCacheFile);	
			}
		}
	}
	else
	{
		nRs = CreateNewCacheFile(pCacheFile);
	}
	
	return nRs;
}

int ReadNextCacheRecord(CacheFileDef* pCacheFile, char** pBuffer)
{
	assert (pCacheFile != NULL && pCacheFile->pFile != NULL);

	int nRs = 0;
	int nDataLen = 0;
	int nRead = 0;
	int nReadTotal = 0;
	char *pReadBuffer = NULL;

	if (!IsReadEnd(pCacheFile))
	{
		fseeko(pCacheFile->pFile, pCacheFile->nReadOffset + FILE_HEAD_LEN, SEEK_SET);
		fread(&nDataLen, sizeof(int), 1, pCacheFile->pFile);
		if (nDataLen > 0)
		{
			pReadBuffer = (char*)calloc(1, nDataLen);
			if (pReadBuffer != NULL)
			{
				while (!feof(pCacheFile->pFile) && (nReadTotal < nDataLen))
				{
					nRead = fread(pReadBuffer+nReadTotal, sizeof(char), nDataLen-nReadTotal, pCacheFile->pFile);
					nReadTotal += nRead;
				}
			}
			else
			{
				LOGERROR("Mallocate memory failed. File name is %s, Offset=%llu, Read count=%d, Data length=%d", 
							pCacheFile->szFileName, pCacheFile->nReadOffset, pCacheFile->nReadCount, nDataLen);
				
				nRs = -2;			
			}
		}
		else
		{
			nRs = -3;
		}

		if (0 == nRs)
		{
			pCacheFile->nReadCount++;
			fseeko(pCacheFile->pFile, 11, SEEK_SET);
			if (fwrite(&pCacheFile->nReadCount, sizeof(int), 1, pCacheFile->pFile) != 1)
				nRs = -4;
			
			pCacheFile->nReadOffset += nReadTotal + sizeof(int);
			if (fwrite(&pCacheFile->nReadOffset, sizeof(uint64_t), 1, pCacheFile->pFile) != 1)
				nRs = -5;
			
			if (0 == nRs)
			{
				nRs = nReadTotal;
			}
			else if (pReadBuffer != NULL)
			{
				free(pReadBuffer);
				pReadBuffer = NULL;
			}
		}
	}
	else
	{
		nRs = -1;
	}
	
	*pBuffer = pReadBuffer;
	return nRs;
}

int WriteNextCacheRecord(CacheFileDef* pCacheFile, const char* pBuffer, int nLen)
{
	assert (pCacheFile != NULL && pCacheFile->pFile != NULL && pBuffer != NULL);

	int nWrite = 0;
	int nWriteTotal = 0;
	int nRs = 0;

	if (pCacheFile->nFirstWriteFlag)
	{
		fseeko(pCacheFile->pFile, pCacheFile->nWriteOffset + FILE_HEAD_LEN, SEEK_SET);
		pCacheFile->nFirstWriteFlag = 0;
	}
	else
		fseeko(pCacheFile->pFile, 0, SEEK_END);
	
	if (fwrite(&nLen, sizeof(int), 1, pCacheFile->pFile) == 1)
	{
		while (nWriteTotal < nLen)
		{
			if ((nWrite = fwrite(pBuffer+nWriteTotal, sizeof(char), nLen-nWriteTotal, pCacheFile->pFile)) < (nLen-nWriteTotal) && (errno == ENOSPC))
			{
				nRs = -2;
				break;
			}
			nWriteTotal += nWrite;
		}
		
		if (0 == nRs)
		{
			pCacheFile->nWriteOffset += nWriteTotal + sizeof(int);
			fseeko(pCacheFile->pFile, 23, SEEK_SET);			
			if (fwrite(&pCacheFile->nWriteOffset, sizeof(uint64_t), 1, pCacheFile->pFile) != 1)
				nRs = -3;
		}

		if (0 == nRs)
		{
			pCacheFile->nWriteCount++;
			fseeko(pCacheFile->pFile, 7, SEEK_SET);
			if (fwrite(&pCacheFile->nWriteCount, sizeof(int), 1, pCacheFile->pFile) != 1)
				nRs = -4;
		}

		if (0 == nRs)
		{
			nRs = nWriteTotal;
			pCacheFile->nFileSize += nWriteTotal + sizeof(int);
		}
	}
	else
	{
		nRs = -1;
	}
	
	return nRs;
}

int CleanCacheFile(CacheFileDef* pCacheFile, int bIsDel)
{
	assert (pCacheFile != NULL);

	if (pCacheFile->pFile != NULL)
	{
		fclose(pCacheFile->pFile);
		pCacheFile->pFile = NULL;
	}
	if (bIsDel)
	{
		char szPathFile[512] = {0};
		sprintf(szPathFile, "%s%s", CACHE_FILE_FOLDER, pCacheFile->szFileName);
		unlink(szPathFile);
	}
	
	memset(pCacheFile->szFileName, 0, 1024);
	memset(pCacheFile->szVersion, 0, 5);
	pCacheFile->nFileSize = 0;
	pCacheFile->nReadCount = 0;
	pCacheFile->nWriteCount = 0;
	pCacheFile->nReadOffset = 0;
	pCacheFile->nWriteOffset = 0;
	pCacheFile->nFirstWriteFlag = 1;
	
	return 0;
}

int FileFilter(const struct dirent *dp)
{
    if (strstr(dp->d_name, ".cache") != NULL)
    {
       return 1;
    }
   
    return 0;
}    

