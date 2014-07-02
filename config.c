#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include <config.h>

#define CONF_NAME_LEN 128

int GetValue_i(const char* confname, const char* name)
{
	char value[32];
	if (GetValue(confname, name, value, sizeof(value)) == NULL) return 0;
	return atoi(value);
}

char* GetValue(const char* confname, const char* name, char* value, size_t len)
{
	assert(value!=NULL && len!=0);
	FILE* fn = fopen(confname, "r");
	if (fn == NULL) return NULL;

	assert(len < len+CONF_NAME_LEN);
	len += CONF_NAME_LEN;

	char* buffer = calloc(1,len);
	if (buffer == NULL){
		fclose(fn);
		return NULL;
	}

	value[0] = '\0';
	do {
		fgets(buffer, len, fn);

		char *left, *right;
		if (split_line(buffer, &left, &right, '=') == 0) {
			if (strcmp(left, name) == 0) {
				strncpy(value, right, len-CONF_NAME_LEN);
				value[len-CONF_NAME_LEN-1] = '\0';
				break;
			}
		}
	} while (!feof(fn));

	free(buffer);
	fclose(fn);

	return value[0]=='\0'? NULL:value;
}

int GetFileData(const char* pszFileName, char* pszFileData, int nMaxLen)
{
	assert(pszFileName!=NULL && pszFileData!=NULL);
	int nRead = 0, nReadTotal = 0;
	int nReadBufferLen = BUFFER_MAX_LEN;
	
	FILE *pFile = NULL;
	pFile = fopen(pszFileName, "r");
	if (pFile != NULL) {
		while (!feof(pFile)) {
			if (nReadTotal+BUFFER_MAX_LEN > nMaxLen)
				nReadBufferLen = nMaxLen - nReadTotal;
			
			nRead = fread(pszFileData+nReadTotal, sizeof(char), nReadBufferLen, pFile); 
			nReadTotal += nRead;

			if (nReadTotal == nMaxLen)
				break;
		}

		pszFileData[nReadTotal] = '\0';
		fclose(pFile);
	} else {
		LOGFATAL("'%s' dont exist.", pszFileName);
		ASSERT(0);
	}

	return nReadTotal;
}
