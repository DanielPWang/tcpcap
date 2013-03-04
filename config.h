#ifndef __CONFIG_H__
#define __CONFIG_H__

#define BUFFER_MAX_LEN 1024
/**
 * @brief get value of name from confname.
 * @note  
 */
char* GetValue(const char* confname, const char* name, char* value, size_t len);
int GetFileData(const char* pszFileName, char* pszFileData, int nMaxLen);

#endif

