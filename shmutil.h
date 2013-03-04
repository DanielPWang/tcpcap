#ifndef __SHM_UTIL_H__
#define __SHM_UTIL_H__

#include <sys/ipc.h>
#include <sys/shm.h>

/**
 * @ only first size is aviale. path must exist.
 * return 0 if sucess. other return -1.
 **/
void* InitSharemem(const char* path, size_t size);

/**
 * @ brief
 */
char* GetBuffer(void *shm, size_t size);

/**
 * @ brief
 */
const char* GetData();

/**
 * @brief
 */
void DestorySharemem(void *shm);

#endif

