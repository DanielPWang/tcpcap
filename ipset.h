#ifndef __IPSET_H__
#define __IPSET_H__

#include <stdint.h>

void ipset_load_from_file(const char* file);
/// if ip in ipset, return index. other -1;
int  ipset_has(uint32_t ip, uint16_t port);

#endif

