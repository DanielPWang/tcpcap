#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

#include <utils.h>
#include <fun_all.h>

int str_ipp(const char* ipport, struct hosts_t* hosts)
{
	assert(ipport != NULL);
	char* tmp = strdup(ipport);
	ASSERT(tmp != NULL);
	char* pos = strchr(tmp, ':');

	if (pos) {
		*pos++ = '\0';
		hosts->port = htons(atoi(pos));
	} else {
		hosts->port = htons(0);
	}

	int nRet = 1;
	if (tmp[0] == '*') {
		hosts->ip.s_addr = INADDR_BROADCAST;
	} else {
		nRet = inet_aton(tmp, &hosts->ip);	
	}
	
	free(tmp);

	if (nRet==0) memset(hosts, 0, sizeof(*hosts));
	return nRet;
}

