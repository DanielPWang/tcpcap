#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>

#include <utils.h>
#include <fun_all.h>

struct _hosts_array_t {
	struct hosts_t *hosts;
	size_t count;
};

struct hosts_t *_exclude_hosts = NULL;
size_t _exclude_hosts_count = 0;

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

static int _comp_host(const void* l, const void* r)
{
	const struct hosts_t *lh = (const struct hosts_t *)l;
	const struct hosts_t *rh = (const struct hosts_t *)r;
	if (rh->ip.s_addr == INADDR_BROADCAST || lh->ip.s_addr == INADDR_BROADCAST) {
		if (rh->port == 0u || lh->port==0u) return 0;
		return rh->port - lh->port;
	}
	if (lh->ip.s_addr == rh->ip.s_addr) {
		if (rh->port == 0u || lh->port==0u) return 0;
		return lh->port - rh->port;
	}
	return lh->ip.s_addr - rh->ip.s_addr;
}
// int inHosts(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
void *inHosts(const void *hosts, const struct hosts_t *host)
{
	ASSERT(hosts != NULL);
	const struct _hosts_array_t* p = (const struct _hosts_array_t*)hosts;
	struct hosts_t *base = bsearch(host, p->hosts, p->count, sizeof(struct hosts_t), _comp_host);
	return base;
}

// Load rule from config.
void* LoadHost(char* hostsbuff)
{
	ASSERT(hostsbuff != NULL);
	// capture these hosts
	char *left, *right, *ipport;
	int n = 0, nDataLen = 0;

	struct _hosts_array_t * p = (struct _hosts_array_t*)calloc(sizeof(struct _hosts_array_t), 1);
	ASSERT(p!=NULL);
	p->count = count_char(hostsbuff, '\n') + 1;
	p->hosts = (struct hosts_t *)calloc(sizeof(struct hosts_t), p->count);

	for(left=hostsbuff; ;left=NULL) {
		ipport = strtok_r(left, "\n", &right);
		if (ipport==NULL) break;
		LOGINFO("monitor host %s", ipport);
		if (str_ipp(ipport, &(p->hosts[n]))) {
		   	++n; 
		}
	}

	qsort(p->hosts, p->count, sizeof(struct hosts_t), _comp_host);
	return p;
}
