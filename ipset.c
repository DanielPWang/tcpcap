#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <glib-2.0/glib.h>

typedef struct {
	uint32_t ip;
	uint16_t port;
	uint16_t res0;
} ip_port_t;

GHashTable *ipp_set = NULL;

guint ip_port_hash(gconstpointer v)
{
	ip_port_t *p = (ip_port_t*)v;
	return p->ip;
}
guint ip_port_search(gconstpointer a, gconstpointer b)
{
	const ip_port_t *lip = (const ip_port_t*)a;
	const ip_port_t *rip = (const ip_port_t*)b;
	if (lip->ip==INADDR_BROADCAST || rip->ip==INADDR_BROADCAST) {
		// NOTHING
	} else if (lip->ip != rip->ip) {
		return (int)(lip->ip - rip->ip);
	}
	if (lip->port & rip->port == 0U) {
		return 0
	}
	return (guint)(lip->port - rip->port);
}

void ipset_load_from_file(const char* file)
{
	if (ipp_set == NULL) {
		ipp_set = g_hash_table_new(ip_port_hash, ip_port_search);
	}

	FILE* pf = fopen(file, "r");
	if (pf == NULL) {
		LOG_ERROR("'%s' doesnt exist.\n", file);
		return ;
	}
	char* line = (char*) malloc(128);
	ip_port_t host;
	while (line=fgets(line, 128, pf)) {
		if (line[0] == '\0') break;

		if (str_ipp(line, &host) > 0) {
			g_hash_table_add() // TODO
		}
	}
	free(line);
	fclose(pf);
	// sort 
	qsort(ip_port_set, ip_port_size, sizeof(ip_port_t), ip_port_compar);
}

int  ipset_has(uint32_t ip, uint16_t port)
{
	ip_port_t host = { ip, port, 0 };
	void *p = bsearch(&host, ip_port_set, ip_port_size, sizeof(ip_port_t),
			ip_port_search_compare);
	return p;
}

int str_ipp(const char* ipport, ip_port_t* hosts)
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
        hosts->ip = INADDR_BROADCAST;
    } else {
        nRet = inet_aton(tmp, (struct in_addr*)&hosts->ip);
    }

    free(tmp);

    if (nRet==0) memset(hosts, 0, sizeof(*hosts));
    return nRet;
}

int ip_port_compar(const void* l, const void* r)
{
	const ip_port_t *lip = (const ip_port_t*)l;
	const ip_port_t *rip = (const ip_port_t*)r;
	if (lip->ip != rip->ip) {
		return (int)(lip->ip - rip->ip);
	}
	return (int)(lip->port - rip->port);
}

