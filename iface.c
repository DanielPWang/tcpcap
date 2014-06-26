#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "utils.h"
#include "define.h"
#include "config.h"

static int SockMonitor[MONITOR_COUNT] = {0};

static int _epollfd = 0;
static struct epoll_event _events[MONITOR_COUNT];
static int _active_sock = 0;
static pcap_t *pcap_live[MONITOR_COUNT] = {0};

extern int DEBUG;
extern char* PCAPFILE;
extern volatile int Living;

int open_monitor(const char* interface, const char* fliter)
{
	char* errbuff = (char*)malloc(PCAP_ERRBUF_SIZE);
	pcap_t *p = pcap_open_live(interface, 65535, 1, 0, errbuff);
	if (p == NULL) {
		LOGFATAL("Cannt open %s [%s]", interface, errbuff);
		abort();
	}
	struct bpf_program fp;
	int err = pcap_compile(p, &fp, fliter, 0, PCAP_NETMASK_UNKNOWN);
	if (err < 0 ) {
		LOGFATAL("pcap_compile error: %s", pcap_geterr(p));
		abort();
	}
	if (pcap_setfilter(p, &fp) < 0) {
		LOGFATAL("pcap_setfilter error: %s", pcap_geterr(p));
		abort();
	}
	pcap_freecode(&fp);

	free(errbuff);

	return pcap_get_selectable_fd(p);
}

static pcap_t *Offline = NULL;
int OpenPcapFile(const char* pcapfile, const char* filter)
{
	char* errbuff = (char*)malloc(PCAP_ERRBUF_SIZE);

	Offline = pcap_open_offline(pcapfile, errbuff);
	if (Offline == NULL) {
		LOGFATAL("open offline failure. %s", errbuff);
		printf("[FATAL] cannt open %s", PCAPFILE);
		abort();
	}
	struct bpf_program fp;
	int err = pcap_compile(Offline, &fp, filter, 0, PCAP_NETMASK_UNKNOWN);
	if (err < 0 ) {
		LOGFATAL("pcap_compile error: %s", pcap_geterr(Offline));
		abort();
	}
	if (pcap_setfilter(Offline, &fp) < 0) {
		LOGFATAL("pcap_setfilter error: %s", pcap_geterr(Offline));
		abort();
	}

	pcap_freecode(&fp);
	free(errbuff);
	return 1;
}

int OpenMonitorDevs()
{
	char* filter = (char*) malloc(4000);
	GetValue(CONFIG_PATH, "filter", filter, 4000);

	if ( DEBUG ) { return OpenPcapFile(PCAPFILE, filter); }

	char* value = (char*)calloc(1,1024);
	ASSERT(value!=NULL);
	if (GetValue(CONFIG_PATH, "monitor", value, 1024)==NULL || value[0]=='\0') {
		LOGFATAL("cannt get monitor from %s", CONFIG_PATH);
		abort();
	}
	ASSERT(_epollfd==0);
	ASSERT(_active_sock == 0);
	_epollfd = epoll_create(MONITOR_COUNT);
	ASSERT(_epollfd!=-1);
	struct epoll_event ev;

	char *left = value;
	char *right = NULL;

	for (; _active_sock<=MONITOR_COUNT ; left=NULL)
	{
		left = strtok_r(left, " ", &right);
		if (left == NULL) break;
		SockMonitor[_active_sock] = open_monitor(left, "");
		if (SockMonitor[_active_sock] > 0) {
			LOGINFO("open interface %s", left);
			ev.events = EPOLLIN;
			ev.data.fd = SockMonitor[_active_sock];
			if (epoll_ctl(_epollfd, EPOLL_CTL_ADD, SockMonitor[_active_sock], &ev)==-1) {
				perror("[ERROR] ");
			}
			++_active_sock;
		} else {
			LOGINFO("cannt open interface %s", left);
		}
	}
	free(value);
	free(filter);
	return _active_sock;
}

int GetPacket_Debug(char* buffer, size_t size)
{
	static uint64_t total_count = 0u;
	sleep(0);
	struct pcap_pkthdr *h;
	const u_char* data;
	int err = pcap_next_ex(Offline, &h, &data);
	if (err == -2) {
		LOGINFO0("will exit from debuging...");
		printf("will exit from debuging. %ull\n", total_count);
		Living = 0;
		return 0;
	}
	++total_count;
	if (h->caplen != h->len) {
		LOGFATAL("pcap_next: buffer not longer. caplen=%u len=%u", h->caplen, h->len);
		abort();
	}
	if (h->len > size) {
		LOGFATAL0("expect more buffer.");
		abort();
	}
	memcpy(buffer, data, h->len);
	return h->len;
}

int CapturePacket(char* buffer, size_t size)
{
	if (DEBUG) return GetPacket_Debug(buffer, size);

	assert(_epollfd > 0);
	assert(_active_sock > 0);

	int nfds = epoll_wait(_epollfd, _events, _active_sock, -1);
	if (nfds < 1 ) return 0;	// test exit.

	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);

	int nRecv = recvfrom(_events[0].data.fd, buffer, size, 0, (struct sockaddr*)&sa, &salen);
	if (nRecv == -1) { return 0; }

	return nRecv;
}

void CloseOpenMonitorDevs()
{
	for (; _active_sock>0; --_active_sock) {
		if (epoll_ctl(_epollfd, EPOLL_CTL_DEL, SockMonitor[_active_sock-1], NULL) == -1) {
			perror("[ERROR] ");
		}
	}
	close(_epollfd);
	_epollfd = 0;
}

