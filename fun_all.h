#ifndef __FUN_ALL_H__
#define __FUN_ALL_H__

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>

enum FLOWDIR {
	NONE,
	C2S,
	S2C
};
struct hosts_t
{
	struct in_addr ip;
	in_port_t port;
};

// it should be http_session
struct http_session
{
	uint32_t index;	// noused
	struct hosts_t client;		// assume
	struct hosts_t server;
	uint32_t flag;		// HTTP_SESSION_???
	uint32_t seq;		// client
	uint32_t ack;		// client
	uint32_t query_image;
	uint32_t content_type;			   // 0:no match; 1:html; 2:file
	struct timeval create;	// first
	struct timeval update;	// the lasttime update. TODO: time_t
	char* query;
	char* http;
	void *data;		// list
	void *lastdata;
	uint32_t packet_num;	// count of packets [data]

	// be used by sm_xxxxxx
	struct http_session *prev;
	struct http_session *next;
	// be used by HttpSession
	struct http_session *_work_next;
};

struct http_sessions_group{
	struct http_session* head;
	pthread_mutex_t lock;
	uint32_t	used;
};
/** @brief tans "10.10.100.10:9900" to host_t 
 *	returns nonzero if the address is valid
 **/
int str_ipp(const char* ipport, struct hosts_t* hosts);
void *inHosts(const void *hosts, const struct hosts_t *host);
void* LoadHost(char* hostsbuff);

#define IPHDR(packet) (struct iphdr*)((void*)(packet) + ((((struct ether_header*)(packet))->ether_type == htons(ETHERTYPE_IP)) ? ETHER_HDR_LEN : (ETHER_HDR_LEN+4)))
#define TCPHDR(ippacket) (struct tcphdr*)((void*)(ippacket) + ((struct iphdr*)(ippacket))->ihl*4)
#define UDPHDR(ippacket) (struct udphdr*)((void*)(ippacket) + ((struct iphdr*)(ippacket))->ihl*4)
#define FLOW_SET(tcphead, x) ((tcphead)->check = (x))
#define FLOW_GET(tcphead) ((tcphead)->check)
#define CONTENT_GET(tcphead) ((void*)tcphead + tcphead->doff*4)
#define CONTENT_LEN_GET(tcphead) ((tcphead)->window)
#define CONTENT_LEN_SET(tcphead, x) do { (tcphead)->window = x; } while(0)
// only for debug
#define FRAME_NUM_SET(packet) (((struct timeval*)(packet))->tv_sec = ++packet_num)
#define FRAME_NUM_GET(packet) (*(uint32_t*)(packet))

#endif

