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

struct line_t {
	const char* content;
	int len;
};

// it should be http_session
struct http_session
{
	struct hosts_t client;		// assume
	struct hosts_t server;
	uint32_t index;
	uint32_t flag;		// HTTP_SESSION_???
	uint32_t seq;		// client
	uint32_t ack;		// client
	uint32_t transfer_flag;
	uint32_t content_encoding;	   // 1:gzip; 0:no encoding
	uint32_t content_type;			   // 0:no match; 1:html; 2:file
	uint32_t contentlen;	// len of last packet
	uint32_t http_content_length;
	struct timeval create;	// first
	struct timeval update;	// the lasttime update. TODO: time_t
	struct line_t query_url;
	struct line_t http;
	char* response_head;
	uint32_t response_head_len;	
	void *data;
	void *lastdata;
	uint32_t packet_num;	// count of packets [data]

	struct http_session *prev;
	struct http_session *next;
};

struct http_sessions_t{
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
#define FLOW_SET(tcphead, x) (tcphead->check = (x))
#define FLOW_GET(tcphead) (tcphead->check)
#define FRAME_NUM_SET(packet) (*(uint32_t*)packet = ++packet_num)
#define FRAME_NUM_GET(packet) (*(uint32_t*)packet)

#endif

