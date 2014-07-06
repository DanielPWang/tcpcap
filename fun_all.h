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
} __attribute__((packed));

struct line_t {
	const char* content;
	int len;
};

// it should be http_session
struct http_session
{
	struct hosts_t client;		// assume
	struct hosts_t server;
	uint32_t flag;		// ACK,SYN,FIN,RST,IDL,S1,S2,S3
	uint32_t seq;		// client
	uint32_t ack;		// client
	uint32_t transfer_flag;
	uint32_t response_head_recv_flag;  // 1:recv ok; 0:default
	uint32_t content_encoding_gzip;	   // 1:gzip; 0:no encoding
	uint32_t content_type;			   // 0:no match; 1:html; 2:file
	uint32_t finish_type;
	uint32_t force_restore_flag;
	uint32_t contentlen;
	uint32_t http_content_length;
	uint32_t res2;
	uint32_t res_true_len;
	uint32_t later_pack_size;
	uint32_t index;
	uint32_t cur_content_len;
	uint32_t part_content_len;
	struct timeval create;	// first
	struct timeval update;		// the lasttime update. TODO: time_t
	struct line_t query_url;
	struct line_t http;
	void *data;
	void *lastdata;
	void *pack_later;
	void *last_pack_later;
	char *request_head;
	char *response_head;
	//char *cur_content;
	//char *part_content;
	uint32_t request_head_len;
	uint32_t request_head_len_valid_flag;
	uint32_t response_head_len;
	uint32_t response_head_gen_time;

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
#define FLOW_SET(packet, x) (*(char*)(((void*)packet)+sizeof(struct timeval)) = (x))
#define FLOW_GET(packet) (*(char*)(((void*)packet)+sizeof(struct timeval)))

#endif

