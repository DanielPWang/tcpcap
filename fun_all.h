#ifndef __FUN_ALL_H__
#define __FUN_ALL_H__

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>

enum FLOWDIR {
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
struct tcp_session
{
	struct hosts_t client;		// assume
	struct hosts_t server;
	unsigned flag;		// ACK,SYN,FIN,RST,IDL,S1,S2,S3
	unsigned seq;		// client
	unsigned ack;		// client
	unsigned transfer_flag;
	unsigned response_head_recv_flag;  // 1:recv ok; 0:default
	unsigned content_encoding_gzip;	   // 1:gzip; 0:no encoding
	unsigned content_type;			   // 0:no match; 1:html; 2:file
	unsigned finish_type;
	unsigned force_restore_flag;
	unsigned res0;
	unsigned res1;
	unsigned res2;
	unsigned res_true_len;
	unsigned later_pack_size;
	unsigned index;
	unsigned request_head_len;
	unsigned request_head_len_valid_flag;
	unsigned response_head_len;
	unsigned response_head_gen_time;
	unsigned cur_content_len;
	unsigned part_content_len;
	struct timeval create;	// first
	struct timeval update;		// the lasttime update. TODO: time_t
	struct line_t query_url;
	struct line_t response_http;
	struct line_t response_content_type;
	struct line_t response_content_length;
	struct line_t response_trans_encoding;
	void *data;
	void *lastdata;
	void *pack_later;
	void *last_pack_later;
	char *request_head;
	char *response_head;
	char *cur_content;
	char *part_content;
	struct tcp_session *prev;
	struct tcp_session *next;
};

struct http_sessions_t{
	struct tcp_session* head;
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

