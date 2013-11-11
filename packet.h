#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>

typedef struct _packet_t {
	struct timeval recv_time;
	uint32_t buffer_len;
	struct iphdr* ip;
	struct tcphdr* tcp;
	uint8_t *content;
	uint32_t content_len;
	uint8_t buffer[1];
}__attribute__ ((__packed__))  packet_t;

/// malloc(sizeof(packet_t) + len)
packet_t* packet_new(void* buffer, uint32_t len);
/// Only for ipv4 and tcp
bool packet_init(packet_t* phdr);
/// just free
void packet_destory(packet_t* packet);

void packet_list_init();
void packet_list_push(packet_t* p);
packet_t* packet_list_pop();
void packet_list_fini();

#endif
