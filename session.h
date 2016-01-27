#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdint.h>

#include "packet.h"

typedef enum {NEW, WAITING, FINISH, TIMEOUT} SESSION_STATUS;

typedef struct {
	uint32_t client;
	uint16_t client_port;
	uint32_t server;
	uint16_t server_port;
	uint32_t content_len;
	uint32_t status;
	struct timeval modify_time;
	packet_head_t *head;
	packet_head_t *tail;
	packet_head_t *c2s_list;
	packet_head_t *s2c_list;
} tcp_session_t;

void* hash
#endif
