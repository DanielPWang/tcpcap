#ifndef __PROCESS_HTTP_H__
#define __PROCESS_HTTP_H__

#include "packet.h"

int process_http_start(pkt_queue_t* pkts);
void process_http_stop();

#endif

