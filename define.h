#ifndef __DEFINE_H__
#define __DEFINE_H__

#define VER_MAJOR 1
#define VER_MINOR 0
#define VER_PATCH 8

#define MONITOR_COUNT 5

// configure
#define CONFIG_PATH_FILE "./config/agent.conf"
#define HTTP_HOST_PATH_FILE "./config/http_host_ip.lst"
#define EXCLUDE_HOST_PATH_FILE "./config/exclude_host_ip.lst"
#define VALUE_LENGTH_MAX  (1024*60)

#define HTTP_PROCESS_THREADS 1
extern const char* CONFIG_PATH;
extern int DEBUG;

// capture
#define RECV_BUFFER_LEN   2400 // 8192

#define MAX_BLOCK_ITEM 500
// HTTP
#define MAX_HTTP_SESSIONS 6000
#define MAX_HTTP_PACKETS  20000
#define HTTP_TIMEOUT      15	// s

#define MAX_LATER_PACKETS 40

// Flow
#define MAX_FLOW_SESSIONS 5
#define MAX_FLOW_PACKETS  5000
#define MAX_FLOW_COLLECT_CLIENT   1000
#define MAX_FLOW_RESPONSE_CLIENT  500
#define FLOW_SEND_INTERVAL_TIME   60

// server
#define SERVER_PORT 2012

// share memory
#define SHMKEY 0x889900

#endif

