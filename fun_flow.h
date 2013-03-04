#ifndef __FUN_FLOW_H__
#define __FUN_FLOW_H__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fun_all.h>

#define MAX_PORT_COUNT  7

enum FLOW_SESSION_STATUS 
{ 
	FLOW_SESSION_IDL = 0, 
	FLOW_SESSION_COLLECTING,
	FLOW_SESSION_FINISH
};

struct s_add_server_flow_req
{
	u_long server_ip;
	u_short port[MAX_PORT_COUNT];
	int time_long;
}__attribute__((packed));

struct s_server_flow
{
	u_long server_ip;
	int64_t total_flow;
	int64_t flow_rate;
	u_short port[MAX_PORT_COUNT];
	int64_t flow[MAX_PORT_COUNT];
	int64_t start_time;
	int64_t cur_time;
	int time_long;
	char status;
}__attribute__((packed));

struct s_client_flow
{
	u_long client_ip;
	int64_t total_flow;
	int64_t flow[MAX_PORT_COUNT];
}__attribute__((packed));

struct s_flow_pack
{
	u_long server_ip;
	u_long client_ip;
	int protocol;
	u_short port;
	int pack_len;
};

struct s_flow_session
{
	int work_status;
	time_t last_time;
	int64_t last_total_flow;
	struct s_server_flow server_flow;
	struct s_client_flow *p_client_flow;
};

int FlowInit();
int FilterPacketForFlow(const char* buffer, const struct iphdr* iphead);
int AddServer(const char* server_buffer);
int StopServerFlow(const char* server_buffer);
int GetServerCount();
int GetFlowData(int nIndex, time_t tmNow, char **data);

#endif
