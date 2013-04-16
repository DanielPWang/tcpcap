#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>
#include <iface.h>
#include <utils.h>
#include <define.h>
#include <fun_all.h>
#include <fun_flow.h>

static int g_nDropCountForPacketFull = 0;

static struct queue_t *_packets = NULL;
static struct s_flow_session* _flow_session = NULL;
extern volatile int Living;
pthread_mutex_t _flow_data_lock = PTHREAD_MUTEX_INITIALIZER;

static int PushFlowPack(const struct iphdr* iphead, unsigned long server_ip, unsigned long client_ip);
static struct s_flow_session* CleanFlowSession(int nIndex);
static void *Flow_Thread(void* param);
static int CompFlowSize(const void *p1, const void *p2);

struct s_flow_session* CleanFlowSession(int nIndex)
{
	struct s_flow_session* pSession = &_flow_session[nIndex];
	if (pSession->work_status != FLOW_SESSION_IDL) 
	{
		memset(&pSession->server_flow, 0, sizeof(struct s_server_flow));
		if (NULL == pSession->p_client_flow)
		{
			free(pSession->p_client_flow);
			pSession->p_client_flow = NULL;
		}
		pSession->work_status = FLOW_SESSION_IDL;
		pSession->last_time = 0;
		pSession->last_total_flow = 0;
	}

	return pSession;
}

int FlowInit()
{
	ASSERT(_packets == NULL);
	ASSERT(_flow_session == NULL);

	_packets = init_queue(MAX_FLOW_PACKETS);
	ASSERT(_packets != NULL);
	
	_flow_session = calloc(sizeof(struct s_flow_session), MAX_FLOW_SESSIONS);
	ASSERT(_flow_session != NULL);

	memset(_flow_session, 0, sizeof(struct s_flow_session)*MAX_FLOW_SESSIONS);
		
	pthread_t pthreadid;
	int err = pthread_create(&pthreadid, NULL, &Flow_Thread, (void*)&Living);
	ASSERT(err==0);
	
	return (_packets == NULL) ? -1 : 0;
}

int PushFlowPack(const struct iphdr* iphead, unsigned long server_ip, unsigned long client_ip)
{	
	struct s_flow_pack *pFlowPack = calloc(sizeof(struct s_flow_pack), 1);
	ASSERT(pFlowPack != NULL);
	
	pFlowPack->protocol = iphead->protocol;
	pFlowPack->server_ip = server_ip;
	pFlowPack->client_ip = client_ip;
	pFlowPack->pack_len = ntohs(iphead->tot_len);

	int bIsSourcePort = (iphead->saddr == server_ip) ? 1 : 0;
	if (IPPROTO_TCP == iphead->protocol)
	{
		struct tcphdr *tcphead = TCPHDR(iphead);
		pFlowPack->port = bIsSourcePort ? ntohs(tcphead->source) : ntohs(tcphead->dest);
	}
	else if (IPPROTO_UDP == iphead->protocol)
	{
		struct udphdr *udphead = UDPHDR(iphead);
		pFlowPack->port = bIsSourcePort ? ntohs(udphead->source) : ntohs(udphead->dest);
	}
		
	int nErr = push_queue(_packets, (const void*)pFlowPack);
	if (nErr < 0) 
	{
		free(pFlowPack);
		pFlowPack = NULL;
		LOGWARN("Flow_queue is full. drop the packets, drop count = %d", ++g_nDropCountForPacketFull);
	}
	
	return nErr;
}

int FilterPacketForFlow(const struct iphdr* iphead)
{
	int nRs = -1;
	for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
	{
		struct s_flow_session *pFSession = &_flow_session[i];
		if (pFSession->work_status != FLOW_SESSION_COLLECTING)
			continue;
		
		if (iphead->saddr == pFSession->server_flow.server_ip)
			nRs = PushFlowPack(iphead, iphead->saddr, iphead->daddr);
		else if (iphead->daddr == pFSession->server_flow.server_ip)
			nRs = PushFlowPack(iphead, iphead->daddr, iphead->saddr);
	}

	return nRs;
}

int AddServer(const char* server_buffer)
{
	ASSERT(server_buffer != NULL);

	int nRs = -1;
	int nSuccessCount = 0;
	int nServerCount = ntohl(*(int*)server_buffer);
	// add server data format: count of server + array of server flow request
	struct s_add_server_flow_req *pReq = (struct s_add_server_flow_req*)(server_buffer+sizeof(int));
	for (int n = 0; n < nServerCount; n++)
	{
		nRs = -1;
		for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
		{
			struct s_flow_session *pFSession = &_flow_session[i];
			if (pFSession->work_status != FLOW_SESSION_IDL)
				continue;

			pFSession->server_flow.server_ip = ntohl(pReq[n].server_ip);
			for (int j = 0; j < MAX_PORT_COUNT; j++)
			{
				if (pReq[n].port[j] > 0)
					pFSession->server_flow.port[j] = ntohs(pReq[n].port[j]);
			}
			pFSession->server_flow.time_long = ntohl(pReq[n].time_long)*60;
			pFSession->p_client_flow = (struct s_client_flow *)calloc(sizeof(struct s_client_flow), MAX_FLOW_COLLECT_CLIENT);
			ASSERT(pFSession->p_client_flow != NULL);

			struct in_addr sip; 
			sip.s_addr = ntohl(pReq[n].server_ip);
			char szSip[16] = {0};
			LOGINFO("Add flow serve. server_ip = %s, time_long = %d s", strcpy(szSip, inet_ntoa(sip)), pFSession->server_flow.time_long);
			
			memset(pFSession->p_client_flow, 0, sizeof(struct s_client_flow)*MAX_FLOW_COLLECT_CLIENT);
			pFSession->server_flow.start_time = time(NULL);
			pFSession->work_status = FLOW_SESSION_COLLECTING;
			pFSession->last_time = time(NULL);
			nRs = i;
			break;
		}

		if (nRs != -1)
		{
			nSuccessCount++;
		}
		else
		{
			struct in_addr sip; 
			sip.s_addr = ntohl(pReq->server_ip);
			char szSip[16] = {0};
			LOGWARN("_flow_session is full. Drop current server flow request. server_ip = %s", strcpy(szSip, inet_ntoa(sip)));
		}
	}
	
	return nSuccessCount;
}

int StopServerFlow(const char* server_buffer)
{
	ASSERT(server_buffer != NULL);

	int nRs = -1;
	int nSuccessCount = 0;
	int nServerCount = ntohl(*(int*)server_buffer);
	u_long *pServer_ip = (u_long *)(server_buffer + sizeof(int));
	for (int n = 0; n < nServerCount; n++)
	{
		nRs = -1;
		for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
		{
			struct s_flow_session *pFSession = &_flow_session[i];
			if (pFSession->work_status != FLOW_SESSION_COLLECTING)
				continue;

			if (ntohl(pServer_ip[n]) == pFSession->server_flow.server_ip)
			{
				struct in_addr sip; 
				sip.s_addr = ntohl(pServer_ip[n]);
				char szSip[16] = {0};
				LOGDEBUG("Stop flow serve. server_ip = %s", strcpy(szSip, inet_ntoa(sip)));
			
				pFSession->work_status = FLOW_SESSION_FINISH;
				nRs = i;
				break;
			}
		}

		if (nRs != -1)
		{
			nSuccessCount++;
		}
		else
		{
			struct in_addr sip; 
			sip.s_addr = ntohl(pServer_ip[n]);
			char szSip[16] = {0};
			LOGWARN("Can not find stop server ip. Drop current stop server flow request. server_ip = %s", strcpy(szSip, inet_ntoa(sip)));
		}
	}
	
	return nSuccessCount;
}

int GetServerCount()
{
	int nCount = 0;
	for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
	{
		struct s_flow_session *pFSession = &_flow_session[i];
		if (pFSession->work_status != FLOW_SESSION_IDL)
			nCount++;
	}

	return nCount;
}

int CompFlowSize(const void *p1, const void *p2)
{
	struct s_client_flow* pClient1 = (struct s_client_flow*)p1;
	struct s_client_flow* pClient2 = (struct s_client_flow*)p2;

	if (pClient2->total_flow > pClient1->total_flow)
		return 1;
	else if (pClient2->total_flow < pClient1->total_flow)
		return -1;

	return 0;		
}

int GetFlowData(int nIndex, time_t tmNow, char **data)
{
	ASSERT(nIndex >= 0 && nIndex < MAX_FLOW_SESSIONS);
	int nClientCount = 0;

	struct s_flow_session *pFSession = &_flow_session[nIndex];
	if (FLOW_SESSION_IDL == pFSession->work_status)
		return 0;

	pthread_mutex_lock(&_flow_data_lock);
	struct s_client_flow *pClientFlow = pFSession->p_client_flow;
	for (int i = 0; i < MAX_FLOW_COLLECT_CLIENT; i++)
	{
		if (pClientFlow[i].client_ip > 0)
			nClientCount++;
		else
			break;
	}

	int nSendCount = (nClientCount > MAX_FLOW_RESPONSE_CLIENT) ? MAX_FLOW_RESPONSE_CLIENT : nClientCount;
	// Send data format: serverflow+count of client+data array of client flow
	int nDataSize = sizeof(struct s_server_flow) + sizeof(int) + sizeof(struct s_client_flow)*nSendCount;
	char *pFlowData = (char*)calloc(1, nDataSize);
	if (NULL == pFlowData) 
	{
		LOGERROR0("Malloc flow data memory failed.");
		*data = NULL;
		pthread_mutex_unlock(&_flow_data_lock);
		return 0;
	}

	qsort(pClientFlow, nClientCount, sizeof(struct s_client_flow), CompFlowSize);

	*data = pFlowData;
	memcpy(pFlowData, &pFSession->server_flow, sizeof(struct s_server_flow));
	struct s_server_flow *pServerFlow = (struct s_server_flow*)pFlowData;
	int nServerIp = pServerFlow->server_ip;
	char curStatus = (char)pFSession->work_status;
	int64_t nTotalFlow = pServerFlow->total_flow;
	int64_t nFlowRate = (nTotalFlow-pFSession->last_total_flow) / (tmNow-pFSession->last_time);
	
	pServerFlow->server_ip = htonl(pServerFlow->server_ip);
	pServerFlow->total_flow = htonll(nTotalFlow);
	pServerFlow->flow_rate = htonll(nFlowRate);
	pServerFlow->cur_time = htonll(tmNow);
	pServerFlow->status = curStatus;

	int nPortCount = 0;
	for (int i = 0; i < MAX_PORT_COUNT; i++)
	{
		if (pServerFlow->port[i] > 0)
		{
			pServerFlow->port[i] = htons(pServerFlow->port[i]);
			pServerFlow->flow[i] = htonll(pServerFlow->flow[i]);
			nPortCount++;
		}
		else
			break;
	}
	pFlowData += sizeof(struct s_server_flow);
	*(int*)pFlowData = htonl(nSendCount);
	pFlowData += sizeof(int);
	if (nSendCount > 0)
	{
		memcpy(pFlowData, pClientFlow, sizeof(struct s_client_flow)*nSendCount);
		pClientFlow = (struct s_client_flow*)pFlowData;
		for (int i = 0; i < nSendCount; i++)
		{
			if (pClientFlow[i].client_ip > 0)
			{
				pClientFlow[i].client_ip = htonl(pClientFlow[i].client_ip);
				pClientFlow[i].total_flow = htonll(pClientFlow[i].total_flow);
				for (int j = 0; j < nPortCount; j++)
				{
					pClientFlow[i].flow[j] = htonll(pClientFlow[i].flow[j]);
				}
			}
			else
				break;
		}
	}

	pFSession->last_total_flow = nTotalFlow;
	pFSession->last_time = time(NULL);
		
	if (FLOW_SESSION_FINISH == curStatus)
	{
		CleanFlowSession(nIndex);
	}

	pthread_mutex_unlock(&_flow_data_lock);

	struct in_addr sip; 
	sip.s_addr = nServerIp;
	char szSip[16] = {0};

	struct tm t;
	char timebuf[30] = {0};
	strftime(timebuf, sizeof(timebuf), "%F %T", localtime_r(&tmNow, &t));
		
	LOGINFO("Get flow data completed. Session index = %d, server_ip = %s, cur_time = %s, total_flow = %lld, flow_rate = %lld, status = %d", nIndex, strcpy(szSip, inet_ntoa(sip)), timebuf, nTotalFlow, nFlowRate, curStatus);
			
	return nDataSize;
}

void *Flow_Thread(void* param)
{
	volatile int *active = (int*)param;
	while (*active)
	{
		struct s_flow_session *pFSession = NULL;
		for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
		{
			pFSession = &_flow_session[i];
			struct s_server_flow* pServerFlow = &pFSession->server_flow;
			if (FLOW_SESSION_COLLECTING == pFSession->work_status)
			{
				if (time(NULL) >= pServerFlow->start_time + pServerFlow->time_long)
				{
					pFSession->work_status = FLOW_SESSION_FINISH;
				}
			}
		}
		
		struct s_flow_pack* pPacket = pop_queue(_packets);
		if (NULL == pPacket) 
		{
			sleep(0);
			continue;
		}

		for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
		{
			pFSession = &_flow_session[i];
			if (FLOW_SESSION_COLLECTING == pFSession->work_status)
			{
				if (pFSession->server_flow.server_ip == pPacket->server_ip)
					break;
				else
					pFSession = NULL;
					
			}
			else
			{
				pFSession = NULL;
			}
		}

		if (NULL == pFSession)
		{
			free(pPacket);
			pPacket = NULL;
			continue;
		}

		pthread_mutex_lock(&_flow_data_lock);
		
		int nPortIndex = -1;
		struct s_server_flow* pServerFlow = &pFSession->server_flow;
		pServerFlow->total_flow += pPacket->pack_len;
		for (int i = 0; i < MAX_PORT_COUNT; i++)
		{
			if ((pServerFlow->port[i] > 0) && (pServerFlow->port[i] == pPacket->port))
			{
				pServerFlow->flow[i] += pPacket->pack_len;
				nPortIndex = i;
				break;
			}
		}

		struct s_client_flow *pClientFlow = pFSession->p_client_flow;
		for (int i = 0; i < MAX_FLOW_COLLECT_CLIENT; i++)
		{
			if (pClientFlow[i].client_ip > 0)
			{
				if (pClientFlow[i].client_ip == pPacket->client_ip)
				{
					pClientFlow[i].total_flow += pPacket->pack_len;
					if (nPortIndex != -1)
						pClientFlow[i].flow[nPortIndex] += pPacket->pack_len;

					break;
				}
			}
			else		
			{
				pClientFlow[i].client_ip = pPacket->client_ip;
				pClientFlow[i].total_flow = pPacket->pack_len;
				if (nPortIndex != -1)
					pClientFlow[i].flow[nPortIndex] = pPacket->pack_len;

				break;
			}
		}

		free(pPacket);
		pPacket = NULL;
		
		pthread_mutex_unlock(&_flow_data_lock);
	}
	
	return NULL;
}

