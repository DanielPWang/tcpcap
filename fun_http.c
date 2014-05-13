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
#include <zlib.h>
#include <iface.h>
#include <utils.h>
#include <define.h>
#include <fun_all.h>
#include <fun_http.h>
#include <block.h>

static volatile int _runing = 1;
static pthread_t _http_thread[MAX_SESSION_THREAD_COUNT];
static int _thread_param[MAX_SESSION_THREAD_COUNT] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

uint32_t g_nThreadCount = 1;
struct hosts_t *_monitor_hosts = NULL;
size_t _monitor_hosts_count = 0;
struct hosts_t **_monitor_hosts_array = NULL;
uint32_t g_nMonitorHostsPieceCount = 0;

struct hosts_t *_exclude_hosts = NULL;
size_t _exclude_hosts_count = 0;

pthread_mutex_t _host_ip_lock[MONITOR_COUNT] = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};
pthread_mutex_t _ile_session_count_lock[MAX_SESSION_THREAD_COUNT] = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};
pthread_mutex_t _session_proc_lock[MAX_SESSION_THREAD_COUNT] = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER};

static struct queue_t **_packets_array = NULL;

static int g_nCountWholeContentFull[MAX_SESSION_THREAD_COUNT] = {0};
static int g_nDropCountForPacketFull[MAX_SESSION_THREAD_COUNT] = {0};
static int g_nDropCountForSessionFull[MAX_SESSION_THREAD_COUNT] = {0};
static int g_nDropCountForImage = 0;
static int g_nTimeOutCount = 0;
static int g_nReusedCount = 0;
static int g_nLaterPackIsMaxCount = 0;
static int g_nContentErrorCount = 0;
static int g_nContentUnknownCount = 0;
static int g_nHttpNullCount = 0;
static int g_nDatalenErrorCount = 0;
static int g_nHttpcodeErrorCount = 0;
static int g_nChunked = 0;
static int g_nNone = 0;
static int g_nHtmlEnd = 0;
static uint64_t g_nHttpLen = 0;
static uint64_t g_nPushedPackCount[MAX_SESSION_THREAD_COUNT] = {0};
static uint64_t g_nSessionCostTime[MAX_SESSION_THREAD_COUNT] = {0};
uint64_t g_nSkippedPackCount = 0;

static int g_nSessionCount[MAX_SESSION_THREAD_COUNT] = {0};
static int g_nMaxUsedPackSize[MAX_SESSION_THREAD_COUNT] = {0};
static int g_nMaxUsedSessionSize[MAX_SESSION_THREAD_COUNT] = {0};
static int g_bIsCapRes = 0;
static int g_bIsSendTimeoutData = 0;
static int g_bIsSendChannelReusedData = 0;
static int g_bIsSendDisorderRebuildFailedData = 0;
static int g_bIsSendUnknownData = 0;

static int g_bIsLogResData = 0;
static int g_bIsLogTimeoutData = 0;
static int g_bIsLogChannelReusedData = 0;
static int g_bIsLogDisorderRebuildFailedData = 0;
static int g_bIsLogUnknownData = 0;

static int g_nGzipCount = 0;
static int g_nUnGzipFailCount = 0;

extern uint64_t g_nCapCount[MONITOR_COUNT];
extern uint64_t g_nCapSize[MONITOR_COUNT];
extern uint64_t g_nValidCapCount[MONITOR_COUNT];
extern uint64_t g_nValidCapSize[MONITOR_COUNT];
extern uint32_t g_nCapFisrtTime;
extern uint32_t g_nCapLastTime;
extern uint64_t g_nGetDataCostTime;
extern uint64_t g_nSendDataCostTime;
extern uint64_t g_nCacheDataCostTime;
extern int g_nSendDataCount;
extern int g_nMaxCacheCount;
extern InterfaceFdDef g_arrayActiveFd[MONITOR_COUNT];
extern int _active_sock;

static int g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
static int g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
static int g_nHttpTimeout = HTTP_TIMEOUT;
static char g_szSpecialClientIp[101] = {0};

static int g_nSendErrStateDataFlag = 1;

static struct tcp_session **_http_session_array = NULL;	// a session = query + reponse
static int *_idl_session_count = NULL;			// all idl session count
static struct queue_t *_whole_content = NULL;		// http_session.flag = HTTP_SESSION_FINISH

extern volatile int g_nFlagGetData;
extern volatile int g_nFlagSendData;

extern int _block_func_on;

// IDL -> REQUESTING -> REQUEST -> REPONSEING -> REPONSE -> FINISH
//           |------------|------------|------------------> TIMEOUT
static const unsigned _http_image = 0x50545448;
static const unsigned _get_image = 0x20544547;
static const unsigned _post_image = 0x54534F50;

void ShowOpLogInfo(int bIsPrintScreen)
{
	static uint64_t nPreCapSize = 0;
	static uint64_t nPreValidCapSize = 0;
	static uint32_t nPreCapTime = 0;
	static uint64_t nPreIfCapSize[MONITOR_COUNT] = {0};
	static uint64_t nPreIfValidCapSize[MONITOR_COUNT] = {0};
	uint64_t nIntervalCapSize = 0;
	uint64_t nValidIntervalCapSize = 0;
	uint32_t nIntervalCostTime = 0;

	uint64_t nCapCount = 0;
	uint64_t nCapSize = 0;
	uint64_t nValidCapCount = 0;
	uint64_t nValidCapSize = 0;
	
	for (int i = 0; i < _active_sock; i++)
	{
		nCapCount += g_nCapCount[i];
		nCapSize += g_nCapSize[i];
		nValidCapCount += g_nValidCapCount[i];
		nValidCapSize += g_nValidCapSize[i];
	}
	
	if (0 == nPreCapTime)
	{
		nIntervalCostTime = g_nCapLastTime - g_nCapFisrtTime;
		nIntervalCapSize = nCapSize;
		nValidIntervalCapSize = nValidCapSize;
		nPreCapTime = g_nCapLastTime;
		nPreCapSize = nCapSize;
		nPreValidCapSize = nValidCapSize;
	}
	else
	{
		nIntervalCapSize = nCapSize - nPreCapSize;
		nValidIntervalCapSize = nValidCapSize - nPreValidCapSize;
		nIntervalCostTime = g_nCapLastTime - nPreCapTime;
		nPreCapSize = nCapSize;
		nPreValidCapSize = nValidCapSize;
		nPreCapTime  = g_nCapLastTime;
	}

	//uint64_t nFlow = 0;
	//uint64_t nValidFlow = 0;
	double dFlow = 0;
	double dValidFlow = 0;
	if (nIntervalCostTime != 0)
	{
		dFlow = nIntervalCapSize / (uint64_t)nIntervalCostTime;
		dFlow = (dFlow*8) / (1024*1024);
		dValidFlow = nValidIntervalCapSize / (uint64_t)nIntervalCostTime;
		dValidFlow = (dValidFlow*8) / (1024*1024);
	}

	uint64_t nPushedPackCount = 0;
	int nDropCountForPacketFull = 0;
	int nDropCountForSessionFull = 0;
	int nSessionCount = 0;
	int nMaxUsedSessionSize = 0;
	int nMaxUsedPackSize = 0;
	int nCurSessionUsedCount[MAX_SESSION_THREAD_COUNT] = {0};
	int nCurSessionUsedCountAll = 0;
	uint64_t nSessionCostTime = 0;

	LOGFIX0("*******************statistic data output begin*******************");
	for (int i = 0; i < g_nThreadCount; i++)
	{
		nPushedPackCount += g_nPushedPackCount[i];
		nDropCountForPacketFull += g_nDropCountForPacketFull[i];
		nDropCountForSessionFull += g_nDropCountForSessionFull[i];
		nSessionCount += g_nSessionCount[i];
		nMaxUsedSessionSize += g_nMaxUsedSessionSize[i];
		nMaxUsedPackSize += g_nMaxUsedPackSize[i];
		nCurSessionUsedCount[i] = g_nMaxHttpSessionCount - _idl_session_count[i];
		nCurSessionUsedCountAll += nCurSessionUsedCount[i];
		nSessionCostTime += g_nSessionCostTime[i];
			
		LOGFIX("\n \
		***线程%d数据: \n \
		共过滤%llu个包入包队列 \n \
		丢弃%d个包[包队列溢出] \n \
		包队列使用最大值 = %d \n \
		共创建%d会话 \n \
		放弃创建%d个会话[会话溢出] \n \
		会话队列使用最大值 = %d \n \
		遗留%d个会话[当前会话队列中的会话数] \n \
		会话处理耗时%llu毫秒 \n", 
		i,
		g_nPushedPackCount[i],
		g_nDropCountForPacketFull[i],
		g_nMaxUsedPackSize[i],
		g_nSessionCount[i],
		g_nDropCountForSessionFull[i],
		g_nMaxUsedSessionSize[i],
		nCurSessionUsedCount[i],
		g_nSessionCostTime[i]/1000);
	}
	
	LOGFIX("\n \
		********** \n \
		*数据汇总* \n \
		********** \n \
		共抓取%llu个包(有效包%llu个), 共%llu字节(有效字节%llu字节)[当前%u秒] \n \
		总背景流量%.3lf Mbps(有效背景流量%.3lf Mbps)[当前%u秒] \n \
		共过滤%llu个包入包队列 \n \
		共过滤丢弃%llu个包 \n \
		丢弃%d个包[包队列溢出] \n \
		包队列使用最大值 = %d \n \
		\n \
		共创建%d会话 \n \
		放弃创建%d个会话[会话溢出] \n \
		放弃创建%d个会话[图片/JS类数据] \n \
		丢弃%d个会话[会话超时] \n \
		丢弃%d个会话[会话通道被重用] \n \
		丢弃%d个会话[会话乱序重组缓存队列溢出] \n \
		丢弃%d个会话[内容问题:未知内容类型数=%d; Http内容指针为空数=%d; 内容长度出错数=%d; 返回http协议标识获取失败数=%d] \n \
		遗留%d个会话[当前会话队列中的会话数] \n \
		共发送%d个Http数据[完成会话的Http数据] \n \
		本地缓存%d个Http数据 \n \
		会话队列使用最大值 = %d \n \
		弹出会话队列的会话内容总大小为%llu字节 \n \
		共有%dGzip会话数据[其中%d个Gzip解压失败] \n \
		\n \
		采集器运行时长%u秒 \n \
		会话处理总耗时%llu毫秒 \n \
		获取Http数据处理总耗时%llu毫秒 \n \
		发送Http数据处理总耗时%llu毫秒 \n \
		本地缓存Http数据处理总耗时%llu毫秒 \n", 
		nCapCount,
		nValidCapCount,
		nCapSize,
		nValidCapSize,
		nIntervalCostTime,
		dFlow,
		dValidFlow,
		nIntervalCostTime,
		nPushedPackCount,
		g_nSkippedPackCount,
		nDropCountForPacketFull, 
		nMaxUsedPackSize,
		nSessionCount,
		nDropCountForSessionFull, 
		g_nDropCountForImage,
		g_nTimeOutCount,
		g_nReusedCount,
		g_nLaterPackIsMaxCount,
		g_nContentErrorCount, g_nContentUnknownCount, g_nHttpNullCount, g_nDatalenErrorCount, g_nHttpcodeErrorCount,
		nCurSessionUsedCountAll,
		g_nSendDataCount,
		g_nMaxCacheCount,
		nMaxUsedSessionSize,
		g_nHttpLen,
		g_nGzipCount,
		g_nUnGzipFailCount,
		g_nCapLastTime - g_nCapFisrtTime,
		nSessionCostTime/1000,
		g_nGetDataCostTime/1000,
		g_nSendDataCostTime/1000,
		g_nCacheDataCostTime/1000);

	//uint64_t nIfFlow[MONITOR_COUNT] = {0};
	//uint64_t nIfValidFlow[MONITOR_COUNT] = {0};
	double dIfFlow[MONITOR_COUNT] = {0};
	double dIfValidFlow[MONITOR_COUNT] = {0};
	for (int i = 0; i < _active_sock; i++)
	{
		uint64_t nIfIntervalCapSize = 0;	
		uint64_t nIfValidIntervalCapSize = 0;
		if (0 == nPreIfCapSize[i])
		{
			nIfIntervalCapSize = g_nCapSize[i];
			nPreIfCapSize[i] = g_nCapSize[i];
			nIfValidIntervalCapSize = g_nValidCapSize[i];
			nPreIfValidCapSize[i] = g_nValidCapSize[i];
		}
		else
		{
			nIfIntervalCapSize = g_nCapSize[i] - nPreIfCapSize[i];
			nPreIfCapSize[i] = g_nCapSize[i];
			nIfValidIntervalCapSize = g_nValidCapSize[i] - nPreIfValidCapSize[i];
			nPreIfValidCapSize[i] = g_nValidCapSize[i];
		}
		
		if (nIntervalCostTime != 0)
		{
			dIfFlow[i] = nIfIntervalCapSize / (uint64_t)nIntervalCostTime;
			dIfFlow[i] = (dIfFlow[i]*8) / (1024*1024);
			dIfValidFlow[i] = nIfValidIntervalCapSize / (uint64_t)nIntervalCostTime;
			dIfValidFlow[i] = (dIfValidFlow[i]*8) / (1024*1024);
		}

		LOGFIX("\n \
		***端口[%s]采集数据情况: \n \
		共抓取%llu个包(有效包%llu个), 共%llu字节(有效字节%llu字节)[当前%u秒] \n \
		总背景流量%.3lf Mbps(有效背景流量%.3lf Mbps)[当前%u秒] \n", 
		g_arrayActiveFd[i].szInterface,
		g_nCapCount[i],
		g_nValidCapCount[i],
		g_nCapSize[i],
		g_nValidCapSize[i],
		nIntervalCostTime,
		dIfFlow[i],
		dIfValidFlow[i],
		nIntervalCostTime);	
	}
	LOGFIX0("*******************statistic data output end*******************");
	
	if (bIsPrintScreen)
	{
		for (int i = 0; i < g_nThreadCount; i++)
		{
			printf("\n \
			***线程%d数据: \n \
			共过滤%llu个包入包队列 \n \
			丢弃%d个包[包队列溢出] \n \
			包队列使用最大值 = %d \n \
			共创建%d会话 \n \
			放弃创建%d个会话[会话溢出] \n \
			会话队列使用最大值 = %d \n \
			遗留%d个会话[当前会话队列中的会话数] \n \
			会话处理耗时%llu毫秒 \n", 
			i,
			g_nPushedPackCount[i],
			g_nDropCountForPacketFull[i],
			g_nMaxUsedPackSize[i],
			g_nSessionCount[i],
			g_nDropCountForSessionFull[i],
			g_nMaxUsedSessionSize[i],
			nCurSessionUsedCount[i],
			g_nSessionCostTime[i]/1000);
		}
		
		printf("\n \
			********** \n \
			*数据汇总* \n \
			********** \n \
			共抓取%llu个包(有效包%llu个), 共%llu字节(有效字节%llu字节)[当前%u秒] \n \
			总背景流量%.3lf Mbps(有效背景流量%.3lf Mbps)[当前%u秒] \n \
			共过滤%llu个包入包队列 \n \
			共过滤丢弃%llu个包 \n \
			丢弃%d个包[包队列溢出] \n \
			包队列使用最大值 = %d \n \
			\n \
			共创建%d会话 \n \
			放弃创建%d个会话[会话溢出] \n \
			放弃创建%d个会话[图片/JS类数据] \n \
			丢弃%d个会话[会话超时] \n \
			丢弃%d个会话[会话通道被重用] \n \
			丢弃%d个会话[会话乱序重组缓存队列溢出] \n \
			丢弃%d个会话[内容问题:未知内容类型数=%d; Http内容指针为空数=%d; 内容长度出错数=%d; 返回http协议标识获取失败数=%d] \n \
			遗留%d个会话[当前会话队列中的会话数] \n \
			共发送%d个Http数据[完成会话的Http数据] \n \
			本地缓存%d个Http数据 \n \
			会话队列使用最大值 = %d \n \
			弹出会话队列的会话内容总大小为%llu字节 \n \
			共有%dGzip会话数据[其中%d个Gzip解压失败] \n \
			\n \
			采集器运行时长%u秒 \n \
			会话处理总耗时%llu毫秒 \n \
			获取Http数据处理总耗时%llu毫秒 \n \
			发送Http数据处理总耗时%llu毫秒 \n \
			本地缓存Http数据处理总耗时%llu毫秒 \n", 
			nCapCount,
			nValidCapCount,
			nCapSize,
			nValidCapSize,
			nIntervalCostTime,
			dFlow,
			dValidFlow,
			nIntervalCostTime,
			nPushedPackCount,
			g_nSkippedPackCount,
			nDropCountForPacketFull, 
			nMaxUsedPackSize,
			nSessionCount,
			nDropCountForSessionFull, 
			g_nDropCountForImage,
			g_nTimeOutCount,
			g_nReusedCount,
			g_nLaterPackIsMaxCount,
			g_nContentErrorCount, g_nContentUnknownCount, g_nHttpNullCount, g_nDatalenErrorCount, g_nHttpcodeErrorCount,
			nCurSessionUsedCountAll,
			g_nSendDataCount,
			g_nMaxCacheCount,
			nMaxUsedSessionSize,
			g_nHttpLen,
			g_nGzipCount,
			g_nUnGzipFailCount,
			g_nCapLastTime - g_nCapFisrtTime,
			nSessionCostTime/1000,
			g_nGetDataCostTime/1000,
			g_nSendDataCostTime/1000,
			g_nCacheDataCostTime/1000);

		for (int i = 0; i < _active_sock; i++)
		{
			printf("\n \
			***端口[%s]采集数据情况: \n \
			共抓取%llu个包(有效包%llu个), 共%llu字节(有效字节%llu字节)[当前%u秒] \n \
			总背景流量%.3lf Mbps(有效背景流量%.3lf Mbps)[当前%u秒] \n", 
			g_arrayActiveFd[i].szInterface,
			g_nCapCount[i],
			g_nValidCapCount[i],
			g_nCapSize[i],
			g_nValidCapSize[i],
			nIntervalCostTime,
			dIfFlow[i],
			dIfValidFlow[i],
			nIntervalCostTime);	
		}
	}
}

struct tcp_session* GetHttpSession(const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	return NULL;
}

struct tcp_session* CleanHttpSession(struct tcp_session* pSession)
{
	LOGDEBUG("Session[%d][%d] start clean!", pSession->thread_index, pSession->index);
	
	if (pSession->flag != HTTP_SESSION_IDL) 
	{
		unsigned thread_index = pSession->thread_index;
		unsigned index = pSession->index;
		void* packet = pSession->data;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGDEBUG("Session[%d][%d] clean packet data successfully!", pSession->thread_index, pSession->index);
		
		packet = pSession->pack_later;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGDEBUG("Session[%d][%d] clean packet_later data successfully!", pSession->thread_index, pSession->index);
		
		if (pSession->request_head!=NULL)
		{
			free(pSession->request_head);
			pSession->request_head = NULL;
		}

		if (pSession->response_head!=NULL)
		{
			free(pSession->response_head);
			pSession->response_head = NULL;
		}

		if (pSession->cur_content!=NULL)
		{
			free(pSession->cur_content);
			pSession->cur_content = NULL;
		}
		
		if (pSession->part_content!=NULL)
		{
			free(pSession->part_content);
			pSession->part_content = NULL;
		}
		
		LOGDEBUG("Session[%d][%d] clean request_head,response_head, cur_content and part_content successfully!", pSession->thread_index, pSession->index);
		
		memset(pSession, 0, sizeof(*pSession));
		pSession->thread_index = thread_index;
		pSession->index = index;
		pSession->flag = HTTP_SESSION_IDL;

		pthread_mutex_lock(&_ile_session_count_lock[pSession->thread_index]);
		_idl_session_count[pSession->thread_index]++;
		pthread_mutex_unlock(&_ile_session_count_lock[pSession->thread_index]);
	}

	LOGDEBUG("Session[%d][%d] end clean!", pSession->thread_index, pSession->index);
	return pSession;
}

void SessionTimeoutProcess()
{
	struct tcp_session *pSession = NULL;
	for (int i = 0; i < g_nThreadCount; i++)
	{
		pthread_mutex_lock(&_session_proc_lock[i]);
		for (int j = 0; j < g_nMaxHttpSessionCount; j++) 
		{
			pSession = &_http_session_array[i][j];
			if (pSession->flag == HTTP_SESSION_IDL || pSession->flag == HTTP_SESSION_FINISH) 
				continue;

			// process timeout
			time_t tmCur = time(NULL);
			if (tmCur - pSession->update.tv_sec >= g_nHttpTimeout) 
			{
				++g_nTimeOutCount;
				LOGWARN("Session[%d][%d] is timeout. flag=%d res1=%d res2=%d g_nTimeOutCount=%d", i, j, pSession->flag, pSession->res1, pSession->res2, g_nTimeOutCount);
				LOGINFO("Timeout Session[%d][%d] Request Head Content = %s", i, j, pSession->request_head);

				if (g_bIsLogTimeoutData)
					LogDropSessionData("Rebuild Failed:Time Out", pSession);

				if (!g_bIsSendTimeoutData)
					CleanHttpSession(pSession);
				else
				{
					int nRs = AppendLaterPacket(i, j, 1);
					if (!nRs)
					{
						pSession->finish_type = HTTP_SESSION_FINISH_TIMEOUT;
						pSession->flag = HTTP_SESSION_FINISH;
						if (push_queue(_whole_content, pSession) < 0)
						{
							++g_nCountWholeContentFull[i];
							LOGWARN("Thread[%d]'s whole content queue is full. count = %d", i, g_nCountWholeContentFull[i]);
						}
					}
				}
			}
			else if ((tmCur - pSession->update.tv_sec >= 30 && tmCur - pSession->update.tv_sec <= 35) && (pSession->later_pack_size > 0))
			{
				LOGWARN("Session[%d][%d] do not update time >=30s and <= 35s, do force restore!", i, j);
				LOGINFO("Timeout Session[%d][%d] force restore, Request Head Content = %s", i, j, pSession->request_head);

				AppendLaterPacket(i, j, 1);
			}
			else if ((tmCur - pSession->update.tv_sec >= 20 && tmCur - pSession->update.tv_sec <= 25) && (pSession->later_pack_size > 0))
			{
				LOGWARN("Session[%d][%d] do not update time >=20s and <= 25s, do force restore!", i, j);
				LOGINFO("Timeout Session[%d][%d] force restore, Request Head Content = %s", i, j, pSession->request_head);

				AppendLaterPacket(i, j, 1);
			}
			else if ((tmCur - pSession->update.tv_sec >= 10 && tmCur - pSession->update.tv_sec <= 15) && (pSession->later_pack_size > 0))
			{
				LOGWARN("Session[%d][%d] do not update time >=10s and <= 15s, do force restore!", i, j);
				LOGINFO("Session[%d][%d] force restore, Request Head Content = %s", i, j, pSession->request_head);

				AppendLaterPacket(i, j, 1);
			}
			
		}
		pthread_mutex_unlock(&_session_proc_lock[i]);
	}
}

int NewHttpSession(int nThreadIndex, const char* packet)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead=TCPHDR(iphead);
	unsigned contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
	char *content = (void*)tcphead + tcphead->doff*4;
	char* enter = NULL;
	for (int i = 0; i < contentlen; i++)
	{
		if (content[i] == '\r')
		{
			enter = &content[i];
			break;
		}
		else if (content[i] == '\n')
		{
			enter = &content[i];
			LOGWARN0("The end of first pack head line is N!");
			break;
		}
	}
	
	if (NULL == enter)
	{
		return -1;
	}
	
	char tmp = *enter;
	*enter = '\0';
	const char* cmdline = content;
	LOGTRACE0(cmdline);
	*enter = tmp;

	unsigned init_content_type = HTTP_CONTENT_NONE;
	char* pTmpContent[RECV_BUFFER_LEN] = {0};
	memcpy(pTmpContent, content, contentlen);
	pTmpContent[contentlen] = '\0';
	strlwr(pTmpContent);
	
	if (!g_bIsCapRes)
	{
		if ((memmem(pTmpContent, contentlen, ".gif ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".js ", 4) != NULL)
			|| (memmem(pTmpContent, contentlen, ".js?", 4) != NULL)
			|| (memmem(pTmpContent, contentlen, ".css ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".jpg ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".ico ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".bmp ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".png ", 5) != NULL))
			//|| (memmem(pTmpContent, contentlen, ".tif ", 5) != NULL)
			//|| (memmem(pTmpContent, contentlen, ".tiff ", 6) != NULL))
		{
			if (is_log_drop_data())
			{
				char sip[20] = {0}, dip[20] = {0};
				char szUrlBody[1500] = {0};
				char szUrl[1500] = {0};
				inet_ntop(AF_INET, &iphead->saddr, sip, 20);
				inet_ntop(AF_INET, &iphead->daddr, dip, 20);

				int nStart = 5;
				char *pszUrlStart = memmem(content, contentlen, "POST ", 5);
				if (NULL == pszUrlStart)
				{
					pszUrlStart = memmem(content, contentlen, "GET ", 4);
					nStart = 4;
				}
				
				char *pszUrlEnd = memmem(content, contentlen, " HTTP/1.1", 9);
				if (NULL == pszUrlEnd)
					pszUrlEnd = memmem(content, contentlen, " HTTP/1.0", 9);

				if ((pszUrlStart != NULL) && (pszUrlEnd != NULL))
				{
					int nUrlBodyLen = pszUrlEnd - pszUrlStart - nStart;
					strncpy(szUrlBody, pszUrlStart+nStart, nUrlBodyLen);
				}
				
				if (szUrlBody[0] != '\0')
				{
					if (strstr(szUrlBody, "http://") == NULL)
					{
						char *pszHost = memmem(content, contentlen, "Host: ", 6);
						if (pszHost != NULL)
						{
							strcpy(szUrl, "Http://");
							char *pszHostEnd = strstr(pszHost, "\r\n"); 
							if (pszHostEnd != NULL)
							{
								int nHostLen = pszHostEnd - pszHost - 6;
								strncat(szUrl, pszHost+6, nHostLen);
							}
						}

						if (szUrl[0] != '\0')
						{
							strcat(szUrl, szUrlBody);
						}
						else
						{
							strcpy(szUrl, szUrlBody);
						}
					}
					else
					{
						strcpy(szUrl, szUrlBody);
					}
				}

				struct tm tm_tmp = {0};
				char szCreateTime[50] = {0};
				localtime_r(&tv->tv_sec, &tm_tmp);
				sprintf(szCreateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
						tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
						tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
						(int)(tv->tv_usec/1000));

				memset(&tm_tmp, 0, sizeof(tm_tmp));
				char szUpdateTime[50] = {0};
				localtime_r(&tv->tv_sec, &tm_tmp);
				sprintf(szUpdateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
						tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
						tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
						(int)(tv->tv_usec/1000));

				struct timeval tv_drop;
				gettimeofday(&tv_drop, NULL);
				char szDropTime[50] = {0};
				memset(&tm_tmp, 0, sizeof(tm_tmp));
				localtime_r(&tv_drop.tv_sec, &tm_tmp);
				sprintf(szDropTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
						tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
						tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
						(int)(tv_drop.tv_usec/1000));
				
				LOG_DROP_DATA(sip, dip, "Drop Image", szCreateTime, szUpdateTime, szDropTime, szUrl);
			}
			
			return -3;
		}
	}
	else
	{
		if ((memmem(pTmpContent, contentlen, ".gif ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".js ", 4) != NULL)
			|| (memmem(pTmpContent, contentlen, ".js?", 4) != NULL)
			|| (memmem(pTmpContent, contentlen, ".css ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".jpg ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".ico ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".bmp ", 5) != NULL)
			|| (memmem(pTmpContent, contentlen, ".png ", 5) != NULL))
			//|| (memmem(pTmpContent, contentlen, ".tif ", 5) != NULL)
			//|| (memmem(pTmpContent, contentlen, ".tiff ", 6) != NULL))
		{
			init_content_type = HTTP_CONTENT_RES;
		}
	}
	
	// find IDL session
	int nIdlIndex = -1;
	struct tcp_session* pIDL = NULL;
	int index = 0;

	pthread_mutex_lock(&_session_proc_lock[nThreadIndex]);
	for (; index < g_nMaxHttpSessionCount; ++index) 
	{
		if (_http_session_array[nThreadIndex][index].flag != HTTP_SESSION_IDL && 
			_http_session_array[nThreadIndex][index].flag != HTTP_SESSION_FINISH) 
		{
			struct tcp_session* pREQ = &_http_session_array[nThreadIndex][index];
			if (pREQ->client.ip.s_addr==iphead->saddr && pREQ->client.port==tcphead->source 
				&& pREQ->server.ip.s_addr==iphead->daddr && pREQ->server.port==tcphead->dest
				&& pREQ->seq == tcphead->seq && pREQ->ack == tcphead->ack_seq) 
			{ // client -> server be reuse.
				++g_nReusedCount;
				LOGWARN("Session[%d][%d] channel is reused. \n \ 
							flag=%d, res1=%u, res2=%u, session.seq=%u, session.ack=%u, iphead.seq=%u, iphead.ack=%u; g_nReusedCount=%d", 
						nThreadIndex, index, pREQ->flag, pREQ->res1, pREQ->res2, 
						pREQ->seq, pREQ->ack, tcphead->seq, tcphead->ack_seq, g_nReusedCount);

				if (g_bIsLogChannelReusedData)
					LogDropSessionData("Rebuild Failed:Channel Reuse", pREQ);

				if (!g_bIsSendChannelReusedData)
				{
					CleanHttpSession(pREQ);
					nIdlIndex = index;

					break;
				}
				else
				{
					pREQ->finish_type = HTTP_SESSION_FINISH_CHANNEL_REUSED;
					pREQ->flag = HTTP_SESSION_FINISH;
					if (push_queue(_whole_content, pREQ) < 0)
					{
						++g_nCountWholeContentFull[nThreadIndex];
						LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
					}
				}
			} 
			else
			{
				continue;
			}
		}
		else if (HTTP_SESSION_IDL == _http_session_array[nThreadIndex][index].flag)
		{
			nIdlIndex = index;
			break;
		}
	}

	if (nIdlIndex != -1)
		pIDL = &_http_session_array[nThreadIndex][nIdlIndex];
	else
	{
		pthread_mutex_unlock(&_session_proc_lock[nThreadIndex]);
		return -2;
	}

	pIDL->flag = HTTP_SESSION_REQUESTING;
	pIDL->client.ip.s_addr = iphead->saddr;
	pIDL->server.ip.s_addr = iphead->daddr;
	pIDL->client.port = tcphead->source;
	pIDL->server.port = tcphead->dest;
	pIDL->create = *tv;
	pIDL->update = *tv;
	pIDL->seq = tcphead->seq;
	pIDL->ack = tcphead->ack_seq;
	pIDL->data = (void*)packet;
	pIDL->lastdata = (void*)packet;
	pIDL->res0 = contentlen;
	pIDL->res1 = 0;
	pIDL->res2 = 0;
	pIDL->res_true_len = 0;
	pIDL->transfer_flag = HTTP_TRANSFER_INIT;
	pIDL->response_head_recv_flag = 0;
	pIDL->content_encoding_gzip = 0;
	pIDL->content_type = init_content_type;
	pIDL->force_restore_flag = 0;
	pIDL->response_head = NULL;
	pIDL->response_head_gen_time = 0;
	pIDL->response_head_len = 0;
	pIDL->part_content = NULL;
	pIDL->part_content_len = 0;
	pIDL->cur_content = NULL;
	pIDL->cur_content_len = 0;
	pIDL->request_head_len_valid_flag = 0;
	*(const char**)packet = NULL;
	if (*(unsigned*)content==_get_image && content[contentlen-4]=='\r'
			&& content[contentlen-3]=='\n' && content[contentlen-2]=='\r'
			&& content[contentlen-1]=='\n') 
	{
		pIDL->flag = HTTP_SESSION_REQUEST;
	}

	pIDL->request_head = (char*)calloc(1, contentlen+1);
	memcpy(pIDL->request_head, content, contentlen);
	pIDL->request_head_len = contentlen+1;
		
	LOGDEBUG("Session[%d][%d]Start request in NewHttpSession, content= %s", pIDL->thread_index, pIDL->index, content);

	pthread_mutex_lock(&_ile_session_count_lock[nThreadIndex]);
	_idl_session_count[nThreadIndex]--;
	pthread_mutex_unlock(&_ile_session_count_lock[nThreadIndex]);
	
	int nSessionSize = g_nMaxHttpSessionCount - _idl_session_count[nThreadIndex];
	if (nSessionSize > g_nMaxUsedSessionSize[nThreadIndex])
	{
		g_nMaxUsedSessionSize[nThreadIndex] = nSessionSize;
	}

	++g_nSessionCount[nThreadIndex];
	LOGINFO("Thread[%d]'s Current Session Count = %d , Max Used Session Buffer Size = %d !", nThreadIndex, g_nSessionCount[nThreadIndex], g_nMaxUsedSessionSize[nThreadIndex]);	

	pthread_mutex_unlock(&_session_proc_lock[nThreadIndex]);
	return index;
}

int AppendServerToClient(int nThreadIndex, int nIndex, const char* pPacket, int bIsCurPack, int nIsForceRestore)
{ 
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
	char *content = (void*)tcphead + tcphead->doff*4;
	struct tcp_session *pSession = &_http_session_array[nThreadIndex][nIndex];
	int nForceRestoreContentLen = 0;
	int nIsForceRestoreSuc = 0;
	// Check seq and ack. not fix.
	if (pSession->seq != tcphead->ack_seq || (pSession->ack+pSession->res0) != tcphead->seq)
	{ 
		if (pSession->ack == tcphead->seq && (pSession->seq + pSession->res0) == tcphead->ack_seq)  // it's not woring on first time.
		{
			LOGDEBUG("S->C packet for first response. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
					nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
			char *pszCode = memmem(content, contentlen, "HTTP/1.1 100", 12);
			if (pszCode == NULL)
				pszCode = memmem(content, contentlen, "HTTP/1.0 100", 12);

			if (pszCode != NULL)
			{
				LOGWARN("Drop this packet for state 100 continue. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

				pSession->flag = HTTP_SESSION_RESPONSEING;
				pSession->seq = tcphead->ack_seq;
				pSession->ack = tcphead->seq;
				pSession->res0 = contentlen;
				pSession->update = *tv;
				
				return HTTP_APPEND_DROP_PACKET;
			}
		}
		else if (((pSession->ack + pSession->res0) == tcphead->seq) && (abs(tcphead->ack_seq - pSession->seq) <= 4380))
		{
			LOGDEBUG("Session[%d][%d] S->C packet, tcphead->ack_seq != pSession->seq. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
					nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

			if ((*(unsigned*)content == _http_image) && (pSession->transfer_flag != HTTP_TRANSFER_INIT))
			{
				LOGWARN("Drop this packet for response repeatly. Session[%d][%d] S->C packet, tcphead->ack_seq != pSession->seq. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
					nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
				
				return HTTP_APPEND_DROP_PACKET;
			}
		}
		else 
		{
			if (bIsCurPack 
				&& (((pSession->seq == tcphead->ack_seq) && ((pSession->ack + pSession->res0) < tcphead->seq))
					 || ((pSession->seq + pSession->res0) == tcphead->ack_seq && pSession->ack < tcphead->seq)))
			{
				if (pSession->later_pack_size != MAX_LATER_PACKETS)
				{
					if (pSession->pack_later == NULL)
						pSession->pack_later = (void*)pPacket;
					else
						*(const char**)pSession->last_pack_later = pPacket;

					*(const char**)pPacket = NULL;
					pSession->last_pack_later = (void*)pPacket;
					pSession->later_pack_size++;

					LOGDEBUG("This packet is later packet for S->C wrong order. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

					return HTTP_APPEND_ADD_PACKET_LATER;
				}
				else
				{
					int nRs = AppendLaterPacket(nThreadIndex, nIndex, 1);
					if (nRs)
					{
						LOGINFO("Session[%d][%d] Force restore successfully. Drop this packet. cur.seq=%u cur.ack=%u cur.len=%u", 
									nThreadIndex, nIndex, tcphead->seq, tcphead->ack_seq, contentlen);
						
						return HTTP_APPEND_DROP_PACKET;
					}
					
					if (pSession->seq == tcphead->ack_seq || (pSession->ack+pSession->res0) == tcphead->seq)
					{
						LOGDEBUG("Session[%d][%d] S->C packet[After force restore]. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
									nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
					}
					else
					{
						if (pSession->later_pack_size != MAX_LATER_PACKETS)
						{
							if (pSession->pack_later == NULL)
								pSession->pack_later = (void*)pPacket;
							else
								*(const char**)pSession->last_pack_later = pPacket;

							*(const char**)pPacket = NULL;
							pSession->last_pack_later = (void*)pPacket;
							pSession->later_pack_size++;

							LOGDEBUG("This packet is later packet for S->C wrong order. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
									nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

							return HTTP_APPEND_ADD_PACKET_LATER;
						}
						else
						{
							++g_nLaterPackIsMaxCount;
							LOGWARN("Drop this packet and clean session. The later packet size is max. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u, g_nLaterPackIsMaxCount = %d", 
									nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen, g_nLaterPackIsMaxCount);

							if (g_bIsLogDisorderRebuildFailedData)
								LogDropSessionData("Rebuild Failed:Disorder Rebuild Failed", pSession);
							
							if (!g_bIsSendDisorderRebuildFailedData)
								CleanHttpSession(pSession);
							else
							{
								pSession->finish_type = HTTP_SESSION_FINISH_DISORDER_REBUILD_FAILED;
								pSession->flag = HTTP_SESSION_FINISH;
								if (push_queue(_whole_content, pSession) < 0)
								{
									++g_nCountWholeContentFull[nThreadIndex];
									LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
								}
							}
							
							return HTTP_APPEND_DROP_PACKET;
						}
					}
				}
			}
			else
			{
				if (!bIsCurPack)
				{
					if (!nIsForceRestore)
					{
						if ((pSession->seq == tcphead->ack_seq && (pSession->ack + pSession->res0) < tcphead->seq)
							|| ((pSession->seq + pSession->res0) == tcphead->ack_seq && pSession->ack < tcphead->seq))
						{
							return HTTP_APPEND_ADD_PACKET_LATER;
						}
					}
					else
					{
						if (pSession->seq == tcphead->ack_seq && (tcphead->seq-(pSession->ack + pSession->res0)) <= 3000)
						{
							nIsForceRestoreSuc = 1;
							nForceRestoreContentLen = tcphead->seq - (pSession->ack + pSession->res0) + contentlen;
						}
						else
						{
							return HTTP_APPEND_ADD_PACKET_LATER;
						}
					}
				}

				if (nIsForceRestoreSuc)
				{
					pSession->force_restore_flag = 1;
					LOGDEBUG("Session[%d][%d] S->C packet[Force restore]. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
								nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
				}
				else
				{
					LOGDEBUG("Drop this packet for S->C wrong order. Session[%d][%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
					
					return HTTP_APPEND_DROP_PACKET;
				}
			}
		}
	}
	else
	{
		LOGDEBUG("Session[%d][%d] S->C packet. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
					nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
	}

	if (pSession->flag == HTTP_SESSION_REQUESTING)
		return HTTP_APPEND_DROP_PACKET;
	
	/*
	pSession->flag = HTTP_SESSION_RESPONSEING;
	pSession->seq = tcphead->ack_seq;
	pSession->ack = tcphead->seq;
	pSession->res0 = contentlen;
	if (bIsCurPack || nIsForceRestore)
		pSession->update = *tv;

	*(const char**)pPacket = NULL;
	*(const char**)pSession->lastdata = pPacket;
	pSession->lastdata = (void*)pPacket;
	*/
	
	// Process the response of the head
	if ((*(unsigned*)content == _http_image) 
			&& (HTTP_TRANSFER_INIT == pSession->transfer_flag) 
			&& (NULL == pSession->response_head))
	{
		pSession->flag = HTTP_SESSION_RESPONSEING;
		pSession->seq = tcphead->ack_seq;
		pSession->ack = tcphead->seq;
		pSession->res0 = contentlen;
		if (bIsCurPack || nIsForceRestore)
			pSession->update = *tv;

		*(const char**)pPacket = NULL;
		*(const char**)pSession->lastdata = pPacket;
		pSession->lastdata = (void*)pPacket;
		
		pSession->response_head = (char*)calloc(1, contentlen+1);
		memcpy(pSession->response_head, content, contentlen);
		pSession->response_head_len = contentlen+1;
		pSession->response_head_gen_time++;
		if (memmem(content, contentlen, "\r\n\r\n", 4) != NULL)
		{
			pSession->response_head_recv_flag = 1;
			content = pSession->response_head;	
		}
		else
		{
			LOGDEBUG("Session[%d][%d] response head is not enough, continue to generate. content= %s",
				nThreadIndex, nIndex, content);
		}
	} 
	else 
	{
		if ((HTTP_TRANSFER_INIT == pSession->transfer_flag) && (NULL != pSession->response_head))
		{
			pSession->flag = HTTP_SESSION_RESPONSEING;
			pSession->seq = tcphead->ack_seq;
			pSession->ack = tcphead->seq;
			pSession->res0 = contentlen;
			if (bIsCurPack || nIsForceRestore)
				pSession->update = *tv;

			*(const char**)pPacket = NULL;
			*(const char**)pSession->lastdata = pPacket;
			pSession->lastdata = (void*)pPacket;
			
			LOGDEBUG("Session[%d][%d] the next response contentlen=%d, content= %s",
				nThreadIndex, nIndex, contentlen, content);
			int last_len = pSession->response_head_len;
			pSession->response_head = realloc(pSession->response_head, last_len + contentlen);
			memcpy(pSession->response_head+last_len-1, content, contentlen);
			pSession->response_head[last_len+contentlen-1] = '\0';
			pSession->response_head_len = last_len + contentlen;
			pSession->response_head_gen_time++;
			content = pSession->response_head;
			contentlen = last_len + contentlen;
			if ((memmem(content, contentlen, "\r\n\r\n", 4) != NULL)
				|| (3 == pSession->response_head_gen_time))
			{
				LOGDEBUG("Session[%d][%d] response head generate successfully. content= %s",
					nThreadIndex, nIndex, content);
				
				pSession->response_head_recv_flag = 1;
			}
			else
			{
				LOGDEBUG("Session[%d][%d] response head is not enough, continue to generate. content= %s",
					nThreadIndex, nIndex, content);
			}
		}
		else if (pSession->transfer_flag != HTTP_TRANSFER_INIT)
		{
			pSession->flag = HTTP_SESSION_RESPONSEING;
			pSession->seq = tcphead->ack_seq;
			pSession->ack = tcphead->seq;
			pSession->res0 = contentlen;
			if (bIsCurPack || nIsForceRestore)
				pSession->update = *tv;

			*(const char**)pPacket = NULL;
			*(const char**)pSession->lastdata = pPacket;
			pSession->lastdata = (void*)pPacket;
			
			pSession->res2 += (!nIsForceRestoreSuc) ? contentlen : nForceRestoreContentLen;
			pSession->res_true_len += contentlen;
			LOGTRACE("Session[%d][%d] part_reponse_len = %u/%u", nThreadIndex, nIndex, pSession->res2, pSession->res1);
		}
		else
		{
			return HTTP_APPEND_DROP_PACKET;
		}
	}

	// Process the part content of response
	if (pSession->part_content != NULL)
	{
		free(pSession->part_content);
		pSession->part_content = NULL;
	}

	if (pSession->cur_content != NULL)
	{
		int nPartContentLen = pSession->cur_content_len + contentlen;
		pSession->part_content = (char*)calloc(1, nPartContentLen+1);
		pSession->part_content_len = nPartContentLen;
		memcpy(pSession->part_content, pSession->cur_content, pSession->cur_content_len);
		memcpy(pSession->part_content+pSession->cur_content_len, content, contentlen);

		free(pSession->cur_content);
		pSession->cur_content = NULL;
	}
	else
	{
		pSession->part_content = (char*)calloc(1, contentlen+1);
		pSession->part_content_len = contentlen;
		memcpy(pSession->part_content, content, contentlen);
	}

	if (contentlen > 0)
	{
		pSession->cur_content = (char*)calloc(1, contentlen+1);
		pSession->cur_content_len = contentlen;
		memcpy(pSession->cur_content, content, contentlen);
	}

	// Process the reponse head content
	if (1 == pSession->response_head_recv_flag)
	{
		pSession->response_head_recv_flag = 0;
		pSession->transfer_flag = HTTP_TRANSFER_NONE;
		strlwr(content);
		LOGDEBUG("Session[%d][%d] response head generate contentlen= %d, content= %s", nThreadIndex, nIndex, contentlen, content);
		
		char* content_encoding = memmem(content, contentlen, "content-encoding: gzip", 22);
		if (content_encoding != NULL)
			pSession->content_encoding_gzip = 1;

		char* content_type = memmem(content, contentlen, "content-type: ", 14);
		if ((content_type != NULL) && (HTTP_CONTENT_NONE == pSession->content_type))
		{
			if (strncmp(content_type+14, "text/html", 9) == 0 
				|| strncmp(content_type+14, "text/xml", 8) == 0 
				|| strncmp(content_type+14, "text/plain", 10) == 0
				|| strncmp(content_type+14, "application/x-ami", 17) == 0
				|| strncmp(content_type+14, "text/javascript", 15) == 0)
			{
				pSession->content_type = HTTP_CONTENT_HTML;
			}
			else if (strncmp(content_type+14, "application/pdf", 15) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_PDF;
			}
			else if (strncmp(content_type+14, "application/kdh", 15) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_KDH;
			}
			else if (strncmp(content_type+14, "text/application/x-research-info-systems", 40) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_RIS;
			}
			else if (strncmp(content_type+14, "application/.pdg", 16) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_PDG;
			}
			else if (strncmp(content_type+14, "application/x-ceb", 17) == 0)
			{
				if (pSession->request_head != NULL)
				{
					char *tmp = NULL;
					char *pszReqRange = memmem(pSession->request_head, pSession->request_head_len, "Range: bytes=0-", 15);
					if (pszReqRange != NULL)
					{
						int nReqMax = strtol(pszReqRange+15, &tmp, 10);
						char *pszResRange = memmem(content, contentlen, "content-range: bytes 0-", 23);
						if ((nReqMax > 0) && (pszResRange != NULL))
						{
							char *pszResRangeSep = strchr(pszResRange, '/');	
							if (pszResRangeSep != NULL)
							{
								*pszResRangeSep = '\r';
								int nResMax = strtol(pszResRange+23, &tmp, 10);
								*pszResRangeSep = '/';
								if (nResMax == nReqMax)
								{
									pszResRangeSep++;
									int nTotalNum = strtol(pszResRangeSep, &tmp, 10);
									if ((nResMax+1) == nTotalNum)
										pSession->content_type = HTTP_CONTENT_FILE_CEB;
								}
							}
						}
					}
				}
			}
			else if ((strncmp(content_type+14, "application/octet-stream", 24) == 0)
					   || (strncmp(content_type+14, "application/x-download", 22) == 0))
			{
				char* pszFileType = memmem(content, contentlen, ".pdf", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_PDF;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "application/caj", 15) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_CAJ;					
			}
			else if (strncmp(content_type+14, "application/text", 16) == 0)
			{
				char* pszFileType = memmem(content, contentlen, ".marc", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_MARC;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "application/x-research-info-systems", 35) == 0)
			{
				char* pszFileType = memmem(content, contentlen, ".ris", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_RIS;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "application/bibtex", 18) == 0)
			{
				char* pszFileType = memmem(content, contentlen, ".bib", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_BIB;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "application/x-no-such-app", 25) == 0)
			{
				char* pszFileType = memmem(content, contentlen, ".txt", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_TXT;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "text/trs", 8) == 0)
			{
				char* pszFileType = memmem(content, contentlen, ".txt", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_TXT;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
			else if (strncmp(content_type+14, "application/rtf", 15) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_RTF;					
			}
			else if (strncmp(content_type+14, "application/ms-excel", 20) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_EXCEL;					
			}
			else if (strncmp(content_type+14, "application/vnd.ms-excel", 24) == 0)
			{
				pSession->content_type = HTTP_CONTENT_FILE_EXCEL;					
			}
		}
		else if (pSession->content_type != HTTP_CONTENT_RES)
		{
			char *pszContentLen = memmem(content, contentlen, "content-length:", 15);
			char *pszTE = memmem(content, contentlen, "transfer-encoding:", 18);
			char *pszChunked = memmem(content, contentlen, "chunked", 7);
			if ((pszContentLen == NULL) && ((pszTE == NULL) || (pszChunked == NULL)))
			{
				char *pszCode = memmem(content, contentlen, "http/1.1 200", 12);
				if (pszCode == NULL)
					pszCode = memmem(content, contentlen, "http/1.0 200", 12);
				
				if (pszCode != NULL)
				{
					LOGDEBUG("Session[%d][%d] with html end, g_nHtmlEnd=%d content= %s", nThreadIndex, nIndex, ++g_nHtmlEnd, content);
					pSession->transfer_flag = HTTP_TRANSFER_WITH_HTML_END;
				}
				else
				{
					LOGDEBUG("Session[%d][%d] with transfer none, g_nNone=%d content= %s", nThreadIndex, nIndex, ++g_nNone, content);
					pSession->transfer_flag = HTTP_TRANSFER_NONE;
				}
			}
			else
			{
				char *pszSB = memmem(pSession->request_head, pSession->request_head_len, "showbook.do", 11);
				if (pszSB != NULL)
				{
					pSession->content_type = HTTP_CONTENT_HTML;
				}
			}
		}
		
		if ((HTTP_CONTENT_HTML == pSession->content_type) || (HTTP_CONTENT_RES == pSession->content_type))
		{
			char *tmp = NULL;
			char *pszContentLen = memmem(content, contentlen, "content-length:", 15);
			if (pszContentLen != NULL) 
			{
				pSession->transfer_flag = HTTP_TRANSFER_HAVE_CONTENT_LENGTH;
				pSession->res1 = strtol(pszContentLen+15, &tmp, 10);
				LOGDEBUG("Session[%d][%d] Content-Length = %u, content = %s", nThreadIndex, nIndex, pSession->res1, content);
				if ((tmp = memmem(content, contentlen, "\r\n\r\n", 4)) != NULL) 
				{
					pSession->res2 = contentlen - (tmp-content) - 4;
					pSession->res_true_len = pSession->res2;
				}
			}
			else
			{
				char *pszTE = memmem(content, contentlen, "transfer-encoding:", 18);
				char *pszChunked = memmem(content, contentlen, "chunked", 7);
				if ((pszTE != NULL) && (pszChunked != NULL))
				{
					pSession->transfer_flag = HTTP_TRANSFER_CHUNKED;
					LOGDEBUG("Session[%d][%d]Transfer-Encoding: chunked, g_nChunked = %d content = %s", nThreadIndex, nIndex, ++g_nChunked, content);
				}
				else
				{
					char *pszCode = memmem(content, contentlen, "http/1.1 200", 12);
					if (pszCode == NULL)
						pszCode = memmem(content, contentlen, "http/1.0 200", 12);
					
					if (pszCode != NULL)
					{
						LOGDEBUG("Session[%d][%d]with html end, g_nHtmlEnd=%d content= %s", nThreadIndex, nIndex, ++g_nHtmlEnd, content);
						pSession->transfer_flag = HTTP_TRANSFER_WITH_HTML_END;

					}
					else
					{
						LOGDEBUG("Session[%d][%d]with transfer none, g_nNone=%d content= %s", nThreadIndex, nIndex, ++g_nNone, content);
						pSession->transfer_flag = HTTP_TRANSFER_NONE;
					}
				}
			}
		}
		else if ((pSession->content_type >= HTTP_CONTENT_FILE_PDF)
				 && (pSession->content_type <= HTTP_CONTENT_FILE_OTHER))
		{
			pSession->content_encoding_gzip = 0;
			pSession->transfer_flag = HTTP_TRANSFER_FILE;
			LOGDEBUG("Session[%d][%d] content is file.", nThreadIndex, nIndex);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;

			pSession->finish_type = HTTP_SESSION_FINISH_SUCCESS;
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
			{
				++g_nCountWholeContentFull[nThreadIndex];
				LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
			}
			
			return HTTP_APPEND_FINISH_CURRENT;
		}

		if (HTTP_TRANSFER_NONE == pSession->transfer_flag)
		{
			LOGDEBUG("Session[%d][%d] content is others and not HTTP_TRANSFER_WITH_HTML_END.", nThreadIndex, nIndex);

			if (HTTP_CONTENT_NONE == pSession->content_type)
			{
				LOGWARN("Session[%d][%d] is content-type unknown; content is \n%s\n%s", 
						 nThreadIndex, nIndex, pSession->request_head, content);
			}
			else
			{
				LOGINFO("Session[%d][%d] is HTTP_TRANSFER_NONE but not HTTP_CONTENT_NONE; content is \n%s\n%s", 
						 nThreadIndex, nIndex, pSession->request_head, content);
			}
			
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;

			pSession->finish_type = HTTP_SESSION_FINISH_UNKNOWN_DATA;
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
			{
				++g_nCountWholeContentFull[nThreadIndex];
				LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
			}
			
			return HTTP_APPEND_FINISH_CURRENT;
		}
	}
	else
	{
		content = pSession->part_content;
		contentlen = pSession->part_content_len;
		strlwr(content);
		LOGDEBUG("Session[%d][%d], part_content=%s", nThreadIndex, nIndex, content);
	}
	
	if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == pSession->transfer_flag)
//		|| HTTP_TRANSFER_NONE == pSession->transfer_flag)
	{
		if (pSession->res2 >= pSession->res1) 
		{
			LOGDEBUG("Session[%d][%d] end_reponse content-length/recv = %u/%u, content= %s", nThreadIndex, nIndex, pSession->res1, pSession->res2, content);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;

			pSession->finish_type = HTTP_SESSION_FINISH_SUCCESS;
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
			{
				++g_nCountWholeContentFull[nThreadIndex];
				LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
			}
			
			return HTTP_APPEND_FINISH_CURRENT;
		}
	}
	else if (HTTP_TRANSFER_CHUNKED == pSession->transfer_flag)
	{
		char *pszChunkedEnd = memmem(content, contentlen, "\r\n0\r\n\r\n", 7);
		if (pszChunkedEnd == NULL)
			pszChunkedEnd = memmem(content, contentlen, "\r\n00000000\r\n\r\n", 14);

		if (pszChunkedEnd == NULL)
			pszChunkedEnd = memmem(content, contentlen, "\r\n0000\r\n\r\n", 10);
		
		if (pszChunkedEnd != NULL)
		{
			LOGDEBUG("Session[%d][%d]end_reponse with chunked data", nThreadIndex, nIndex);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;

			pSession->finish_type = HTTP_SESSION_FINISH_SUCCESS;
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
			{
				++g_nCountWholeContentFull[nThreadIndex];
				LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
			}
			
			return HTTP_APPEND_FINISH_CURRENT;
		}
	}
	else if (HTTP_TRANSFER_WITH_HTML_END == pSession->transfer_flag)
	{
		char *pszHtmlEnd = memmem(content, contentlen, "</html>", 7);
		if (pszHtmlEnd != NULL)
		{
			LOGDEBUG("Session[%d][%d] find </html>, content=%s", nThreadIndex, nIndex, content);
			int nLeft = contentlen - (pszHtmlEnd-content+7);
			if (((pszHtmlEnd-content+7) == contentlen)
				|| ((nLeft >= 6) && (memmem(pszHtmlEnd+7, 6, "\r\n\r\n", 4) != NULL || memmem(pszHtmlEnd+7, 6, "\n\n", 2) != NULL))
				|| (memmem(pszHtmlEnd+7, nLeft, "<", 1) == NULL
					&& memmem(pszHtmlEnd+7, nLeft, ">", 1) == NULL))
			{
				LOGDEBUG("Session[%d][%d]end_reponse with </html>, left length=%d", nThreadIndex, nIndex, nLeft);
				if (!bIsCurPack)
					return HTTP_APPEND_FINISH_LATER;
				
				pSession->finish_type = HTTP_SESSION_FINISH_SUCCESS;
				pSession->flag = HTTP_SESSION_FINISH;
				if (push_queue(_whole_content, pSession) < 0)
				{
					++g_nCountWholeContentFull[nThreadIndex];
					LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
				}
				
				return HTTP_APPEND_FINISH_CURRENT;
			}
		}
	}

	return HTTP_APPEND_ADD_PACKET;
}

int AppendClientToServer(int nThreadIndex, int nIndex, const char* pPacket)
{
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
	const char *content = (void*)tcphead + tcphead->doff*4;
	struct tcp_session *pSession = &_http_session_array[nThreadIndex][nIndex];

	if (pSession->flag != HTTP_SESSION_REQUESTING) 
		LOGWARN("Resend request or post request. Current flag = %d", pSession->flag);

	if ((pSession->seq+pSession->res0) != tcphead->seq || pSession->ack != tcphead->ack_seq) 
	{
		LOGWARN("Session[%d][%d] C->S packet wrong order. pre.seq=%u pre.ack=%u "
				"pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
				 nThreadIndex, nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

		if ((1 == contentlen) && (*content == '\0'))
		{
			LOGWARN("Session[%d][%d] AppendClientToServer drop packet, wrong order, contentlen=1, content=empty!", nThreadIndex, nIndex);
		}
		else
		{
			pSession->request_head_len_valid_flag = 1;
			pSession->seq += contentlen;
			LOGWARN("Session[%d][%d] AppendClientToServer drop packet, content!=empty!", nThreadIndex, nIndex);
		}
		return HTTP_APPEND_DROP_PACKET;
	}

	LOGINFO("Session[%d][%d] AppendClientToServer content=%s", nThreadIndex, nIndex, content);

	if ((1 == contentlen) && (*content == '\0'))
	{
		LOGWARN("Session[%d][%d] AppendClientToServer drop packet, contentlen=1, content=empty!", nThreadIndex, nIndex);
		return HTTP_APPEND_DROP_PACKET;
	}

	pSession->ack = tcphead->ack_seq;
	pSession->seq = tcphead->seq;
	pSession->res0 = contentlen;
	pSession->update = *tv;

	*(const char**)pPacket = NULL;
	*(const char**)pSession->lastdata = pPacket;
	pSession->lastdata = (void*)pPacket;

	int last_len = pSession->request_head_len;
	pSession->request_head = realloc(pSession->request_head, last_len + contentlen);
	memcpy(pSession->request_head+last_len-1, content, contentlen);
	pSession->request_head[last_len+contentlen-1] = '\0';
	pSession->request_head_len = last_len + contentlen;

	if (content[contentlen-4]=='\r' && content[contentlen-3]=='\n'
		&& content[contentlen-2]=='\r' && content[contentlen-1]=='\n') 
	{
		pSession->flag = HTTP_SESSION_REQUEST;
	}

	return HTTP_APPEND_ADD_PACKET;
}

int AppendLaterPacket(int nThreadIndex, int nIndex, int nIsForceRestore)
{
	ASSERT(nIndex >= 0);

	int nIsFinish = 0;
	struct tcp_session *pSession = &_http_session_array[nThreadIndex][nIndex];
	void *pLaterPack = pSession->pack_later;
	
	if (pLaterPack != NULL)
	{
		LOGDEBUG("###########Start Process later packet list! index=%d", nIndex);
		
		void *pCurTmp = NULL, *pPreTmp = NULL;
		while (pLaterPack != NULL) 
		{
			pCurTmp = pLaterPack;
			pLaterPack = *(void**)pLaterPack;
			int nRs = AppendServerToClient(nThreadIndex, nIndex, pCurTmp, 0, nIsForceRestore);
			LOGDEBUG("Process later packet, ******** nRs=%d ******** index=%d", nRs, nIndex);
			
			if (nRs == HTTP_APPEND_DROP_PACKET 
				|| nRs == HTTP_APPEND_ADD_PACKET 
				|| nRs == HTTP_APPEND_FINISH_LATER)
			{
				if (pCurTmp == pSession->pack_later)
				{
					pSession->pack_later = pLaterPack;
				}
				else
				{
					*(void**)pPreTmp = pLaterPack;
					if (pLaterPack == NULL)
						pSession->last_pack_later = pPreTmp;
				}
				
				switch (nRs)
				{
				case HTTP_APPEND_DROP_PACKET:
					free(pCurTmp);
					break;
				case HTTP_APPEND_FINISH_LATER:
					pSession->finish_type = HTTP_SESSION_FINISH_SUCCESS;
					pSession->flag = HTTP_SESSION_FINISH;
					if (push_queue(_whole_content, pSession) < 0)
					{
						++g_nCountWholeContentFull[nThreadIndex];
						LOGWARN("Thread[%d]'s whole content queue is full. count = %d", nThreadIndex, g_nCountWholeContentFull[nThreadIndex]);
					}

					nIsFinish = 1;
					break;
				default:
					break;
				}

				pSession->later_pack_size--;
					
				if (nRs == HTTP_APPEND_FINISH_LATER)
					break;
				else
					continue;
			}
			pPreTmp = pCurTmp;
		}
		LOGDEBUG("###########End Process later packet list! index=%d", nIndex);
	}

	return nIsFinish;
}

int AppendReponse(int nThreadIndex, const char* packet)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead = TCPHDR(iphead);
	struct tcp_session *pREQ = &_http_session_array[nThreadIndex][0];

	int index = 0;

	pthread_mutex_lock(&_session_proc_lock[nThreadIndex]);
	for (; index < g_nMaxHttpSessionCount; ++index) 
	{
		pREQ = &_http_session_array[nThreadIndex][index];
		if (pREQ->flag == HTTP_SESSION_IDL || pREQ->flag == HTTP_SESSION_FINISH) 
			continue;

		// process timeout
		int nRs = 0;
		if (pREQ->client.ip.s_addr == iphead->daddr && pREQ->client.port == tcphead->dest 
			&& pREQ->server.ip.s_addr == iphead->saddr && pREQ->server.port == tcphead->source) // server -> client
		{
			nRs = AppendServerToClient(nThreadIndex, index, packet, 1, 0);
			if (nRs == HTTP_APPEND_ADD_PACKET || nRs == HTTP_APPEND_ADD_PACKET_LATER)
			{
				AppendLaterPacket(nThreadIndex, index, 0);
			}
			else if (nRs == HTTP_APPEND_DROP_PACKET)
			{
				pthread_mutex_unlock(&_session_proc_lock[nThreadIndex]);
				return nRs;	
			}
			
			break;
		}
		else if (pREQ->client.ip.s_addr == iphead->saddr && pREQ->client.port == tcphead->source // client -> server
				 && pREQ->server.ip.s_addr == iphead->daddr && pREQ->server.port == tcphead->dest) 
		{ 
			nRs = AppendClientToServer(nThreadIndex, index, packet);
			if (nRs == HTTP_APPEND_DROP_PACKET)
			{
				pthread_mutex_unlock(&_session_proc_lock[nThreadIndex]);
				return nRs;	
			}
			
			break;
		} 
		else 
		{
			char sip[20], dip[20], stip[20], dtip[20];
			LOGTRACE("Session[%d][%d] %s:%d => %s:%d. append %s:%d => %s:%d", nThreadIndex, index,
					inet_ntop(AF_INET, &pREQ->client.ip, sip, 20), ntohs(pREQ->client.port),
					inet_ntop(AF_INET, &pREQ->server.ip, dip, 20), ntohs(pREQ->server.port),
					inet_ntop(AF_INET, &iphead->saddr, stip, 20),  ntohs(tcphead->source),
					inet_ntop(AF_INET, &iphead->daddr, dtip, 20),  ntohs(tcphead->dest));
		}
	}
	pthread_mutex_unlock(&_session_proc_lock[nThreadIndex]);
	
	if (index == g_nMaxHttpSessionCount) 
	{
		char stip[20], dtip[20];
		LOGTRACE("Session[%d][%d]  append %s:%d => %s:%d", nThreadIndex, index,
				inet_ntop(AF_INET, &iphead->saddr, stip, 20),  ntohs(tcphead->source),
				inet_ntop(AF_INET, &iphead->daddr, dtip, 20),  ntohs(tcphead->dest));
		
		index = HTTP_APPEND_DROP_PACKET;
	}

	return index;
}

void *HTTP_Thread(void* param)
{
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	
	int nThreadIndex = *(int*)param;
	while (_runing)
	{
		int nPackSize = len_queue(_packets_array[nThreadIndex]);
		if (nPackSize > g_nMaxUsedPackSize[nThreadIndex])
		{
			g_nMaxUsedPackSize[nThreadIndex] = nPackSize;
		}
		
		const char* packet = pop_queue(_packets_array[nThreadIndex]);
		if (packet == NULL) {
			usleep(50000);
			continue;
		}

		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		char *content = (void*)tcphead + tcphead->doff*4;

		if (tcphead->syn || contentlen <=0) { 
			free((void*)packet); 
			continue; 
		} 

		struct timeval tvBeforProc;
		gettimeofday(&tvBeforProc, NULL);
		
		unsigned *cmd = (unsigned*)content;
		if (*cmd == _get_image || *cmd == _post_image) 
		{
			if (_block_func_on && (GetBlockItemCnt() > 0))
			{
				int nIndex = FilterBlockList(packet);
				if (nIndex != -1)
				{
					if (BlockHttpRequest(packet, nIndex))
					{
						struct in_addr sip; 
						struct in_addr dip; 
						sip.s_addr = iphead->saddr;
						dip.s_addr = iphead->daddr;
						char ssip[16], sdip[16];
						LOGINFO("Success to block client request(%s => %s)!", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
					}
				}
			}
			
			tcphead->seq = ntohl(tcphead->seq);
			tcphead->ack_seq = ntohl(tcphead->ack_seq);

			int nRes = 0;
			struct timeval *tv = (struct timeval*)packet;
			gettimeofday(tv, NULL);
			if ((nRes = NewHttpSession(nThreadIndex, packet)) < 0) 
			{
				if (nRes == -3) 
				{
					++g_nDropCountForImage;
					LOGINFO("Content is not html data. drop count = %d", g_nDropCountForImage);
				}
				else if (nRes == -1) 
				{
					LOGWARN0("Request content is error! Do not insert into session.");
				} 
				else if (nRes == -2) 
				{
					char *enter = strchr(content, '\r');
					if (enter != NULL) 
					{
						++g_nDropCountForSessionFull[nThreadIndex];
						*enter = '\0';
						LOGWARN("_http_session_array[%d] is full. drop count = %d, drop content = %s", nThreadIndex, g_nDropCountForSessionFull[nThreadIndex], content);
						*enter = '\r';

						LOGWARN("Current Send status: g_nFlagGetData = %d, g_nFlagSendData = %d", g_nFlagGetData, g_nFlagSendData);
					}
				}
				free((void*)packet);
			}

			struct timeval tvAfterProc;
			gettimeofday(&tvAfterProc, NULL);
			g_nSessionCostTime[nThreadIndex] += ((uint64_t)tvAfterProc.tv_sec*1000000 + tvAfterProc.tv_usec) - ((uint64_t)tvBeforProc.tv_sec*1000000 + tvBeforProc.tv_usec);
		
			continue;
		}

		tcphead->seq = ntohl(tcphead->seq);
		tcphead->ack_seq = ntohl(tcphead->ack_seq);
		
		struct timeval *tv = (struct timeval*)packet;
		gettimeofday(tv, NULL);
		int nIndex = AppendReponse(nThreadIndex, packet);
		if (nIndex == HTTP_APPEND_DROP_PACKET) 
		{
			LOGDEBUG0("cannt find request with reponse.");
			free((void*)packet);
		}

		struct timeval tvAfterProc;
		gettimeofday(&tvAfterProc, NULL);
		g_nSessionCostTime[nThreadIndex] += ((uint64_t)tvAfterProc.tv_sec*1000000 + tvAfterProc.tv_usec) - ((uint64_t)tvBeforProc.tv_sec*1000000 + tvBeforProc.tv_usec);
	}
	return NULL;
}

int HttpInit()
{
	ASSERT(_packets_array == NULL);
	ASSERT(_http_session_array == NULL);

	char szThreadCount[10] = {0};
	GetValue(CONFIG_PATH, "thread_count", szThreadCount, 4);
	g_nThreadCount = atoi(szThreadCount);
	if (g_nThreadCount < 1 || g_nThreadCount > MAX_SESSION_THREAD_COUNT)
		g_nThreadCount = 1;

	printf("thread_count = %d\n", g_nThreadCount);
	
	LoadHttpConf(CONFIG_PATH);
	
	char szSendErrStateDataFlag[10] = {0};
	if (GetValue(CONFIG_PATH, "SendErrStateDataFlag", szSendErrStateDataFlag, 2) != NULL)
		g_nSendErrStateDataFlag = atoi(szSendErrStateDataFlag);

	char szMaxSessionCount[10] = {0};
	char szMaxPacketCount[10] = {0};
	char szHttpTimeout[10] = {0};
	GetValue(CONFIG_PATH, "max_session_count", szMaxSessionCount, 7);
	GetValue(CONFIG_PATH, "max_packet_count", szMaxPacketCount, 7);
	GetValue(CONFIG_PATH, "http_timeout", szHttpTimeout, 4);
	
	char szCapRes[10] = {0};
	GetValue(CONFIG_PATH, "cap_res", szCapRes, 6);
	if (strcmp(szCapRes, "true") == 0)
		g_bIsCapRes = 1;

	char szSendTimeoutData[10] = {0};
	GetValue(CONFIG_PATH, "send_timeout_data", szSendTimeoutData, 6);
	if (strcmp(szSendTimeoutData, "true") == 0)
		g_bIsSendTimeoutData = 1;

	char szSendChannelReusedData[10] = {0};
	GetValue(CONFIG_PATH, "send_channel_reused_data", szSendChannelReusedData, 6);
	if (strcmp(szSendChannelReusedData, "true") == 0)
		g_bIsSendChannelReusedData = 1;

	char szSendUnknownData[10] = {0};
	GetValue(CONFIG_PATH, "send_unknown_data", szSendUnknownData, 6);
	if (strcmp(szSendUnknownData, "true") == 0)
		g_bIsSendUnknownData = 1;

	char szSendDisorderRebuildFailedData[10] = {0};
	GetValue(CONFIG_PATH, "send_disorder_rebuild_failed_data", szSendDisorderRebuildFailedData, 6);
	if (strcmp(szSendDisorderRebuildFailedData, "true") == 0)
		g_bIsSendDisorderRebuildFailedData = 1;

	char szLogResData[10] = {0};
	GetValue(CONFIG_PATH, "log_image_data", szLogResData, 6);
	if (strcmp(szLogResData, "true") == 0)
		g_bIsLogResData = 1;
	
	char szLogTimeoutData[10] = {0};
	GetValue(CONFIG_PATH, "log_timeout_data", szLogTimeoutData, 6);
	if (strcmp(szLogTimeoutData, "true") == 0)
		g_bIsLogTimeoutData = 1;

	char szLogChannelReusedData[10] = {0};
	GetValue(CONFIG_PATH, "log_channel_reused_data", szLogChannelReusedData, 6);
	if (strcmp(szLogChannelReusedData, "true") == 0)
		g_bIsLogChannelReusedData = 1;

	char szLogUnknownData[10] = {0};
	GetValue(CONFIG_PATH, "log_unknown_data", szLogUnknownData, 6);
	if (strcmp(szLogUnknownData, "true") == 0)
		g_bIsLogUnknownData = 1;

	char szLogDisorderRebuildFailedData[10] = {0};
	GetValue(CONFIG_PATH, "log_disorder_rebuild_failed_data", szLogDisorderRebuildFailedData, 6);
	if (strcmp(szLogDisorderRebuildFailedData, "true") == 0)
		g_bIsLogDisorderRebuildFailedData = 1;
	
	GetValue(CONFIG_PATH, "special_client_ip", g_szSpecialClientIp, 100);
	
	g_nMaxHttpSessionCount = atoi(szMaxSessionCount);
	if (g_nMaxHttpSessionCount < 50 || g_nMaxHttpSessionCount > 100000)
		g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
	
	g_nMaxHttpPacketCount = atoi(szMaxPacketCount);
	if (g_nMaxHttpPacketCount < 100 || g_nMaxHttpPacketCount > 200000)
		g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
	
	g_nHttpTimeout = atoi(szHttpTimeout);
	if (g_nHttpTimeout < 10 || g_nHttpTimeout > 600)
		g_nHttpTimeout = HTTP_TIMEOUT;

	printf("max_http_session_count = %d\n", g_nMaxHttpSessionCount);
	printf("max_http_packet_count = %d\n", g_nMaxHttpPacketCount);
	printf("max_http_timeout = %d\n", g_nHttpTimeout);

	_packets_array = (struct queue_t **)calloc(sizeof(struct queue_t*), g_nThreadCount);
	for (int i = 0; i < g_nThreadCount; i++)
	{
		_packets_array[i] = init_queue(g_nMaxHttpPacketCount);
	}
	ASSERT(_packets_array != NULL);

	_http_session_array = (struct tcp_session**)calloc(sizeof(struct tcp_session*), g_nThreadCount);
	for (int i = 0; i < g_nThreadCount; i++)
	{
		_http_session_array[i] = (struct tcp_session*)calloc(sizeof(struct tcp_session), g_nMaxHttpSessionCount);
	}
	ASSERT(_http_session_array != NULL);

	_idl_session_count = (int *)calloc(sizeof(int), g_nThreadCount);
	for (int i = 0; i < g_nThreadCount; i++)
	{
		_idl_session_count[i] = g_nMaxHttpSessionCount;
		for (size_t index = 0; index < g_nMaxHttpSessionCount; ++index)
		{
			_http_session_array[i][index].thread_index = i;
			_http_session_array[i][index].index = index;
		}
	}
	ASSERT(_idl_session_count != NULL);
		
	_whole_content = init_queue(g_nMaxHttpSessionCount*g_nThreadCount);
	ASSERT(_whole_content != NULL);

	//_use_session = init_queue(g_nMaxHttpSessionCount);
	//ASSERT(_use_session != NULL);
	
	for (int i = 0; i < g_nThreadCount; i++)
	{
		int err = pthread_create(&_http_thread[i], NULL, &HTTP_Thread, &_thread_param[i]);
		ASSERT(err==0);
	}
	
	return _packets_array==NULL? -1:0;
}

void StopHttpThread()
{
	_runing = 0;
	void* result;
	for (int i = 0; i < g_nThreadCount; i++)
	{
		pthread_join(_http_thread[i], &result);
	}

	for (int i = 0; i < g_nThreadCount; i++)
	{
		for (int j = 0; j < g_nMaxHttpSessionCount; j++) 
		{
			if (_http_session_array[i][j].flag != HTTP_SESSION_IDL) 
			{
				struct tcp_session* pSession = &_http_session_array[i][j];
				CleanHttpSession(pSession);	
			}
		}
		free(_http_session_array[i]);
	}
	free(_http_session_array);
	
	void* pPacket = NULL;
	for (int i = 0; i < g_nThreadCount; i++)
	{
		while ((pPacket = pop_queue(_packets_array[i])) != NULL)
		{
			free(pPacket);
		}

		destory_queue(_packets_array[i]);
	}
	free(_packets_array);
	
	destory_queue(_whole_content);

	free(_idl_session_count);
}

int inHosts(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	if (NULL == _monitor_hosts)
		return -1;
	
	const char *content = (const char *)tcphead + tcphead->doff*4;
	unsigned *cmd = (unsigned*)content;
	for (int i = 0; i < g_nThreadCount; i++)
	{
		for (int npos = 0; npos < g_nMonitorHostsPieceCount; npos++)
		{
			struct hosts_t *tmp = &_monitor_hosts_array[i][npos];
			if (0 == tmp->ip.s_addr)
				continue;
			
			if (tmp->ip.s_addr==INADDR_BROADCAST 
				&& (tmp->port==tcphead->source || tmp->port==tcphead->dest || tmp->port==0u))
				return i;

			if ( (tmp->ip.s_addr==iphead->saddr && (tmp->port==tcphead->source || tmp->port==0u) && (*cmd != _get_image && *cmd != _post_image))
				 || (tmp->ip.s_addr==iphead->daddr && (tmp->port==tcphead->dest || tmp->port==0u)))
			{
				return i;
			}
		}
	}
	return -1;
}

int inExcludeHosts(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	if (NULL == _exclude_hosts)
		return -1;
	
	for (int npos = 0; npos < _exclude_hosts_count; npos++)
	{
		struct hosts_t *tmp = &_exclude_hosts[npos];
		if (0 == tmp->ip.s_addr)
			continue;
		
		if (tmp->ip.s_addr==INADDR_BROADCAST 
			&& (tmp->port==tcphead->source || tmp->port==tcphead->dest || tmp->port==0u))
			return npos;

		if ( (tmp->ip.s_addr==iphead->saddr && (tmp->port==tcphead->source || tmp->port==0u))
			 || (tmp->ip.s_addr==iphead->daddr && (tmp->port==tcphead->dest || tmp->port==0u)))
		{
			return npos;
		}
	}
	return -1;
}

int PushHttpPack(int nThreadIndex, const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{	
	int err = push_queue(_packets_array[nThreadIndex], (const void*)buffer);
	if (err < 0) 
	{
		++g_nDropCountForPacketFull[nThreadIndex];
		LOGWARN("Thread[%d]'s http_queue is full. drop the packets, drop count = %d", nThreadIndex, g_nDropCountForPacketFull[nThreadIndex]);
	}
	return err;
}

/// buffer is http return 0. other return -1;
int FilterPacketForHttp(int nFdIndex, const char* buffer, int nBufferLen, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	int nRs = 0;

	pthread_mutex_lock(&_host_ip_lock[nFdIndex]);

	int nThreadIndex = 0;
	nThreadIndex = inHosts(buffer, iphead, tcphead);
	if ((nThreadIndex == -1) 
		|| (inExcludeHosts(buffer, iphead, tcphead) != -1))
	{
		struct in_addr sip; 
		struct in_addr dip; 

		sip.s_addr = iphead->saddr;
		dip.s_addr = iphead->daddr;
		char ssip[16], sdip[16];
		LOGTRACE("%s => %s is skipped.", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
		g_nSkippedPackCount++;

		nRs = -1; 
	}
	else
	{
		++g_nValidCapCount[nFdIndex];
		g_nValidCapSize[nFdIndex] += nBufferLen;
			
		if (PushHttpPack(nThreadIndex, buffer, iphead, tcphead) != -1)
			g_nPushedPackCount[nThreadIndex]++;
		else
			nRs = -1;

		int nPackSize = len_queue(_packets_array[nThreadIndex]);
		if (nPackSize > g_nMaxUsedPackSize[nThreadIndex])
		{
			g_nMaxUsedPackSize[nThreadIndex] = nPackSize;
		}
	}

	pthread_mutex_unlock(&_host_ip_lock[nFdIndex]);
		
	return nRs;
}

int IsConfigPort(struct hosts_t *pServer)
{
	if (NULL == _monitor_hosts)
		return -1;

	int nRs = 0;
	for (int npos = 0; npos < _monitor_hosts_count; npos++)
	{
		struct hosts_t *tmp = &_monitor_hosts[npos];
		if (0 == tmp->ip.s_addr)
			continue;
		
		if (tmp->ip.s_addr == pServer->ip.s_addr)
		{
			if (tmp->port == pServer->port)
				nRs = 1;
		}
	}

	return nRs;
}


// Load rule from config.
int LoadHttpConf(const char* filename)
{
	// dont support reload in runing...
	ASSERT((NULL == _monitor_hosts) && (NULL == _exclude_hosts));
	// capture these hosts
	char *left, *right, *ipport;
	int n = 0, nDataLen = 0;

	char* pFileData = (char*)calloc(1, VALUE_LENGTH_MAX+1);
	ASSERT(pFileData != NULL);
	
	char* httphosts = pFileData;

	nDataLen = GetFileData(HTTP_HOST_PATH_FILE, httphosts, VALUE_LENGTH_MAX);
	if (nDataLen > 0)
	{
		_monitor_hosts_count = count_char(httphosts, '\n') + 1;
		_monitor_hosts = (struct hosts_t *)calloc(sizeof(*_monitor_hosts), _monitor_hosts_count);

		for(left=httphosts; ;left=NULL) 
		{
			ipport = strtok_r(left, "\n", &right);
			if (ipport==NULL) 
				break;
			LOGFIX("monitor host %s", ipport);
			if (str_ipp(ipport, &_monitor_hosts[n])) 
				++n;
		}

		_monitor_hosts_array = (struct hosts_t **)calloc(sizeof(struct hosts_t*), g_nThreadCount);
		g_nMonitorHostsPieceCount = _monitor_hosts_count/g_nThreadCount + _monitor_hosts_count%g_nThreadCount;
		printf("g_nMonitorHostsPieceCount = %d\n", g_nMonitorHostsPieceCount);
		for (int i = 0; i < g_nThreadCount; i++)
		{
			_monitor_hosts_array[i] = (struct hosts_t *)calloc(sizeof(struct hosts_t), g_nMonitorHostsPieceCount);
		}
		
		int nArrayIndex = 0, nUnitIndex = 0;
		for (int i = 0; i < _monitor_hosts_count; i++) 
		{
			_monitor_hosts_array[nArrayIndex++][nUnitIndex] = _monitor_hosts[i];
			if (nArrayIndex%g_nThreadCount == 0)
			{
				nArrayIndex = 0;
				nUnitIndex++;
			}
		}
	}

	n = 0;
	char* excludehosts = pFileData;
	memset(excludehosts, 0, VALUE_LENGTH_MAX+1);
	nDataLen = GetFileData(EXCLUDE_HOST_PATH_FILE, excludehosts, VALUE_LENGTH_MAX);
	if (nDataLen > 0)
	{
		_exclude_hosts_count = count_char(excludehosts, '\n') + 1;
		_exclude_hosts = (struct hosts_t *)calloc(sizeof(*_exclude_hosts), _exclude_hosts_count);

		for (left=excludehosts; ;left=NULL) 
		{
			ipport = strtok_r(left, "\n", &right);
			if (ipport==NULL) 
				break;
			LOGFIX("exclude host %s", ipport);
			if (str_ipp(ipport, &_exclude_hosts[n])) 
				++n;
		}
	}

	free(pFileData);
		
	return 0;
}

int TransGzipData(const char *pGzipData, int nDataLen, char **pTransData)
{
	if (pGzipData == NULL)
		return -1;
	
	*pTransData = NULL;
	int plain_len = *(int*)(pGzipData+nDataLen-4);
	
	LOGDEBUG("TransGzipData, content length = %d, plain length = %d", nDataLen, plain_len);
	
	char *pPlain = NULL;

	if (plain_len > 0 && plain_len < 10000000)
	{
		if (nDataLen > plain_len)
		{
			LOGWARN("TransGzipData, content length(%d) > plain length(%d), trans stop!", nDataLen, plain_len);
			return -1;
		}
		
		pPlain = calloc(1, plain_len+1024);
	}
	else if (0 == plain_len)
	{
		if (nDataLen > 0 && nDataLen < 800000)
		{
			pPlain = calloc(1, 5120);
			plain_len = -1;
		}
		else
		{
			LOGWARN("TransGzipData, plain length = 0 and content length(%d) >= 800KB, trans stop!", nDataLen);
			return -1;
		}
	}
	else
	{
		LOGWARN("TransGzipData, plain length(%d) < 0 or plain length >= 10M, trans stop!", plain_len);
		return -1;
	}
	
	if (pPlain == NULL) {
		LOGWARN0("Can not calloc plain!");
		return -1;
	}

	char gzfile[] = "/dev/shm/gzipXXXXXX";
	int fd = mkstemp(gzfile);
	if (fd == -1) {
		LOGERROR("mkstemp() failed. %s", strerror(errno));
		free(pPlain);
		pPlain = NULL;
		return -1;
	}
	int nWrited = 0;
	do {
		int n = write(fd, pGzipData+nWrited, nDataLen-nWrited);
		if (n == -1) {
			LOGERROR("write tmp.gz failed. %s", strerror(errno));
			free(pPlain);
			pPlain = NULL;
			close(fd);
			unlink(gzfile);
			return -1;
		}
		nWrited += n;
	}while (nWrited < nDataLen);
	close(fd);

	gzFile p = gzopen(gzfile, "r");
	int nReaded = 0;
	int n = 0;
	int nRepeatRead = 0;
	if (plain_len > 0)
	{
		while (!gzeof(p) && (nReaded < plain_len)) 
		{
			n = gzread(p, pPlain+nReaded, plain_len+1024-nReaded);
			if ((n == -1) || (n == 0))
			{
				LOGWARN("gzread() return -1. %s", strerror(errno));
				break;
			}
			nReaded += n;
			if (nReaded > plain_len) {
				LOGWARN("gzread() return more than plain_len, read data length = %d, plain length = %d", nReaded, plain_len);
				break;
			}
		}
	}
	else
	{
		while (!gzeof(p)) 
		{
			n = gzread(p, pPlain+nReaded, 5120);
			LOGDEBUG("gzread() return %d", n);
			if ((n == -1) || (n == 0))
			{
				LOGWARN("gzread() return -1. %s", strerror(errno));
				break;
			}
			nReaded += n;
			pPlain = realloc(pPlain, nReaded + 5120);

			if (++nRepeatRead >= 150)
			{
				LOGWARN0("Time of gzread >= 150! Stop to gzread!");
				break;
			}
		}
	}
	
	gzclose(p);
	unlink(gzfile);
	LOGDEBUG("TransGzipData finish. Read data length = %d, plain length = %d", nReaded, plain_len);

	if (nReaded > 0)
		*pTransData = pPlain;
	else
	{
		if (pPlain != NULL)
		{
			free(pPlain);
			pPlain = NULL;
		}
	}
	
	return nReaded;
}

int GetHttpData(char **data)
{
	*data = NULL;
	struct tcp_session *pSession = (struct tcp_session*)pop_queue(_whole_content);
	if (pSession == NULL) 
		return 0;
	
	size_t http_len = 0;
	if (pSession->flag != HTTP_SESSION_FINISH)
	{
		LOGWARN("pSession[%d][%d]->flag != HTTP_SESSION_FINISH. pSession->flag = %d\n", pSession->thread_index, pSession->index, pSession->flag);
		return 0;
	}
	if (NULL == pSession->data)
	{
		LOGWARN("pSession[%d][%d]->data == NULL. pSession->flag = %d\n", pSession->thread_index, pSession->index, pSession->flag);
		CleanHttpSession(pSession);
		return 0;
	}
	//ASSERT(pSession->flag == HTTP_SESSION_FINISH);
	//assert(pSession->data != NULL);

	LOGDEBUG("Session[%d][%d] ready to get data.", pSession->thread_index, pSession->index);
	
	// get all http_content len
	unsigned transfer_flag = pSession->transfer_flag;
	void* packet = pSession->data;
	do 
	{
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		http_len += contentlen;
		packet = *(void**)packet;
	} while (packet!=NULL);

	g_nHttpLen += http_len;
	LOGINFO("Total http data len = %llu Bytes, Session[%d][%d] http data len = %u Bytes!", g_nHttpLen, pSession->thread_index, pSession->index, http_len);

	int nPortOffsite = 0;
	int bIsConfigPort = IsConfigPort(&pSession->server);
	if (bIsConfigPort)
		nPortOffsite = 6;
	
	unsigned data_len = http_len+35+10+26+26+nPortOffsite+5+1;
	char* http_content = (char*)calloc(1, data_len);
	if (http_content == NULL) 
	{
		LOGERROR0("mallocing memory failed. will be retry");
		return 0;
	}
	// make data
	size_t pos = 0;
	char sip[20] = {0};
	char sport[20] = {0};
	struct tm _tm = {0};
	localtime_r(&pSession->create.tv_sec, &_tm);
	sprintf(http_content, "VISIT_TIME=%04d-%02d-%02d %02d:%02d:%02d:%03d",
			_tm.tm_year+1900, _tm.tm_mon+1, _tm.tm_mday,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (int)(pSession->create.tv_usec/1000));

	sprintf(http_content+35+10, "IP_CLIENT=%15s", inet_ntop(AF_INET, &pSession->client.ip, sip, 20));

	if (!nPortOffsite)
	{
		sprintf(http_content+35+10+26, "IP_SERVER=%15s", inet_ntop(AF_INET, &pSession->server.ip, sip, 20));
	}
	else
	{
		sprintf(sport, "%u", ntohs(pSession->server.port));
		sprintf(http_content+35+10+26, "IP_SERVER=%15s:%-5s", inet_ntop(AF_INET, &pSession->server.ip, sip, 20), sport);
	}
	
	sprintf(http_content+35+10+26+26+nPortOffsite, "DATA=");
	pos = 35+10+26+26+nPortOffsite+5;

	LOGINFO("Session[%d][%d] init http_content finished!", pSession->thread_index, pSession->index);
	
	packet = pSession->data;
	do 
	{
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead = TCPHDR(iphead);
		unsigned contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		if (contentlen > RECV_BUFFER_LEN) 
		{
			LOGERROR("Contentlen[%u] of packet is great than RECV_BUFFER_LEN[%u]", contentlen, RECV_BUFFER_LEN);
			pSession->data = packet;
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}
		const char *content = (void*)tcphead + tcphead->doff*4;
		memcpy(http_content+pos, content, contentlen);
		pos += contentlen;
		void* tmp = packet;
		packet = *(void**)packet;
		free(tmp);
	} while (packet!=NULL);
	pSession->data = NULL;

	LOGINFO("Session[%d][%d] generate http_content finished!", pSession->thread_index, pSession->index);
	
	http_content[pos] = '\0';
	ASSERT(pos+1 == data_len);

	LOGINFO("Session[%d][%d] start to process problem data!", pSession->thread_index, pSession->index);
	char* HTTP = http_content+35+10+26+26+nPortOffsite+5;
	char* HTTP_PRE = HTTP;
	if (HTTP_SESSION_FINISH_SUCCESS != pSession->finish_type)
	{
		int nHttpcode = 0;
		switch (pSession->finish_type)
		{
			case HTTP_SESSION_FINISH_TIMEOUT:
				nHttpcode = HTTP_SPECIAL_STATE_TIMEOUT;
				LOGWARN("Session[%d][%d] finish to get data with timeout!", pSession->thread_index, pSession->index);
				break;
			case HTTP_SESSION_FINISH_CHANNEL_REUSED:
				nHttpcode = HTTP_SPECIAL_STATE_CHANNEL_REUSED;
				LOGWARN("Session[%d][%d] finish to get data with channel reused!", pSession->thread_index, pSession->index);
				break;
			case HTTP_SESSION_FINISH_DISORDER_REBUILD_FAILED:
				nHttpcode = HTTP_SPECIAL_STATE_DISORDER_REBUILD_FAILED;
				LOGWARN("Session[%d][%d] finish to get data with rebuild failed!", pSession->thread_index, pSession->index);
				break;
			case HTTP_SESSION_FINISH_UNKNOWN_DATA:
				{
					nHttpcode = HTTP_SPECIAL_STATE_UNKNOWN_DATA;
					LOGWARN("Session[%d][%d] content is HTTP_CONTENT_NONE and is not HTTP_TRANSFER_WITH_HTML_END, g_nContentErrorCount = %d, g_nContentUnknownCount = %d", pSession->thread_index, pSession->index, g_nContentErrorCount, g_nContentUnknownCount);
					LOGINFO("Session[%d][%d] content is %s", pSession->thread_index, pSession->index, HTTP_PRE);
					LOGWARN("Session[%d][%d] finish to get data with unknown data!", pSession->thread_index, pSession->index);
					++g_nContentErrorCount;
					++g_nContentUnknownCount;
					if (g_bIsLogUnknownData)
						LogDropSessionData("Rebuild Failed:Content Unknown", pSession);
				}			
				break;
			default:
				{
					nHttpcode = HTTP_SPECIAL_STATE_UNKNOWN_DATA;
					LOGWARN("Session[%d][%d] content is HTTP_CONTENT_NONE and is not HTTP_TRANSFER_WITH_HTML_END, g_nContentErrorCount = %d, g_nContentUnknownCount = %d", pSession->thread_index, pSession->index, g_nContentErrorCount, g_nContentUnknownCount);
					LOGINFO("Session[%d][%d] content is %s", pSession->thread_index, pSession->index, HTTP_PRE);
					LOGWARN("Session[%d][%d] finish to get data with unknown data!", pSession->thread_index, pSession->index);
					++g_nContentErrorCount;
					++g_nContentUnknownCount;
					if (g_bIsLogUnknownData)
						LogDropSessionData("Rebuild Failed:Content Unknown", pSession);
				}			
				break;
		}
		sprintf(http_content+35, "STATE=%03d", nHttpcode);

		if ((pSession->finish_type != HTTP_SESSION_FINISH_UNKNOWN_DATA)
			 || g_bIsSendUnknownData)
		{
			LogDataItems(pSession, nHttpcode, data_len);
			CleanHttpSession(pSession);
			*data = http_content;
			LOGDEBUG("Session[%d][%d] get problem data successfully!", pSession->thread_index, pSession->index);

			return data_len;
		}

		CleanHttpSession(pSession);
		free(http_content);
		return 0;
	}
			
	LOGINFO("Session[%d][%d] start to get http head!", pSession->thread_index, pSession->index);
	
	// proce http
	if (*(unsigned*)HTTP == _get_image) 
	{
		HTTP = strstr(HTTP, "\r\n\r\n");	// skip query
		if (HTTP != NULL)
		{
			if (0 == pSession->request_head_len_valid_flag)
			{
				HTTP += 4;
			}
			else
			{
				HTTP = HTTP_PRE + pSession->request_head_len - 1;
			}
		}
	} 
	else if (*(unsigned*)HTTP == _post_image) 
	{
		char* query_len = strstr(HTTP, "Content-Length:");
		int query_length = 0;
		if (query_len != NULL)
			query_length = strtol(query_len+15, NULL, 10);

		HTTP = strstr(HTTP, "\r\n\r\n");	// skip query
		if (HTTP != NULL)
		{
			if (0 == pSession->request_head_len_valid_flag)
			{
				HTTP += 4 + query_length;
			}
			else
			{
				HTTP = HTTP_PRE + pSession->request_head_len - 1;
			}
		}
	} 
	else 
	{
		LOGERROR("No GET or POST. %c%c%c%c", HTTP[0],HTTP[1],HTTP[2],HTTP[3]);
	}

	LOGINFO("Session[%d][%d] start to process html content!", pSession->thread_index, pSession->index);
	
	int nHttpNoErr = 0;
	if (HTTP != NULL) 
	{
		if ((HTTP - http_content) >= data_len) 
		{
			if (HTTP_SESSION_FINISH_SUCCESS == pSession->finish_type)
			{
				++g_nContentErrorCount;
				++g_nDatalenErrorCount;
				LOGWARN("Session[%d][%d] Address more than data length. Current content= %s, g_nContentErrorCount = %d, g_nDatalenErrorCount = %d", pSession->thread_index, pSession->index, HTTP_PRE, g_nContentErrorCount, g_nDatalenErrorCount);

				if (g_bIsLogUnknownData)
					LogDropSessionData("Content Error:Data Length Error", pSession);
			}
		}
		else
		{
			nHttpNoErr = 1;
		}
	}
	else
	{
		if (HTTP_SESSION_FINISH_SUCCESS == pSession->finish_type)
		{
			++g_nContentErrorCount;
			++g_nHttpNullCount;
			LOGWARN("Fail to find http content! g_nContentErrorCount = %d, g_nHttpNullCount = %d", g_nContentErrorCount, g_nHttpNullCount);

			if (g_bIsLogUnknownData)
				LogDropSessionData("Content Error:Http Null", pSession);
		}
	}

	if (HTTP_SESSION_FINISH_SUCCESS == pSession->finish_type)
	{
		if (!nHttpNoErr)
		{
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}
	}

	LOGINFO("Session[%d][%d] start to process successful content!", pSession->thread_index, pSession->index);
	
	if ((pSession->content_type != HTTP_CONTENT_NONE)
		|| (HTTP_TRANSFER_WITH_HTML_END == transfer_flag))
	{
		// get http code
		char* http_code = strstr(HTTP, "HTTP/1.0 ");
		if (NULL == http_code)
			http_code = strstr(HTTP, "HTTP/1.1 ");
		
		if (NULL == http_code)
		{
			++g_nContentErrorCount;
			++g_nHttpcodeErrorCount;

			if (g_bIsLogUnknownData)
				LogDropSessionData("Content Error:HTTP/1.1 Null", pSession);
			
			LOGWARN("Session[%d][%d] has not HTTP/1.0 or HTTP/1.1, Current content= %s, g_nContentErrorCount = %d, g_nHttpcodeErrorCount = %d", pSession->thread_index, pSession->index, HTTP_PRE, g_nContentErrorCount, g_nHttpcodeErrorCount);
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}

		http_code += 9;
		int nHttpcode = strtol(http_code, NULL, 10);
		if ((0 == g_nSendErrStateDataFlag) && (nHttpcode >= 404))
		{
			LOGDEBUG("Session[%d][%d] httpcode=%d, Do not send current content.", pSession->thread_index, pSession->index, nHttpcode);
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}

		sprintf(http_content+35, "STATE=%03d", nHttpcode);
		LOGDEBUG("Session[%d][%d] get data httpcode=%d, transfer_flag=%d", pSession->thread_index, pSession->index, nHttpcode, transfer_flag);

		int nIsImmSendData = 0;
		int nContentLength = 0;
		if (HTTP_TRANSFER_CHUNKED == transfer_flag)
		{
			char* pOldContent = strstr(HTTP, "\r\n\r\n");
			if (pOldContent == NULL)
			{
				LOGWARN("Session[%d][%d] with flag(HTTP_TRANSFER_CHUNKED) has not content, Current content= %s", pSession->thread_index, pSession->index, HTTP_PRE);
				//goto NOZIP;
				nIsImmSendData = 1;
			}
			else
			{
				pOldContent += 4;

				char *pFind = NULL, *pEnd = NULL, *pTmpPart = NULL;
				char *pTmpContent = pOldContent;
				while (pTmpContent < http_content+data_len)
				{
					pEnd = NULL;
					int nChunkLen = strtol(pTmpContent, &pEnd, 16);
					if (nChunkLen > 0)
					{
						pFind = memmem(pEnd, 2, "\r\n", 2);
						if (pFind != NULL)
						{
							pTmpContent = pEnd;
							if (!pSession->force_restore_flag)
							{
								nContentLength += nChunkLen;
								pTmpContent += 2+nChunkLen+2;
							}
							else
							{
								pTmpPart = pTmpContent+2;
								pFind = memmem(pTmpPart, nChunkLen, "\r\n", 2);
								if (pFind != NULL)
								{
									nContentLength += pFind-pTmpPart;
									pTmpContent = pFind+2;	
								}
								else
								{
									nContentLength += nChunkLen;
									pTmpContent += 2+nChunkLen;
									pFind = memmem(pTmpContent, 2, "\r\n", 2);
									if (pFind != NULL)
									{
										pTmpContent += 2;
									}
									else
									{
										pFind = memmem(pTmpContent, data_len-(pTmpContent-http_content), "\r\n", 2);
										if (pFind != NULL)
										{
											pTmpContent = pFind+2;
										}
										else
										{
											nContentLength = 0;
											break;
										}
									}
								}
							}
						}
						else
						{
							nContentLength = 0;
							break;
						}
						/*
						pTmpContent = strstr(pTmpContent, "\r\n");
						if (pTmpContent != NULL)
						{
							nContentLength += nChunkLen;
							pTmpContent += 2+nChunkLen+2;
						}
						else
						{
							nContentLength = 0;
							break;
						}
						*/
					}
					else if (0 == nChunkLen)
					{
						pFind = memmem(pEnd, 4, "\r\n\r\n", 4);
						if (NULL == pFind)
						{
							LOGWARN("Session[%d][%d] fail to get end of chunk data. nContentLength=%d", pSession->thread_index, pSession->index, nContentLength);
							nContentLength = 0;
						}
						else
						{
							pTmpContent = pEnd + 4;
						}
							
						/*
						pTmpContent = strstr(pTmpContent, "\r\n\r\n");
						if (pTmpContent == NULL)
						{
							LOGWARN("Session[%d][%d] fail to get end of chunk data. nContentLength=%d", pSession->thread_index, pSession->index, nContentLength);
							nContentLength = 0;
						}
						*/
						break;
					}
					else
					{
						LOGWARN("Session[%d][%d] get chunk size < 0 nChunkLen=%d", pSession->thread_index, pSession->index, nChunkLen);
						nContentLength = 0;
						break;
					}
				}

				LOGDEBUG("Calculate the chunk size = %d", nContentLength);
				if (pTmpContent > http_content+data_len)
				{
					nContentLength = 0;
					LOGERROR("Session[%d][%d] fail to calculate the chunk size!", pSession->thread_index, pSession->index);
				}
					
				if (nContentLength > 0)
				{
					data_len = (pOldContent-http_content)+nContentLength+1;
					char* pChunkContent = calloc(1, data_len);
					if (pChunkContent != NULL)
					{
						int nRespStartPos = HTTP - http_content;
						int nOffset = pOldContent-http_content;
						memcpy(pChunkContent, http_content, nOffset);	

						pTmpContent = pOldContent;
						while (pTmpContent < http_content+data_len)
						{
							/*
							int nChunkLen = strtol(pTmpContent, NULL, 16);
							if (nChunkLen > 0)
							{
								pTmpContent = strstr(pTmpContent, "\r\n");
								memcpy(pChunkContent+nOffset, pTmpContent+2, nChunkLen);
								pTmpContent += 2+nChunkLen+2;
								nOffset += nChunkLen;
							}
							else if (nChunkLen == 0)
								break;
							*/

							pEnd = NULL;
							int nChunkLen = strtol(pTmpContent, &pEnd, 16);
							if (nChunkLen > 0)
							{
								pFind = memmem(pEnd, 2, "\r\n", 2);
								if (pFind != NULL)
								{
									pTmpContent = pEnd;
									if (!pSession->force_restore_flag)
									{
										memcpy(pChunkContent+nOffset, pTmpContent+2, nChunkLen);
										pTmpContent += 2+nChunkLen+2;
										nOffset += nChunkLen;
									}
									else
									{
										pTmpPart = pTmpContent+2;
										pFind = memmem(pTmpPart, nChunkLen, "\r\n", 2);
										if (pFind != NULL)
										{
											int nTmpLen = pFind-pTmpPart;
											memcpy(pChunkContent+nOffset, pTmpContent+2, nTmpLen);
											nOffset += nTmpLen;
											pTmpContent = pFind+2;	
										}
										else
										{
											memcpy(pChunkContent+nOffset, pTmpContent+2, nChunkLen);
											nOffset += nChunkLen;
										
											pTmpContent += 2+nChunkLen;
											pFind = memmem(pTmpContent, 2, "\r\n", 2);
											if (pFind != NULL)
											{
												pTmpContent += 2;
											}
											else
											{
												pFind = memmem(pTmpContent, data_len-(pTmpContent-http_content), "\r\n", 2);
												if (pFind != NULL)
												{
													pTmpContent = pFind+2;
												}
											}
										}
									}
								}
							}
						}

						pChunkContent[nOffset] = '\0';
						free(http_content);
						http_content = pChunkContent;
						HTTP = http_content + nRespStartPos;
					}
					else
					{
						LOGERROR("cannt calloc() chunk content buffer, %s", strerror(errno));
						//goto NOZIP
						nIsImmSendData = 1;
					}
				}
			}
		} 
		else if (HTTP_TRANSFER_WITH_HTML_END == transfer_flag)
		{
			char* pTmpContent = strstr(HTTP, "\r\n\r\n");
			if (pTmpContent == NULL)
			{
				LOGWARN("Session[%d][%d] with flag(HTTP_TRANSFER_WITH_HTML_END) has not content, current content = %s", pSession->thread_index, pSession->index, HTTP_PRE);
				//goto NOZIP;
				nIsImmSendData = 1;
			}
			else
			{
				pTmpContent += 4;
				
				char *pszHtmlEnd = strstr(HTTP, "</html>");
				if (pszHtmlEnd == NULL)
				{
					pszHtmlEnd = strstr(HTTP, "</Html>");
					if (pszHtmlEnd == NULL)
						pszHtmlEnd = strstr(HTTP, "</HTML>");
				}
				
				if (pszHtmlEnd != NULL)
				{
					pszHtmlEnd += 7;
					nContentLength = pszHtmlEnd - pTmpContent;
				}
				LOGDEBUG("The content length of content with html end is %d", nContentLength);
			}
		}
		else if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == transfer_flag)
		{
			LOGDEBUG("Session[%d][%d] with TRANSFER_HAVE_CONTENT_LENGTH, true len = %d, res1 = %d", pSession->thread_index, pSession->index, pSession->res_true_len, pSession->res1);
			nContentLength = (pSession->res_true_len > pSession->res1) ? pSession->res1 : pSession->res_true_len;
		}
		else if (HTTP_TRANSFER_FILE == transfer_flag)
		{
			char* pOldContent = strstr(HTTP, "\r\n\r\n");
			if (pOldContent == NULL)
			{
				LOGWARN("Session[%d][%d] with flag(HTTP_TRANSFER_FILE) has not content, current content = %s", pSession->thread_index, pSession->index, HTTP_PRE);
				//goto NOZIP
				nIsImmSendData = 1;;
			}
			else
			{
				pOldContent += 4;

				char szEmptyHtml[100] = {0};
				if (HTTP_CONTENT_FILE_PDF == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>pdf file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_KDH == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>kdh file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_CEB == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>ceb file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_CAJ == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>caj file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_MARC == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>marc file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_RIS == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>ris file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_BIB == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>bib file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_TXT == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>txt file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_PDG == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>pdg file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_EXCEL == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>excel file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_RTF == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>rtf file</title></head><body></body></html>\r\n");
				else if (HTTP_CONTENT_FILE_OTHER == pSession->content_type)
					strcpy(szEmptyHtml, "<html><head><title>other file</title></head><body></body></html>\r\n");
				
				nContentLength = strlen(szEmptyHtml);
				data_len = (pOldContent-http_content)+nContentLength+1;
				char* pFileContent = calloc(1, data_len);
				if (pFileContent != NULL)
				{
					int nRespStartPos = HTTP - http_content;
					int nOffset = pOldContent - http_content;
					memcpy(pFileContent, http_content, nOffset);	
					memcpy(pFileContent+nOffset, szEmptyHtml, nContentLength);
					pFileContent[nOffset+nContentLength] = '\0';
					free(http_content);
					http_content = pFileContent;
					HTTP = http_content + nRespStartPos;
					nContentLength = data_len;
				}
				else
				{
					LOGERROR("cannt calloc() file content buffer, %s", strerror(errno));
					//goto NOZIP;
					nIsImmSendData = 1;
				}
			}
		}

		LOGDEBUG("Session[%d][%d] get data nContentLength=%d", pSession->thread_index, pSession->index, nContentLength);

		if (1 == nIsImmSendData)
		{
			LOGWARN("Session[%d][%d] send data Immediately with warn or error!", pSession->thread_index, pSession->index);			
		}
		else
		{
			if (nContentLength == 0) 
			{
				LOGWARN("Session[%d][%d] has not content-Length or is 0, current content = %s", pSession->thread_index, pSession->index, HTTP);
				//goto NOZIP;
			}
			else
			{
				char* content = strstr(HTTP, "\r\n\r\n");
				if (content == NULL)
				{
					LOGWARN("Session[%d][%d] has not content, current content = %s", pSession->thread_index, pSession->index, HTTP);
					//goto NOZIP;
				}
				else
				{
					content += 4;

					LOGDEBUG("Session[%d][%d] content_encoding_gzip flag = %d", pSession->thread_index, pSession->index, pSession->content_encoding_gzip);
					
					// gzip Content-Encoding: gzip
					if (1 == pSession->content_encoding_gzip) 
					{
						const char* pZip_data = content;
						char* pPlain = NULL;
						++g_nGzipCount;
						int nUnzipLen = TransGzipData(pZip_data, nContentLength, &pPlain);
						LOGDEBUG("Session[%d][%d] transGzipData finish, nUnzipLen = %d", pSession->thread_index, pSession->index, nUnzipLen);
						if (nUnzipLen > 0)
						{
							int new_data_len = data_len+(nUnzipLen-nContentLength);
							if ((content-http_content+nUnzipLen+1) <= new_data_len)
							{
								char* new_http_content = calloc(1, new_data_len);
								if (new_http_content != NULL) 
								{
									int npos = content - http_content;
									memcpy(new_http_content, http_content, npos);
									memcpy(new_http_content+npos, pPlain, nUnzipLen);
									npos += nUnzipLen;
									new_http_content[npos] = '\0';
									free(pPlain);
									pPlain = NULL;
									free(http_content);
									data_len = npos+1;
									http_content = new_http_content;

									LOGDEBUG("Session[%d][%d] upzipData recombine finish", pSession->thread_index, pSession->index);
								}
								else
								{
									LOGERROR("cannt calloc() new_data, %s", strerror(errno));
									//goto NOZIP;
								}
							}
							else
							{
								LOGERROR("New data len after TransGzipData is error! new_data_len=%d, acturely_data_len=%d", new_data_len, (content-http_content+nUnzipLen+1));
							}
						}
						else
						{
							++g_nUnGzipFailCount;
							LOGWARN("Session[%d][%d] fail to UnGzip! Gzip Session count=%d, UnGzip fail count=%d", pSession->thread_index, pSession->index, g_nGzipCount, g_nUnGzipFailCount);
							
						}
					}
				}
			}
		}

		LogDataItems(pSession, nHttpcode, data_len);

		CleanHttpSession(pSession);
		*data = http_content;
		LOGDEBUG("Session[%d][%d] get data successfully!", pSession->thread_index, pSession->index);

		return data_len;
	}
	/*
	else
	{
		++g_nContentErrorCount;
		++g_nContentUnknownCount;
		LOGWARN("Session[%d][%d] content is HTTP_CONTENT_NONE and is not HTTP_TRANSFER_WITH_HTML_END, g_nContentErrorCount = %d, g_nContentUnknownCount = %d", pSession->thread_index, pSession->index, g_nContentErrorCount, g_nContentUnknownCount);
		LOGINFO("Session[%d][%d] content is %s", pSession->thread_index, pSession->index, HTTP_PRE);

		if (g_bIsLogUnknownData)
			LogDropSessionData("Rebuild Failed:Content Unknown", pSession);
		
		if (g_bIsSendUnknownData)
		{
			int nHttpcode = HTTP_SPECIAL_STATE_UNKNOWN_DATA;
			sprintf(http_content+35, "STATE=%03d", nHttpcode);
			LogDataItems(pSession, nHttpcode, data_len);
			CleanHttpSession(pSession);
			*data = http_content;
			LOGDEBUG("Session[%d][%d] get data successfully!", pSession->thread_index, pSession->index);
			return data_len;
		}
	}
	*/
	
	CleanHttpSession(pSession);
	free(http_content);
	return 0;
}

void LogDropSessionData(const char *pszDropType, const struct tcp_session *pSession)
{
	if (!is_log_drop_data())
		return;
	
	if ((NULL == pszDropType) || (NULL == pSession))
		return;
	
	char sip[20] = {0}, dip[20] = {0};
	char szUrlBody[1500] = {0};
	char szUrl[1500] = {0};
	inet_ntop(AF_INET, &pSession->client.ip, sip, 20);
	inet_ntop(AF_INET, &pSession->server.ip, dip, 20);

	if ('\0' != g_szSpecialClientIp[0])
	{
		if (strstr(g_szSpecialClientIp, sip) == NULL)
			return;
	}
		
	int nStart = 5;
	char *pszUrlStart = memmem(pSession->request_head, pSession->request_head_len, "POST ", 5);
	if (NULL == pszUrlStart)
	{
		pszUrlStart = memmem(pSession->request_head, pSession->request_head_len, "GET ", 4);
		nStart = 4;
	}
	
	char *pszUrlEnd = memmem(pSession->request_head, pSession->request_head_len, " HTTP/1.1", 9);
	if (NULL == pszUrlEnd)
		pszUrlEnd = memmem(pSession->request_head, pSession->request_head_len, " HTTP/1.0", 9);

	if ((pszUrlStart != NULL) && (pszUrlEnd != NULL))
	{
		int nUrlBodyLen = pszUrlEnd - pszUrlStart - nStart;
		strncpy(szUrlBody, pszUrlStart+nStart, nUrlBodyLen);
	}

	if (szUrlBody[0] != '\0')
	{
		if (strstr(szUrlBody, "http://") == NULL)
		{
			char *pszHost = memmem(pSession->request_head, pSession->request_head_len, "Host: ", 6);
			if (pszHost != NULL)
			{
				strcpy(szUrl, "Http://");
				char *pszHostEnd = strstr(pszHost, "\r\n");	
				if (pszHostEnd != NULL)
				{
					int nHostLen = pszHostEnd - pszHost - 6;
					strncat(szUrl, pszHost+6, nHostLen);
				}
			}

			if (szUrl[0] != '\0')
			{
				strcat(szUrl, szUrlBody);
			}
			else
			{
				strcpy(szUrl, szUrlBody);
			}
		}
		else
		{
			strcpy(szUrl, szUrlBody);
		}
	}
	
	struct tm tm_tmp = {0};
	char szCreateTime[50] = {0};
	localtime_r(&pSession->create.tv_sec, &tm_tmp);
	sprintf(szCreateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
			tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
			(int)(pSession->create.tv_usec/1000));

	memset(&tm_tmp, 0, sizeof(tm_tmp));
	char szUpdateTime[50] = {0};
	localtime_r(&pSession->update.tv_sec, &tm_tmp);
	sprintf(szUpdateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
			tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
			(int)(pSession->update.tv_usec/1000));

	struct timeval tv_drop;
	gettimeofday(&tv_drop, NULL);
	char szDropTime[50] = {0};
	memset(&tm_tmp, 0, sizeof(tm_tmp));
	localtime_r(&tv_drop.tv_sec, &tm_tmp);
	sprintf(szDropTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
			tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
			(int)(tv_drop.tv_usec/1000));
	
	LOG_DROP_DATA(sip, dip, pszDropType, szCreateTime, szUpdateTime, szDropTime, szUrl);
}

void LogDataItems(const struct tcp_session *pSession, int nState, int nDataSize)
{
	if (!is_log_data_items())
		return;
	
	if (NULL == pSession)
		return;
	
	char sip[20] = {0}, dip[20] = {0};
	char szUrlBody[1500] = {0};
	char szUrl[1500] = {0};
	inet_ntop(AF_INET, &pSession->client.ip, sip, 20);
	inet_ntop(AF_INET, &pSession->server.ip, dip, 20);

	if ('\0' != g_szSpecialClientIp[0])
	{
		if (strstr(g_szSpecialClientIp, sip) == NULL)
			return;
	}
	
	int nStart = 5;
	char *pszUrlStart = memmem(pSession->request_head, pSession->request_head_len, "POST ", 5);
	if (NULL == pszUrlStart)
	{
		pszUrlStart = memmem(pSession->request_head, pSession->request_head_len, "GET ", 4);
		nStart = 4;
	}
	
	char *pszUrlEnd = memmem(pSession->request_head, pSession->request_head_len, " HTTP/1.1", 9);
	if (NULL == pszUrlEnd)
		pszUrlEnd = memmem(pSession->request_head, pSession->request_head_len, " HTTP/1.0", 9);

	if ((pszUrlStart != NULL) && (pszUrlEnd != NULL))
	{
		int nUrlBodyLen = pszUrlEnd - pszUrlStart - nStart;
		strncpy(szUrlBody, pszUrlStart+nStart, nUrlBodyLen);
	}
	
	if (szUrlBody[0] != '\0')
	{
		if (strstr(szUrlBody, "http://") == NULL)
		{
			char *pszHost = memmem(pSession->request_head, pSession->request_head_len, "Host: ", 6);
			if (pszHost != NULL)
			{
				strcpy(szUrl, "Http://");
				char *pszHostEnd = strstr(pszHost, "\r\n"); 
				if (pszHostEnd != NULL)
				{
					int nHostLen = pszHostEnd - pszHost - 6;
					strncat(szUrl, pszHost+6, nHostLen);
				}
			}

			if (szUrl[0] != '\0')
			{
				strcat(szUrl, szUrlBody);
			}
			else
			{
				strcpy(szUrl, szUrlBody);
			}
		}
		else
		{
			strcpy(szUrl, szUrlBody);
		}
	}

	struct tm tm_tmp = {0};
	char szCreateTime[50] = {0};
	localtime_r(&pSession->create.tv_sec, &tm_tmp);
	sprintf(szCreateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
			tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
			(int)(pSession->create.tv_usec/1000));

	char szUpdateTime[50] = {0};
	memset(&tm_tmp, 0, sizeof(tm_tmp));
	localtime_r(&pSession->update.tv_sec, &tm_tmp);
	sprintf(szUpdateTime, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
			tm_tmp.tm_year+1900, tm_tmp.tm_mon+1, tm_tmp.tm_mday,
			tm_tmp.tm_hour, tm_tmp.tm_min, tm_tmp.tm_sec, 
			(int)(pSession->update.tv_usec/1000));

	int nUsedTime = ((uint64_t)pSession->update.tv_sec*1000 + pSession->update.tv_usec/1000) - ((uint64_t)pSession->create.tv_sec*1000 + pSession->create.tv_usec/1000);
	LOG_DATA_ITEMS(sip, dip, szCreateTime, szUpdateTime, nUsedTime, nDataSize, nState, szUrl);
}
