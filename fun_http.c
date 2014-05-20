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

struct hosts_t *_monitor_hosts = NULL;
size_t _monitor_hosts_count = 0;

struct hosts_t *_exclude_hosts = NULL;
size_t _exclude_hosts_count = 0;

pthread_mutex_t _host_ip_lock = PTHREAD_MUTEX_INITIALIZER;

//static char**  _monitor_uris = NULL;
//static size_t _monitor_uris_count = 0;

//static char**  _ignore_request = NULL;
//static size_t _ignore_request_count = 0;

static struct queue_t *_packets = NULL;

static int g_nCountWholeContentFull = 0;
static int g_nDropCountForPacketFull = 0;
static int g_nDropCountForSessionFull = 0;
static int g_nDropCountForImage = 0;
static int g_nTimeOutCount = 0;
static int g_nReusedCount = 0;
static int g_nChunked = 0;
static int g_nNone = 0;
static int g_nHtmlEnd = 0;

static int g_nSendErrStateDataFlag = 1;

static struct tcp_session* _http_session = NULL;	// a session = query + reponse
static struct queue_t *_idl_session = NULL;			// all idl session
static struct queue_t *_whole_content = NULL;		// http_session.flag = HTTP_SESSION_FINISH

extern volatile int g_nFlagGetData;
extern volatile int g_nFlagSendData;

enum HTTP_SESSION_FLAGS { 
	HTTP_SESSION_IDL, 
	HTTP_SESSION_REQUESTING,
	HTTP_SESSION_REQUEST, 
	HTTP_SESSION_REPONSE, 
	HTTP_SESSION_REPONSEING,
	HTTP_SESSION_FINISH, 
	HTTP_SESSION_TIMEOUT 
};

enum HTTP_TRANSFER_FLAGS { 
	HTTP_TRANSFER_INIT,
	HTTP_TRANSFER_NONE,
	HTTP_TRANSFER_HAVE_CONTENT_LENGTH, 
	HTTP_TRANSFER_CHUNKED,
	HTTP_TRANSFER_WITH_HTML_END,
	HTTP_TRANSFER_FILE
};

enum HTTP_CONTENT_TYPE { 
	HTTP_CONTENT_NONE,
	HTTP_CONTENT_HTML,
	HTTP_CONTENT_FILE_PDF,
	HTTP_CONTENT_FILE_KDH,
	HTTP_CONTENT_FILE_CEB,
	HTTP_CONTENT_FILE_OTHER
};

enum HTTP_APPEND_STATUS { 
	HTTP_APPEND_DROP_PACKET = -1,
	HTTP_APPEND_ADD_PACKET = 0,
	HTTP_APPEND_ADD_PACKET_LATER,
	HTTP_APPEND_FINISH_LATER,
	HTTP_APPEND_FINISH_CURRENT
};

// IDL -> REQUESTING -> REQUEST -> REPONSEING -> REPONSE -> FINISH
//           |------------|------------|------------------> TIMEOUT
extern volatile int Living;
static const unsigned _http_image = 0x50545448;
static const unsigned _get_image = 0x20544547;
static const unsigned _post_image = 0x54534F50;

// TODO: 先不处理ignore和uri
//
int isRelation(const struct iphdr *ip, const struct tcphdr *tcp,
		const struct tcp_session* session)
{
	// TODO
	return 1;
}

struct tcp_session* GetHttpSession(const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	return NULL;
}

struct tcp_session* CleanHttpSession(struct tcp_session* pSession)
{
	LOGDEBUG("Session[%d] start clean!", pSession->index);
	
	if (pSession->flag != HTTP_SESSION_IDL) 
	{
		unsigned index = pSession->index;
		void* packet = pSession->data;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGDEBUG("Session[%d] clean packet data successfully!", pSession->index);
		
		packet = pSession->pack_later;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGDEBUG("Session[%d] clean packet_later data successfully!", pSession->index);
		
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
		
		LOGDEBUG("Session[%d] clean response_head successfully!", pSession->index);
		
		memset(pSession, 0, sizeof(*pSession));
		pSession->index = index;
		pSession->flag = HTTP_SESSION_IDL;
		
		push_queue(_idl_session, pSession);
	}

	LOGDEBUG("Session[%d] end clean!", pSession->index);
	return pSession;
}

int NewHttpSession(const char* packet)
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
			LOGERROR0("The end of first pack head line is N!");
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
	
	if ((strstr(cmdline, ".gif ") != NULL)
		|| (strstr(cmdline, ".js ") != NULL)
		|| (strstr(cmdline, ".js?") != NULL)
		|| (strstr(cmdline, ".css ") != NULL)
		|| (strstr(cmdline, ".jpg ") != NULL)
		|| (strstr(cmdline, ".ico ") != NULL)
		|| (strstr(cmdline, ".bmp ") != NULL)
		|| (strstr(cmdline, ".png ") != NULL))
		//|| (strstr(cmdline, ".tif ") != NULL)
		//|| (strstr(cmdline, ".tiff ") != NULL))
	{
		return -3;
	}
	
	// find IDL session
	struct tcp_session* pIDL = NULL;
	int index = 0;
	for (; index < MAX_HTTP_SESSIONS; ++index) 
	{
		if (_http_session[index].flag != HTTP_SESSION_IDL && 
			_http_session[index].flag != HTTP_SESSION_FINISH) 
		{
			struct tcp_session* pREQ = &_http_session[index];
			if (pREQ->client.ip.s_addr==iphead->saddr && pREQ->client.port==tcphead->source && 
				pREQ->server.ip.s_addr==iphead->daddr && pREQ->server.port==tcphead->dest) 
			{ // client -> server be reuse.
				LOGWARN("session[%d] channel is reused. flag=%d res1=%d res2=%d g_nReusedCount=%d", index, pREQ->flag, pREQ->res1, pREQ->res2, ++g_nReusedCount);
				CleanHttpSession(pREQ);
				break;
			} 
			else if (tv->tv_sec - pREQ->update > HTTP_TIMEOUT) 
			{
				LOGWARN("one http_session is timeout. tv->tv_sec=%d pREQ->update=%d flag=%d index=%d res1=%d res2=%d g_nTimeOutCount=%d", tv->tv_sec, pREQ->update, pREQ->flag, index, pREQ->res1, pREQ->res2, ++g_nTimeOutCount);
				CleanHttpSession(pREQ);
				break;
			} 
			else 
			{
				continue;
			}
		}
		else if (HTTP_SESSION_IDL == _http_session[index].flag)
		{
			break;
		}
	}

	pIDL = (struct tcp_session*)pop_queue(_idl_session);
	if (pIDL == NULL) 
		return -2;

	pIDL->flag = HTTP_SESSION_REQUESTING;
	pIDL->client.ip.s_addr = iphead->saddr;
	pIDL->server.ip.s_addr = iphead->daddr;
	pIDL->client.port = tcphead->source;
	pIDL->server.port = tcphead->dest;
	pIDL->create = *tv;
	pIDL->update = tv->tv_sec;
	pIDL->seq = tcphead->seq;
	pIDL->ack = tcphead->ack_seq;
	pIDL->data = (void*)packet;
	pIDL->lastdata = (void*)packet;
	pIDL->res0 = contentlen;
	pIDL->res1 = 0;
	pIDL->res2 = 0;
	pIDL->transfer_flag = HTTP_TRANSFER_INIT;
	pIDL->response_head_recv_flag = 0;
	pIDL->content_encoding_gzip = 0;
	pIDL->content_type = HTTP_CONTENT_NONE;
	pIDL->response_head = NULL;
	pIDL->response_head_gen_time = 0;
	pIDL->response_head_len = 0;
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
		
	LOGDEBUG("Session[%d]Start request in NewHttpSession, content= %s", pIDL->index, content);
	
	return index;
}

int AppendServerToClient(int nIndex, const char* pPacket, int bIsCurPack)
{ 
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
	const char *content = (void*)tcphead + tcphead->doff*4;
	struct tcp_session *pSession = &_http_session[nIndex];

	// Check seq and ack. not fix.
	if (pSession->seq != tcphead->ack_seq || (pSession->ack+pSession->res0) != tcphead->seq)
	{ 
		if (pSession->ack == tcphead->seq && (pSession->seq + pSession->res0) == tcphead->ack_seq)  // it's not woring on first time.
		{
			LOGDEBUG("S->C packet for first response. Session[%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
					nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
			char *pszCode = memmem(content, contentlen, "HTTP/1.1 100", 12);
			if (pszCode == NULL)
				pszCode = memmem(content, contentlen, "HTTP/1.0 100", 12);

			if (pszCode != NULL)
			{
				LOGWARN("Drop this packet for state 100 continue. Session[%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

				pSession->flag = HTTP_SESSION_REPONSEING;
				pSession->seq = tcphead->ack_seq;
				pSession->ack = tcphead->seq;
				pSession->res0 = contentlen;
				pSession->update = tv->tv_sec;
				
				return HTTP_APPEND_DROP_PACKET;
			}
		}
		else if (((pSession->ack + pSession->res0) == tcphead->seq) && (abs(tcphead->ack_seq - pSession->seq) <= 4380))
		{ // TODO: why? check old. 
			LOGDEBUG("Session[%d] S->C packet, tcphead->ack_seq != pSession->seq. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
					nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
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

					LOGDEBUG("This packet is later packet for S->C wrong order. Session[%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

					return HTTP_APPEND_ADD_PACKET_LATER;
				}
				else
				{
					CleanHttpSession(pSession);
					LOGWARN("Drop this packet and clean session. The later packet size is max. Session[%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
							nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

					return HTTP_APPEND_DROP_PACKET;
				}
			}
			else
			{	// TODO: Check old.
				if (!bIsCurPack
					&& (((pSession->seq == tcphead->ack_seq) && ((pSession->ack + pSession->res0) < tcphead->seq))
						|| ((pSession->seq + pSession->res0) == tcphead->ack_seq && pSession->ack < tcphead->seq)))
				{
					return HTTP_APPEND_ADD_PACKET_LATER;
				}
				
				LOGDEBUG("Drop this packet for S->C wrong order. Session[%d] pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", 
						nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
				
				return HTTP_APPEND_DROP_PACKET;
			}
		}
	}
	else
	{
		//LOGDEBUG("Session[%d] S->C packet. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u content= %s", //ljr
		//		nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen, content);
		LOGDEBUG("Session[%d] S->C packet. pre.seq=%u pre.ack=%u pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u",
				nIndex, pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);
	}
	
	pSession->flag = HTTP_SESSION_REPONSEING;
	pSession->seq = tcphead->ack_seq;
	pSession->ack = tcphead->seq;
	pSession->res0 = contentlen;
	if (bIsCurPack)
		pSession->update = tv->tv_sec;

	*(const char**)pPacket = NULL;
	*(const char**)pSession->lastdata = pPacket;
	pSession->lastdata = (void*)pPacket;

	// reponse length
	if ((*(unsigned*)content == _http_image)
		|| ((pSession->res1 == 0)
			&& (HTTP_TRANSFER_INIT == pSession->transfer_flag) 
			&& (NULL == pSession->response_head) ))     // TODO: bug. Content-Length被分到两个包中
	{
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
			LOGDEBUG("Session[%d] response head is not enough, continue to generate. content= %s",
				nIndex, content);
		}
	} 
	else 
	{
		if ((HTTP_TRANSFER_INIT == pSession->transfer_flag) && (NULL != pSession->response_head))
		{
			LOGDEBUG("Session[%d] the next response contentlen=%d, content= %s",
				nIndex, contentlen, content);
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
				LOGDEBUG("Session[%d] response head generate successfully. content= %s",
					nIndex, content);
				
				pSession->response_head_recv_flag = 1;
			}
			else
			{
				LOGDEBUG("Session[%d] response head is not enough, continue to generate. content= %s",
					nIndex, content);
			}
		}
		else
		{
			pSession->res2 += contentlen;
			LOGTRACE("Session[%d] part_reponse_len = %u/%u", nIndex, pSession->res2, pSession->res1);
		}
	}
		
	if (1 == pSession->response_head_recv_flag)
	{
		pSession->response_head_recv_flag = 0;
		pSession->transfer_flag = HTTP_TRANSFER_NONE;
		strlwr(content);
		LOGDEBUG("Session[%d] response head generate contentlen= %d, content= %s", nIndex, contentlen, content);
		
		char* content_encoding = memmem(content, contentlen, "content-encoding: gzip", 22);
		if (content_encoding != NULL)
			pSession->content_encoding_gzip = 1;

		char* content_type = memmem(content, contentlen, "content-type: ", 14);
		if (content_type != NULL)
		{
			if (strncmp(content_type+14, "text/html", 9) == 0 
				|| strncmp(content_type+14, "text/xml", 8) == 0 
				|| strncmp(content_type+14, "text/plain", 10) == 0
				|| strncmp(content_type+14, "application/x-ami", 17) == 0)
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
			{	// TODO: add download file.
				char* pszFileType = memmem(content, contentlen, ".pdf", 4);
				if (pszFileType != NULL)
					pSession->content_type = HTTP_CONTENT_FILE_PDF;					
				else
					pSession->content_type = HTTP_CONTENT_FILE_OTHER;
			}
		}
		else
		{
			char *tmp = NULL;
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
					LOGDEBUG("Session[%d]with html end, g_nHtmlEnd=%d content= %s", nIndex, ++g_nHtmlEnd, content);
					pSession->transfer_flag = HTTP_TRANSFER_WITH_HTML_END;
				}
				else
				{
					LOGDEBUG("Session[%d]with transfer none, g_nNone=%d content= %s", nIndex, ++g_nNone, content);
					pSession->transfer_flag = HTTP_TRANSFER_NONE;
				}
			}
		}
		
		if (HTTP_CONTENT_HTML == pSession->content_type)
		{
			char *tmp = NULL;
			char *pszContentLen = memmem(content, contentlen, "content-length:", 15);
			if (pszContentLen != NULL) 
			{
				pSession->transfer_flag = HTTP_TRANSFER_HAVE_CONTENT_LENGTH;
				pSession->res1 = strtol(pszContentLen+15, &tmp, 10);
				LOGDEBUG("Session[%d] Content-Length = %u, content = %s", nIndex, pSession->res1, content);
				if ((tmp = strstr(content, "\r\n\r\n")) != NULL) 
				{
					pSession->res2 = contentlen - (tmp-content) - 4;
				}
			}
			else
			{
				char *pszTE = memmem(content, contentlen, "transfer-encoding:", 18);
				char *pszChunked = memmem(content, contentlen, "chunked", 7);
				if ((pszTE != NULL) && (pszChunked != NULL))
				{
					pSession->transfer_flag = HTTP_TRANSFER_CHUNKED;
					LOGDEBUG("Session[%d]Transfer-Encoding: chunked, g_nChunked = %d content = %s", nIndex, ++g_nChunked, content);
				}
				else
				{
					char *pszCode = memmem(content, contentlen, "http/1.1 200", 12);
					if (pszCode == NULL)
						pszCode = memmem(content, contentlen, "http/1.0 200", 12);
					
					if (pszCode != NULL)
					{
						LOGDEBUG("Session[%d]with html end, g_nHtmlEnd=%d content= %s", nIndex, ++g_nHtmlEnd, content);
						pSession->transfer_flag = HTTP_TRANSFER_WITH_HTML_END;

					}
					else
					{
						LOGDEBUG("Session[%d]with transfer none, g_nNone=%d content= %s", nIndex, ++g_nNone, content);
						pSession->transfer_flag = HTTP_TRANSFER_NONE;
					}
				}
			}
		}
		else if ((HTTP_CONTENT_FILE_PDF == pSession->content_type)
				 || (HTTP_CONTENT_FILE_KDH == pSession->content_type)
				 || (HTTP_CONTENT_FILE_CEB == pSession->content_type)
				 || (HTTP_CONTENT_FILE_OTHER == pSession->content_type))
		{
			pSession->content_encoding_gzip = 0;
			pSession->transfer_flag = HTTP_TRANSFER_FILE;
			LOGDEBUG("Session[%d] content is file.", nIndex);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;
			
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
				LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
			
			return HTTP_APPEND_FINISH_CURRENT;
		}

		if (HTTP_TRANSFER_NONE == pSession->transfer_flag)
		{
			LOGDEBUG("Session[%d] content is others and not HTTP_TRANSFER_WITH_HTML_END.", nIndex);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;
			
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
				LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
			
			return HTTP_APPEND_FINISH_CURRENT;
		}

		/*
		if (pSession->response_head != NULL)
		{
			free(pSession->response_head);
			pSession->response_head = NULL;
		}
		*/
	}

	if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == pSession->transfer_flag)
//		|| HTTP_TRANSFER_NONE == pSession->transfer_flag)
	{
		if (pSession->res2 >= pSession->res1) 
		{
			LOGDEBUG("Session[%d] end_reponse content-length/recv = %u/%u, content= %s", nIndex, pSession->res1, pSession->res2, content);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;
			
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
				LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
			
			return HTTP_APPEND_FINISH_CURRENT;
		}
	}
	else if (HTTP_TRANSFER_CHUNKED == pSession->transfer_flag)
	{
		char *pszChunkedEnd = memmem(content, contentlen, "\r\n0\r\n\r\n", 7);
		if (pszChunkedEnd != NULL)
		{
			LOGDEBUG("Session[%d]end_reponse with chunked data", nIndex);
			if (!bIsCurPack)
				return HTTP_APPEND_FINISH_LATER;
			
			pSession->flag = HTTP_SESSION_FINISH;
			if (push_queue(_whole_content, pSession) < 0)
				LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
			
			return HTTP_APPEND_FINISH_CURRENT;
		}
	}
	else if (HTTP_TRANSFER_WITH_HTML_END == pSession->transfer_flag)
	{
		char *pszHtmlEnd = memmem(content, contentlen, "</html>", 7);
		if (pszHtmlEnd == NULL)
		{
			pszHtmlEnd = memmem(content, contentlen, "</Html>", 7);
			if (pszHtmlEnd == NULL)
				pszHtmlEnd = memmem(content, contentlen, "</HTML>", 7);
		}
		
		if (pszHtmlEnd != NULL)
		{
			LOGDEBUG("Session[%d] find </html>, content=%s", nIndex, content);
			int nLeft = contentlen - (pszHtmlEnd-content+7);
			if (((pszHtmlEnd-content+7) == contentlen)
				|| ((nLeft >= 6) && (memmem(pszHtmlEnd+7, 6, "\r\n\r\n", 4) != NULL || memmem(pszHtmlEnd+7, 6, "\n\n", 2) != NULL))
				|| (memmem(pszHtmlEnd+7, nLeft, "<", 1) == NULL
					&& memmem(pszHtmlEnd+7, nLeft, ">", 1) == NULL))
			{
				LOGDEBUG("Session[%d]end_reponse with </html>, left length=%d", nIndex, nLeft);
				if (!bIsCurPack)
					return HTTP_APPEND_FINISH_LATER;
				
				pSession->flag = HTTP_SESSION_FINISH;
				if (push_queue(_whole_content, pSession) < 0)
					LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
				
				return HTTP_APPEND_FINISH_CURRENT;
			}
		}
	}

	return HTTP_APPEND_ADD_PACKET;
}

int AppendClientToServer(int nIndex, const char* pPacket)
{
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
	const char *content = (void*)tcphead + tcphead->doff*4;
	struct tcp_session *pSession = &_http_session[nIndex];

	if (pSession->flag != HTTP_SESSION_REQUESTING) 
		LOGWARN("Resend request or post request. Current flag = %d", pSession->flag);

	if ((pSession->seq+pSession->res0) != tcphead->seq || pSession->ack != tcphead->ack_seq) 
	{
		LOGWARN("Session[%d] C->S packet wrong order. pre.seq=%u pre.ack=%u "
				 "pre.len=%u cur.seq=%u cur.ack=%u cur.len=%u", nIndex,
				 pSession->seq, pSession->ack, pSession->res0, tcphead->seq, tcphead->ack_seq, contentlen);

		if ((1 == contentlen) && (*content == '\0'))
		{
			LOGWARN("Session[%d] AppendClientToServer drop packet, wrong order, contentlen=1, content=empty!", nIndex);
		}
		else
		{
			pSession->request_head_len_valid_flag = 1;
			pSession->seq += contentlen;
			LOGWARN("Session[%d] AppendClientToServer drop packet, content!=empty!", nIndex);
		}
		return HTTP_APPEND_DROP_PACKET;
	}

	LOGINFO("Session[%d] AppendClientToServer content=%s", nIndex, content);

	if ((1 == contentlen) && (*content == '\0'))
	{
		LOGWARN("Session[%d] AppendClientToServer drop packet, contentlen=1, content=empty!", nIndex);
		return HTTP_APPEND_DROP_PACKET;
	}

	pSession->ack = tcphead->ack_seq;
	pSession->seq = tcphead->seq;
	pSession->res0 = contentlen;
	pSession->update = tv->tv_sec;

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

int AppendLaterPacket(int nIndex)
{
	ASSERT(nIndex >= 0);
	
	struct tcp_session *pSession = &_http_session[nIndex];
	void *pLaterPack = pSession->pack_later;
	
	if (pLaterPack != NULL)
	{
		LOGDEBUG("###########Start Process later packet list! index=%d", nIndex);
		
		void *pCurTmp = NULL, *pPreTmp = NULL;
		while (pLaterPack != NULL) 
		{
			pCurTmp = pLaterPack;
			pLaterPack = *(void**)pLaterPack;
			int nRs = AppendServerToClient(nIndex, pCurTmp, 0);
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
					pSession->flag = HTTP_SESSION_FINISH;
					if (push_queue(_whole_content, pSession) < 0)
						LOGWARN("whole content queue is full. count = %d", ++g_nCountWholeContentFull);
					
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

	return 0;
}

int AppendReponse(const char* packet, int bIsCurPack)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead = TCPHDR(iphead);
	struct tcp_session *pREQ = &_http_session[0];

	int index = 0;
	for (; index < MAX_HTTP_SESSIONS; ++index) 
	{
		pREQ = &_http_session[index];
		if (pREQ->flag == HTTP_SESSION_IDL || pREQ->flag == HTTP_SESSION_FINISH) 
			continue;

		// process timeout
		if (tv->tv_sec-pREQ->update > HTTP_TIMEOUT) 
		{
			LOGWARN("one http_session is timeout. tv->tv_sec=%d pREQ->update=%d flag=%d index=%d res1=%d res2=%d g_nTimeOutCount=%d", tv->tv_sec, pREQ->update, pREQ->flag, index, pREQ->res1, pREQ->res2, ++g_nTimeOutCount);
			CleanHttpSession(pREQ);
			continue;
		}

		int nRs = 0;
		if (pREQ->client.ip.s_addr == iphead->daddr && pREQ->client.port == tcphead->dest 
			&& pREQ->server.ip.s_addr == iphead->saddr && pREQ->server.port == tcphead->source) // server -> client
		{
			nRs = AppendServerToClient(index, packet, bIsCurPack);
			if (nRs == HTTP_APPEND_ADD_PACKET || nRs == HTTP_APPEND_ADD_PACKET_LATER)
			{
				AppendLaterPacket(index);
			}
			else if (nRs == HTTP_APPEND_DROP_PACKET)
				return nRs;	
			
			break;
		}
		else if (pREQ->client.ip.s_addr == iphead->saddr && pREQ->client.port == tcphead->source // client -> server
				 && pREQ->server.ip.s_addr == iphead->daddr && pREQ->server.port == tcphead->dest) 
		{ 
			nRs = AppendClientToServer(index, packet);
			if (nRs == HTTP_APPEND_DROP_PACKET)
				return nRs;	
			
			break;
		} 
		else 
		{
			char sip[20], dip[20], stip[20], dtip[20];
			LOGTRACE("Session[%d] %s:%d => %s:%d. append %s:%d => %s:%d", index,
					inet_ntop(AF_INET, &pREQ->client.ip, sip, 20), ntohs(pREQ->client.port),
					inet_ntop(AF_INET, &pREQ->server.ip, dip, 20), ntohs(pREQ->server.port),
					inet_ntop(AF_INET, &iphead->saddr, stip, 20),  ntohs(tcphead->source),
					inet_ntop(AF_INET, &iphead->daddr, dtip, 20),  ntohs(tcphead->dest));
		}
	}
	if (index == MAX_HTTP_SESSIONS) 
	{
		char sip[20], dip[20], stip[20], dtip[20];
		LOGTRACE("Session[%d]  append %s:%d => %s:%d", index,
				inet_ntop(AF_INET, &iphead->saddr, stip, 20),  ntohs(tcphead->source),
				inet_ntop(AF_INET, &iphead->daddr, dtip, 20),  ntohs(tcphead->dest));
		
		index = HTTP_APPEND_DROP_PACKET;
	}

	return index;
}

void *HTTP_Thread(void* param)
{
	volatile int *active = (int*)param;
	while (*active)
	{
		const char* packet = pop_queue(_packets);
		if (packet == NULL) {
			sleep(0);
			continue;
		}

		struct timeval *tv = (struct timeval*)packet;
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		int contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		char *content = (void*)tcphead + tcphead->doff*4;

		if (tcphead->syn || contentlen <=0) { 
			free((void*)packet); 
			continue; 
		} 

		// TMP
		tcphead->seq = ntohl(tcphead->seq);
		tcphead->ack_seq = ntohl(tcphead->ack_seq);

		unsigned *cmd = (unsigned*)content;
		if (*cmd == _get_image || *cmd == _post_image) 
		{
			int nRes = 0;
			if ((nRes = NewHttpSession(packet)) < 0) 
			{
				if (nRes == -3) 
				{
					LOGDEBUG("Content is not html data. drop count = %d", ++g_nDropCountForImage);
				}
				else if (nRes == -1) 
				{
					LOGWARN0("Content is error! Do not insert into session.");
				} 
				else if (nRes == -2) 
				{
					char *enter = strchr(content, '\r');
					if (enter != NULL) 
					{
						*enter = '\0';
						LOGWARN("_http_session is full. drop count = %d, drop content = %s", ++g_nDropCountForSessionFull, content);
						*enter = '\r';

						LOGINFO("g_nFlagGetData = %d", g_nFlagGetData);
						LOGINFO("g_nFlagSendData = %d", g_nFlagSendData);
					}
				}
				free((void*)packet);
			}

			//LOGWARN("g_nDropCountForSessionFull  = %d, g_nDropCountForPacketFull = %d", g_nDropCountForSessionFull, g_nDropCountForPacketFull);
			continue;
		}

		int nIndex = AppendReponse(packet, 1);
		if (nIndex == HTTP_APPEND_DROP_PACKET) 
		{
			LOGDEBUG0("cannt find request with reponse.");
			free((void*)packet);
		}
	}
	return NULL;
}

int HttpInit()
{
	ASSERT(_packets == NULL);
	ASSERT(_http_session == NULL);

	char szSendErrStateDataFlag[10] = {0};
	if (GetValue(CONFIG_PATH, "SendErrStateDataFlag", szSendErrStateDataFlag, 2) != NULL)
		g_nSendErrStateDataFlag = atoi(szSendErrStateDataFlag);
	
	_packets = init_queue(MAX_HTTP_PACKETS);
	ASSERT(_packets != NULL);
	_http_session = calloc(sizeof(_http_session[0]), MAX_HTTP_SESSIONS);
	ASSERT(_http_session != NULL);
	_whole_content = init_queue(MAX_HTTP_SESSIONS);
	ASSERT(_whole_content != NULL);
	_idl_session = init_queue(MAX_HTTP_SESSIONS);
	ASSERT(_idl_session != NULL);
	//_use_session = init_queue(MAX_HTTP_SESSIONS);
	//ASSERT(_use_session != NULL);

	for (size_t index = 0; index < MAX_HTTP_SESSIONS; ++index)
	{
		_http_session[index].index = index;
		push_queue(_idl_session, &_http_session[index]);
	}

	//for (int n=0; n<1; ++n) {
	pthread_t pthreadid;
	int err = pthread_create(&pthreadid, NULL, &HTTP_Thread, (void*)&Living);
	ASSERT(err==0);
	// }

	return _packets==NULL? -1:0;
}

int inHosts(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	if (NULL == _monitor_hosts)
		return -1;
	
	const char *content = (const char *)tcphead + tcphead->doff*4;
	unsigned *cmd = (unsigned*)content;

	for (int npos = 0; npos < _monitor_hosts_count; npos++)
	{
		struct hosts_t *tmp = &_monitor_hosts[npos];
		if (0 == tmp->ip.s_addr)
			continue;
		
		if (tmp->ip.s_addr==INADDR_BROADCAST 
			&& (tmp->port==tcphead->source || tmp->port==tcphead->dest || tmp->port==0u))
			return npos;

		if ( (tmp->ip.s_addr==iphead->saddr && (tmp->port==tcphead->source || tmp->port==0u) && (*cmd != _get_image && *cmd != _post_image))
			 || (tmp->ip.s_addr==iphead->daddr && (tmp->port==tcphead->dest || tmp->port==0u)))
		{
			return npos;
		}
	}

	return -1;
}

int inExcludeHosts(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	if (NULL == _exclude_hosts)
		return -1;
	
	const char *content = (const char *)tcphead + tcphead->doff*4;
	unsigned *cmd = (unsigned*)content;
	
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

int PushHttpPack(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{	
	struct timeval *tv = (struct timeval*)buffer;
	gettimeofday(tv, NULL);
	int err = push_queue(_packets, (const void*) buffer);
	if (err < 0) 
	{
		LOGWARN("http_queue is full. drop the packets, drop count = %d", ++g_nDropCountForPacketFull);
	}
	return err;
}

/// buffer is http return 0. other return -1;
int FilterPacketForHttp(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	int nRs = 0;

	pthread_mutex_lock(&_host_ip_lock);
	
	if ((inHosts(buffer, iphead, tcphead) == -1) 
		|| (inExcludeHosts(buffer, iphead, tcphead) != -1))
	{
		struct in_addr sip; 
		struct in_addr dip; 

		sip.s_addr = iphead->saddr;
		dip.s_addr = iphead->daddr;
		char ssip[16], sdip[16];
		LOGTRACE("%s => %s is skiped.", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));

		nRs = -1; 
	}
	else
	{
		if (PushHttpPack(buffer, iphead, tcphead) == -1)
			nRs = -1;
	}

	pthread_mutex_unlock(&_host_ip_lock);
	
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

		for(left=httphosts; ;left=NULL) {
			ipport = strtok_r(left, "\n", &right);
			if (ipport==NULL) break;
			LOGINFO("monitor host %s", ipport);
			if (str_ipp(ipport, &_monitor_hosts[n])) { ++n; }
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

		for(left=excludehosts; ;left=NULL) {
			ipport = strtok_r(left, "\n", &right);
			if (ipport==NULL) break;
			LOGINFO("exclude host %s", ipport);
			if (str_ipp(ipport, &_exclude_hosts[n])) { ++n; }
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
			LOGWARN0("TransGzipData, content length > plain length, trans stop!");
			return -1;
		}
		
		pPlain = calloc(1, plain_len+1024);
	}
	else if (0 == plain_len)
	{ // TODO: check old. 
		if (nDataLen > 0 && nDataLen < 800000)
		{
			pPlain = calloc(1, 5120);
			plain_len = -1;
		}
		else
		{
			LOGWARN0("TransGzipData, plain length = 0 and plain length >= 800KB, trans stop!");
			return -1;
		}
	}
	else
	{
		LOGWARN0("TransGzipData, plain length < 0 or plain length >= 10M, trans stop!");
		return -1;
	}
	
	if (pPlain == NULL) {
		LOGWARN0("cannt calloc plain!");
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
	if (plain_len > 0)
	{
		while (!gzeof(p)) {
			n = gzread(p, pPlain+nReaded, plain_len+1024-nReaded);
			if (n == -1) {
				LOGERROR("gzread() return -1. %s", strerror(errno));
				break;
			}
			nReaded += n;
			if (nReaded > plain_len) {
				LOGERROR("gzread() return more than plain_len, read data length = %d, plain length = %d", nReaded, plain_len);
				break;
			}
		}
	}
	else
	{
		while (!gzeof(p)) {
			n = gzread(p, pPlain+nReaded, 5120);
			LOGDEBUG("gzread() return %d", n);
			if (n == -1) {
				LOGERROR("gzread() return -1. %s", strerror(errno));
				break;
			}
			nReaded += n;
			pPlain = realloc(pPlain, nReaded + 5120);
		}
	}
	
	gzclose(p);
	unlink(gzfile);
	LOGDEBUG("TransGzipData finish. Read data length = %d, plain length = %d", nReaded, plain_len);
	
	*pTransData = pPlain;
	return nReaded;
}

int GetHttpData(char **data)
{
	*data = NULL;
	struct tcp_session *pSession = (struct tcp_session*)pop_queue(_whole_content);
	if (pSession == NULL) 
		return 0;
	
	size_t http_len = 0;
	ASSERT(pSession->flag == HTTP_SESSION_FINISH);
	assert(pSession->data != NULL);

	// get all http_content len
	unsigned transfer_flag = pSession->transfer_flag;
	void* packet = pSession->data;
	do {
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		http_len += contentlen;
		//const char *content = (void*)tcphead + tcphead->doff*4;
		packet = *(void**)packet;
	} while (packet!=NULL);
	// malloc
	unsigned data_len = http_len+35+10+26+26+5+1;
	char* http_content = (char*)calloc(1, data_len);
	if (http_content == NULL) {
		LOGERROR0("mallocing memory failed. will be retry");
		return 0;
	}
	// make data
	size_t pos = 0;
	char sip[20];
	struct tm _tm;
	localtime_r(&pSession->create.tv_sec, &_tm);
	sprintf(http_content, "VISIT_TIME=%04d-%02d-%02d %02d:%02d:%02d:%03d",
			_tm.tm_year+1900, _tm.tm_mon+1, _tm.tm_mday,
			_tm.tm_hour, _tm.tm_min, _tm.tm_sec, (int)(pSession->create.tv_usec/1000));
	// sprintf(http_content+35, "STATE=200");
	sprintf(http_content+35+10, "IP_CLIENT=%15s", inet_ntop(AF_INET, &pSession->client.ip, sip, 20));
	sprintf(http_content+35+10+26, "IP_SERVER=%15s", inet_ntop(AF_INET, &pSession->server.ip, sip, 20));
	sprintf(http_content+35+10+26+26, "DATA=");
	pos = 35+10+26+26+5;
	
	packet = pSession->data;
	do {
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = ntohs(iphead->tot_len) - iphead->ihl*4 - tcphead->doff*4;
		if (contentlen > RECV_BUFFER_LEN) {
			LOGERROR("contentlen[%u] is great than RECV_BUFFER_LEN[%u]", contentlen, RECV_BUFFER_LEN);
		}
		const char *content = (void*)tcphead + tcphead->doff*4;
		memcpy(http_content+pos, content, contentlen);
		pos += contentlen;
		void* tmp = packet;
		packet = *(void**)packet;
		free(tmp);
	} while (packet!=NULL);
	pSession->data = NULL;
	
	http_content[pos] = '\0';
	ASSERT(pos+1 == data_len);

	/*
	FILE* pf;
	int nwrite, n;

	// sent for debug
	pf = fopen("sent.txt", "a+b");
	nwrite = 0;
	do {
		n = fwrite(http_content+nwrite, 1, data_len-nwrite, pf);
		if (n<1) {
			perror("Error in writing sent.txt");
			break;
		}
		nwrite += n;
	} while (nwrite < data_len);
	fprintf(pf, "\n===================[%d]==%d=========\n", data_len, nwrite);
	fclose(pf); 
	*/
	
	// proce http
	char* HTTP = http_content+35+10+26+26+5;
	char* HTTP_PRE = HTTP;
	if (*(unsigned*)HTTP == _get_image) 
	{
		HTTP = strstr(HTTP, "\r\n\r\n");	// skip query
		if (HTTP != NULL)
			HTTP += 4;
	} 
	else if (*(unsigned*)HTTP == _post_image) 
	{
		char* query_len = strstr(HTTP, "Content-Length:");
		int query_length = 0;
		if (query_len != NULL)
			query_length = strtol(query_len+15, NULL, 10);

		char* HTTP_pre = HTTP;
		HTTP = strstr(HTTP, "\r\n\r\n");	// skip query
		if (HTTP != NULL)
		{
			if (0 == pSession->request_head_len_valid_flag)
			{
				HTTP += 4 + query_length;
			}
			else
			{
				HTTP = HTTP_pre + pSession->request_head_len - 1;
			}
		}
	} 
	else 
	{
		LOGERROR("No GET or POST. %c%c%c%c", HTTP[0],HTTP[1],HTTP[2],HTTP[3]);
	}
	
	if (HTTP == NULL) {
		LOGERROR0("Not http!!!!! cannt get here!!!.");
		CleanHttpSession(pSession);
		free(http_content);
		return 0;
	}

	if ((HTTP - http_content) >= data_len) {
		LOGWARN("Session[%d] Address more than data length. Current content= %s", pSession->index, HTTP_PRE);
		CleanHttpSession(pSession);
		free(http_content);
		return 0;
	}
	
	LOGDEBUG("Session[%d] ready to get data", pSession->index);
	if ((pSession->content_type != HTTP_CONTENT_NONE)
		|| (HTTP_TRANSFER_WITH_HTML_END == transfer_flag))
	{
		// get http code
		char* http_code = strstr(HTTP, "HTTP/1.0 ");
		if (NULL == http_code)
			http_code = strstr(HTTP, "HTTP/1.1 ");
		
		if (NULL == http_code)
		{
			LOGWARN("Session[%d] has not HTTP/1.0 or HTTP/1.1, Current content= %s", pSession->index, HTTP_PRE);
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}

		http_code += 9;
		int nHttpcode = strtol(http_code, NULL, 10);
		if ((0 == g_nSendErrStateDataFlag) && (nHttpcode >= 404))
		{
			LOGDEBUG("Session[%d] httpcode=%d, Do not send current content.", pSession->index, nHttpcode);
			CleanHttpSession(pSession);
			free(http_content);
			return 0;
		}

		sprintf(http_content+35, "STATE=%03d", nHttpcode);
		LOGDEBUG("Session[%d] get data httpcode=%d, transfer_flag=%d", pSession->index, nHttpcode, transfer_flag);
		
		int nContentLength = 0;
		if (HTTP_TRANSFER_CHUNKED == transfer_flag)
		{
			char* pOldContent = strstr(HTTP, "\r\n\r\n");
			if (pOldContent == NULL)
			{
				LOGWARN("Session[%d] has not content_TRANSFER_CHUNKED, Current content= %s", pSession->index, HTTP_PRE);
				goto NOZIP;
			}
			pOldContent += 4;
			
			char* pTmpContent = pOldContent;
			while (pTmpContent < http_content+data_len)
			{
				int nChunkLen = strtol(pTmpContent, NULL, 16);
				if (nChunkLen > 0)
				{
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
				}
				else if (nChunkLen == 0)
				{
					pTmpContent = strstr(pTmpContent, "\r\n\r\n");
					if (pTmpContent == NULL)
					{
						LOGWARN("Session[%d] fail to get end of chunk data. nContentLength=%d", pSession->index, nContentLength);
						nContentLength = 0;
					}
					
					break;
				}
				else
				{
					LOGWARN("Session[%d] get chunk size <0 nChunkLen=%d", pSession->index, nChunkLen);
					nContentLength = 0;
					break;
				}
			}

			LOGDEBUG("Calculate the chunk size = %d", nContentLength);
			if (pTmpContent >= http_content+data_len)
			{
				nContentLength = 0;
				LOGERROR("Session[%d] fail to calculate the chunk size!", pSession->index);
			}
				
			if (nContentLength > 0)
			{
				data_len = (pOldContent-http_content)+nContentLength+1;
				char* pChunkContent = calloc(1, data_len);
				if (pChunkContent == NULL)
					goto NOZIP;

				int nRespStartPos = HTTP - http_content;
				int nOffset = pOldContent-http_content;
				memcpy(pChunkContent, http_content, nOffset);	

				pTmpContent = pOldContent;
				while (pTmpContent < http_content+data_len)
				{
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
				}

				pChunkContent[nOffset] = '\0';
				free(http_content);
				http_content = pChunkContent;
				HTTP = http_content + nRespStartPos;
			}
		} 
		else if (HTTP_TRANSFER_WITH_HTML_END == transfer_flag)
		{
			char* pTmpContent = strstr(HTTP, "\r\n\r\n");
			if (pTmpContent == NULL)
			{
				LOGWARN("Session[%d] has not content_HTML_END, current content = %s", pSession->index, HTTP_PRE);
				goto NOZIP;
			}
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
		else if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == transfer_flag)
		{
			nContentLength = pSession->res1;
		}
		else if (HTTP_TRANSFER_FILE == transfer_flag)
		{
			char* pOldContent = strstr(HTTP, "\r\n\r\n");
			if (pOldContent == NULL)
			{
				LOGWARN("Session[%d] has not content_TRANSFER_FILE, current content = %s", pSession->index, HTTP_PRE);
				goto NOZIP;
			}
			pOldContent += 4;

			char szEmptyHtml[100] = {0};
			if (HTTP_CONTENT_FILE_PDF == pSession->content_type)
				strcpy(szEmptyHtml, "<html><head><title>pdf file</title></head><body></body></html>\r\n");
			else if (HTTP_CONTENT_FILE_KDH == pSession->content_type)
				strcpy(szEmptyHtml, "<html><head><title>kdh file</title></head><body></body></html>\r\n");
			else if (HTTP_CONTENT_FILE_CEB == pSession->content_type)
				strcpy(szEmptyHtml, "<html><head><title>ceb file</title></head><body></body></html>\r\n");
			else if (HTTP_CONTENT_FILE_OTHER == pSession->content_type)
				strcpy(szEmptyHtml, "<html><head><title>other file</title></head><body></body></html>\r\n");
			
			nContentLength = strlen(szEmptyHtml);
			data_len = (pOldContent-http_content)+nContentLength+1;
			char* pFileContent = calloc(1, data_len);
			if (pFileContent == NULL)
				goto NOZIP;

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

		LOGDEBUG("Session[%d] get data nContentLength=%d", pSession->index, nContentLength);
		
		if (nContentLength == 0) 
		{
			LOGWARN("Session[%d] has not content-Length or is 0, current content = %s", pSession->index, HTTP);
			goto NOZIP;
		}
		
		char* content = strstr(HTTP, "\r\n\r\n");
		if (content == NULL)
		{
			LOGWARN("Session[%d] has not content, current content = %s", pSession->index, HTTP);
			goto NOZIP;
		}
		content += 4;

		LOGDEBUG("Session[%d] get data content_encoding_gzip=%d", pSession->index, pSession->content_encoding_gzip);
		
		// gzip Content-Encoding: gzip
		if (1 == pSession->content_encoding_gzip) 
		{
			const char* pZip_data = content;
			char* pPlain = NULL;
			int nUnzipLen = TransGzipData(pZip_data, nContentLength, &pPlain);
			if (nUnzipLen != -1)
			{
				int new_data_len = data_len+(nUnzipLen-nContentLength);
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
				}
				else
				{
					LOGERROR("cannt calloc() new_data, %s", strerror(errno));
					goto NOZIP;
				}
			}
		}
NOZIP:
		CleanHttpSession(pSession);
		*data = http_content;
		LOGDEBUG("Session[%d] get data successfully!", pSession->index);
		
		return data_len;
	}
	else
	{
		LOGDEBUG("Session[%d] content is HTTP_CONTENT_NONE and is not HTTP_TRANSFER_WITH_HTML_END", pSession->index);
	}
	
	CleanHttpSession(pSession);
	free(http_content);
	return 0;
}

