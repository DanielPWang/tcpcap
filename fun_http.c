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
#include <sys/types.h>
#include <zlib.h>
#include <sched.h>

#include "config.h"
#include "iface.h"
#include "utils.h"
#include "define.h"
#include "fun_all.h"
#include "fun_http.h"
#include "statis.h"


// TODO: mutil thread to process http
static pthread_t _http_thread_id[HTTP_PROCESS_THREADS];

static void* _valid_hosts = NULL;
pthread_mutex_t _host_ip_lock = PTHREAD_MUTEX_INITIALIZER;
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
// TODO: why?
static uint64_t g_nHttpLen = 0;
static int g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
static int g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
static int g_nHttpTimeout = HTTP_TIMEOUT;
// end.

static int g_nSendErrStateDataFlag = 1;

static struct http_session* _http_session = NULL;	// a session = query + reponse
static struct queue_t *_idl_session = NULL;			// all idl session
static struct queue_t *_whole_content = NULL;		// http_session.flag = HTTP_SESSION_FINISH
pthread_rwlock_t _working_session_lock = {0};
static struct queue_t *_working_session = NULL;

extern volatile int g_nFlagGetData;
extern volatile int g_nFlagSendData;

extern int _block_func_on;

// IDL -> REQUESTING -> REQUEST -> REPONSEING -> REPONSE -> FINISH
//           |------------|------------|------------------> TIMEOUT
volatile int _http_living = 1;
volatile time_t _http_active = 0;
static const unsigned _http_image = 0x50545448;
static const unsigned _get_image = 0x20544547;
static const unsigned _post_image = 0x54534F50;

// Content-Type: text/html; charset=gbk\r\n
// Content-Length: 26\r\n
// Content-Encoding: gzip\r\n
// Transfer-Encoding: chunked\r\n
static const char Content_Length[] = "content-length";
static const char Content_Type[] = "content-type";
static const char Content_Encoding[] = "content-encoding";
static const char Transfer_Encoding[] = "transfer-encoding";

struct _type_content_t {
	int type;
	char *content;
	int len;
};
// Notice: jscript,text => text/jscript, text/xxx
struct _type_content_t CONTENT_TYPE[] = {
	{ HTTP_CONTENT_JSCRIPT, "javascript", 10 },	// text/javascript
	{ HTTP_CONTENT_IMAGE, "image", 5 },		// image/git jpeg ico
	{ HTTP_CONTENT_HTML, "text", 4 },	// text/html text/xml text/plain
	{ HTTP_CONTENT_HTML, "json", 4},
	{ HTTP_CONTENT_HTML, "x-ami", 5 },	// application/x-ami
	{ HTTP_CONTENT_FILE, "application", 11},	// ignore next
	{ HTTP_CONTENT_FILE, "pdf", 3 },
	{ HTTP_CONTENT_FILE, "kdh", 3 },
	{ HTTP_CONTENT_FILE, "x-research-info-systems", 23},
	{ HTTP_CONTENT_FILE, "pdg", 3},
	{ HTTP_CONTENT_FILE, "x-ceb", 5},
	{ HTTP_CONTENT_FILE, "octet-stream", 12},
	{ HTTP_CONTENT_FILE, "x-download", 10},
	{ HTTP_CONTENT_FILE, "caj", 3},
	{ HTTP_CONTENT_FILE, "bibtex", 6},
	{ HTTP_CONTENT_FILE, "x-no-such-app", 13} // ...rtf ms-excel postscript ms-word
};
// #include "fun_http_sessions.inc"

// TODO: 
//
int isRelation(const struct iphdr *ip, const struct tcphdr *tcp, const struct http_session* session)
{
	// TODO
	return 1;
}

struct http_session* GetHttpSession(const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	return NULL;
}
///////////////////////////////////////////////////////////////
struct http_session* CleanHttpSession(struct http_session* pSession)
{
	LOGDEBUG("Session[%d] start clean!", pSession->index);
	
	//if (pSession->flag != HTTP_SESSION_IDL) 
	{
		unsigned index = pSession->index;
		void* packet = pSession->data;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGTRACE("Session[%d] clean packet data successfully!", pSession->index);
		
		packet = pSession->pack_later;
		while (packet!=NULL)
		{
			void* tmp = packet;
			packet = *(void**)packet;
			free(tmp);
		}

		LOGTRACE("Session[%d] clean packet_later data successfully!", pSession->index);
		
		if (pSession->request_head!=NULL) { free(pSession->request_head);}

		if (pSession->response_head!=NULL) { free(pSession->response_head);}
		// TODO: add by jrl why?
		//if (pSession->cur_content!=NULL) { free(pSession->cur_content); pSession->cur_content = NULL; }
		
		//if (pSession->part_content!=NULL) { free(pSession->part_content); pSession->part_content = NULL; }
		// END
		
		LOGTRACE("Session[%d] clean response_head successfully!", pSession->index);
		
		bzero(pSession, sizeof(*pSession));
		pSession->index = index;
		pSession->flag = HTTP_SESSION_IDL;
		
		push_queue(_idl_session, pSession);
	}

	LOGDEBUG("Session[%d] end clean!", pSession->index);
	return pSession;
}

void *_process_timeout(void* p)
{
	while (_http_living) {
		sleep(1);
		if (_http_active == 0) continue;

		for (int index = 0; index < g_nMaxHttpSessionCount; ++index)	{
			struct http_session* session = &_http_session[index];
			if ( session->flag < HTTP_SESSION_FINISH ) {
				if (_http_active-session->update.tv_sec > g_nHttpTimeout) {
					LOGWARN("http_session[%d] is timeout. %d - %d > %d flag=%d ", 
							index, _http_active, session->update, g_nHttpTimeout, session->flag);
					session->flag = HTTP_SESSION_TIMEOUT;
					push_queue(_whole_content, session);
					break;
				}
			}
		}
	}
	return NULL;
}
char* _IGNORE_EXT[] = { ".gif", ".js", ".js?", ".css" , ".jpg", ".ico", ".bmp", ".png" };
int NewHttpSession(const char* packet)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead=TCPHDR(iphead);
	unsigned contentlen = tcphead->window;
	char *content = (void*)tcphead + tcphead->doff*4;
	const char* cmdline = content;

	char* enter = strchr(content, '\r');
	if (enter == NULL) {
		enter = strchr(content, '\n');
		if (enter == NULL) return -1;	// TODO: wrong packet.
	}
	
	char tmp = *enter;
	int cmdlinen = enter-content;
	*enter = '\0';
	LOGTRACE("New http-session: %s", cmdline);
	//  reuse
	for (int n=0; n<g_nMaxHttpSessionCount; ++n){
		struct http_session* p = &_http_session[n];
		if (p->flag >= HTTP_SESSION_FINISH) continue;
		if (p->client.ip.s_addr == iphead->saddr && p->client.port==tcphead->source){
			p->flag = HTTP_SESSION_REUSED;
			push_queue(_whole_content, p);
			break;
		}
	}
	
	for (int n=0; n<sizeof(_IGNORE_EXT)/sizeof(char*); ++n) {
		if (strstr(cmdline, _IGNORE_EXT[n]) != NULL) return -3;	// TODO: ignore
	}
	*enter = tmp;

	struct http_session* pIDL = NULL;
LOOP_DEBUG:
	pIDL = (struct http_session*)pop_queue_timedwait(_idl_session);
	if (DEBUG && pIDL==NULL) {	goto LOOP_DEBUG; }	// For test
	if (pIDL == NULL) return -2;

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
	pIDL->contentlen = contentlen;
	pIDL->http_content_length = 0;
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
	if ((*(unsigned*)content==_get_image)
			&& content[contentlen-4]=='\r' && content[contentlen-3]=='\n'
			&& content[contentlen-2]=='\r' && content[contentlen-1]=='\n') {
		pIDL->flag = HTTP_SESSION_REQUEST;
	} else if ( *(unsigned*)content==_post_image ) {	// TODO: maybe bug. maybe not complete
		pIDL->flag = HTTP_SESSION_REQUEST;
	}

	// TODO:
	pIDL->prev = NULL;
	pIDL->next = NULL;
	pIDL->query_url.content = cmdline;
	pIDL->query_url.len = cmdlinen;
	if (FLOW_GET(packet)!=C2S) {
		char sip[32],dip[32];
		inet_ntop(AF_INET, &iphead->saddr, sip, sizeof(sip));
		inet_ntop(AF_INET, &iphead->daddr, dip, sizeof(dip));
		LOGERROR("client[%s:%u.%d] maybe server. => [%s:%u]", sip, ntohs(tcphead->source),
				FLOW_GET(packet), dip, ntohs(tcphead->dest));
	}
	LOGTRACE("Session[%d] NewHttpSession", pIDL->index);
	return pIDL->index;
}

int AppendServerToClient(int nIndex, const char* pPacket)
{ 
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	unsigned contentlen = tcphead->window;
	char *content = (void*)tcphead + tcphead->doff*4;
	struct http_session *pSession = &_http_session[nIndex];

	// TODO: not deal with wrong order. seq == ack_seq
	pSession->seq = tcphead->ack_seq;
	pSession->ack = tcphead->seq;
	pSession->contentlen = contentlen;
	pSession->update = *tv;

	// tcp
	if (tcphead->rst) {
		LOGTRACE("Session[%d] be reset.", index);
		pSession->flag = HTTP_SESSION_RESET;
		push_queue(_whole_content, pSession);
		if (contentlen > 0) { LOGERROR("Session[%d].len = %u. droped.", contentlen); }
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	} else if (tcphead->fin) {
		pSession->flag = HTTP_SESSION_FINISH;
		if (contentlen>0) {
			*(const char**)pPacket = NULL;
			*(const char**)pSession->lastdata = pPacket;
			pSession->lastdata = (void*)pPacket;
		} else {
			free((void*)pPacket);
		}
		push_queue(_whole_content, pSession);
		return HTTP_APPEND_SUCCESS;
	} else if (contentlen == 0) {
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	}
	// http
	if ((*(unsigned*)content == _http_image)) {
		pSession->flag = HTTP_SESSION_RESPONSEING;
		if (pSession->response_head==NULL) {
			pSession->response_head = (char*) malloc(RECV_BUFFER_LEN);
			if (pSession->response_head == NULL) {
				LOGERROR0("less memory.");
			}
		}
		char* p = memchr(content, '\r', contentlen);
		if (p==NULL) { 
			pSession->http.content = content;
			pSession->http.len = contentlen;
		} else {
			pSession->http.content = content;
			pSession->http.len = p-content;
		}
	}
	if (pSession->flag == HTTP_SESSION_RESPONSEING) {
		char* end = NULL;
		end = (char*)memmem(content, contentlen, "\r\n\r\n", 4);
		if (end != NULL) { 
			pSession->flag = HTTP_SESSION_REPONSE; 
		}
		if (pSession->response_head!=NULL) {	// no memory
			uint32_t clen = contentlen;
			if (end != NULL) { clen = end-content; }
			if (pSession->response_head_len+contentlen >= RECV_BUFFER_LEN) {
				LOGERROR0("Response-head is too longer. maybe wrong");
				clen = RECV_BUFFER_LEN-pSession->response_head_len-1;
			} 
			memcpy(pSession->response_head+pSession->response_head_len, content, clen);
			pSession->response_head_len += clen;
			pSession->response_head[pSession->response_head_len] = '\0';
		}
	}
	if (pSession->flag==HTTP_SESSION_REPONSE && pSession->response_head != NULL) {
		strlwr(pSession->response_head);
		// Process Content-Length and Transfer-Encoding
		char* content_length = (char*)memmem(pSession->response_head, pSession->response_head_len,
				Content_Length, sizeof(Content_Length)-1);
		if (content_length == NULL) { 
			char* trans_encoding = (char*)memmem(pSession->response_head, pSession->response_head_len,
					Transfer_Encoding, sizeof(Transfer_Encoding)-1);
			if (trans_encoding == NULL){
				LOGERROR("No Content-Length and Transfer-Encoding. \n%s", pSession->response_head); 
			}
			pSession->transfer_flag = HTTP_TRANSFER_CHUNKED;
		} else {
			pSession->http_content_length = strtoul(content_length, NULL, 10);
			ASSERT(pSession->http_content_length == 0);
			pSession->transfer_flag = HTTP_TRANSFER_HAVE_CONTENT_LENGTH;
		}
		char* content_type = (char*)memmem(pSession->response_head, pSession->response_head_len,
				Content_Type, sizeof(Content_Type)-1);
		if (content_type==NULL) { LOGINFO0("No Content-Type."); } else {
			char* lf = strchr(content_type, '\r');
			uint32_t len = lf==NULL? pSession->response_head_len-(content_type-pSession->response_head):(lf-content_type);
			char* type = content_type+sizeof(Content_Type)+1;
			for (int n=0; n < sizeof(CONTENT_TYPE)/sizeof(CONTENT_TYPE[0]); ++n){
				if (memmem(type, len, CONTENT_TYPE[n].content, CONTENT_TYPE[n].len)!=NULL) {
					pSession->content_type = CONTENT_TYPE[n].type;
					break;
				}
			}
		}
		// TODO: gzip
		// end gzip
		pSession->flag = HTTP_SESSION_REPONSE_ENTITY;
		*(const char**)pPacket = NULL;
		*(const char**)pSession->lastdata = pPacket;
		pSession->lastdata = (void*)pPacket;
		return HTTP_APPEND_SUCCESS;
	}
	// TODO: if HTTP_CONTENT_FILE, drop packet. 
	if (pSession->content_type>=HTTP_CONTENT_FILE){
		// TODO: Content-Length/Transfer-Encoding. HTTP_SESSION_FINISH
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	} else {
		*(const char**)pPacket = NULL;
		*(const char**)pSession->lastdata = pPacket;
		pSession->lastdata = (void*)pPacket;
		return HTTP_APPEND_SUCCESS;
	}
/**
	if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == pSession->transfer_flag)
//		|| HTTP_TRANSFER_NONE == pSession->transfer_flag)
	{
		if (pSession->res2 >= pSession->http_content_length) 
		{
			LOGDEBUG("Session[%d] end_reponse content-length/recv = %u/%u, content= %s", nIndex, pSession->http_content_length, pSession->res2, content);
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
	} **/

	return HTTP_APPEND_ADD_PACKET;
}

int AppendClientToServer(int nIndex, const char* pPacket)
{
	ASSERT(nIndex >= 0);
	
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = tcphead->window;
	const char *content = (void*)tcphead + tcphead->doff*4;
	struct http_session *pSession = &_http_session[nIndex];

	// tcp
	if (tcphead->rst) {
		LOGTRACE("Session[%d] be reset.", index);
		pSession->flag = HTTP_SESSION_RESET;
		push_queue(_whole_content, pSession);
		if (contentlen > 0) { LOGERROR("Session[%d].len = %u. droped.", contentlen); }
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	} else if (tcphead->fin) {
		pSession->flag = HTTP_SESSION_FINISH;
		if (contentlen>0) {
			*(const char**)pPacket = NULL;
			*(const char**)pSession->lastdata = pPacket;
			pSession->lastdata = (void*)pPacket;
		} else {
			free((void*)pPacket);
		}
		push_queue(_whole_content, pSession);
		return HTTP_APPEND_SUCCESS;
	} else if (contentlen == 0) {
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	}
	// HTTP
	if (pSession->flag != HTTP_SESSION_REQUESTING) {
		if (pSession->flag != HTTP_SESSION_REQUEST) {
			char sip[32], dip[32];
			LOGERROR("expect query[%u]. %s:%u.%u.%u -> %s:%u", pSession->flag,
					inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
					tcphead->seq, tcphead->ack_seq,
					inet_ntop(AF_INET, &iphead->daddr, dip, 32), ntohs(tcphead->dest));
			pSession->flag = HTTP_SESSION_REUSED;
			push_queue(_whole_content, pSession);
			free((void*)pPacket);
			return HTTP_APPEND_REUSE;
		} else {
			if (*(uint32_t*)pSession->query_url.content != _post_image) {
				char* tmp = (char*)alloca(pSession->query_url.len+1);
				memcpy(tmp, pSession->query_url.content, pSession->query_url.len+1);
				tmp[pSession->query_url.len] = '\0';
				LOGERROR("? [%s]. Current flag = %u", tmp, pSession->flag);
			}
		}
	}
	if (memmem(content, contentlen, "\r\n\r\n", 4)!=NULL) {
		pSession->flag = HTTP_SESSION_REQUEST;
	}

	pSession->seq = tcphead->seq;
	pSession->ack = tcphead->ack_seq;
	pSession->contentlen = contentlen;
	pSession->update = *tv;
	*(const char**)pPacket = NULL;
	*(const char**)pSession->lastdata = pPacket;
	pSession->lastdata = (void*)pPacket;

	return HTTP_APPEND_SUCCESS;
}

int AppendLaterPacket(int nIndex)
{
	ASSERT(nIndex >= 0);
	
	struct http_session *pSession = &_http_session[nIndex];
	void *pLaterPack = pSession->pack_later;
	
	if (pLaterPack != NULL)
	{
		LOGDEBUG("###########Start Process later packet list! index=%d", nIndex);
		
		void *pCurTmp = NULL, *pPreTmp = NULL;
		while (pLaterPack != NULL) 
		{
			pCurTmp = pLaterPack;
			pLaterPack = *(void**)pLaterPack;
			int nRs = AppendServerToClient(nIndex, pCurTmp);
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

int AppendResponse(const char* packet)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead = TCPHDR(iphead);
	struct http_session *pREQ = &_http_session[0];
	unsigned contentlen = tcphead->window;
	char *content = (void*)tcphead + tcphead->doff*4;
	if (contentlen==0 && !tcphead->fin && !tcphead->rst) {
		free((void*)packet);
		return HTTP_APPEND_SUCCESS;
	}
	int flow = FLOW_GET(packet);

	int index = 0;
	for (; index < g_nMaxHttpSessionCount; ++index) // TODO: MAX_HTTP_SESSION
	{
		pREQ = &_http_session[index];
		if (pREQ->flag == HTTP_SESSION_IDL || pREQ->flag >= HTTP_SESSION_FINISH) continue;

		int nRs = 0;
		if (pREQ->client.ip.s_addr == iphead->daddr && pREQ->client.port == tcphead->dest 
			&& pREQ->server.ip.s_addr == iphead->saddr && pREQ->server.port == tcphead->source) {
			// server -> client
			if (FLOW_GET(packet)!=S2C) {
				char sip[32],dip[32];
				inet_ntop(AF_INET, &iphead->saddr, sip, sizeof(sip));
				inet_ntop(AF_INET, &iphead->daddr, dip, sizeof(dip));
				LOGERROR("server[%s:%u.%u.%u.%u] maybe client. => [%s:%u]", sip, 
						ntohs(tcphead->source), tcphead->seq, tcphead->ack_seq,
					FLOW_GET(packet), dip, ntohs(tcphead->dest));
			}
			nRs = AppendServerToClient(index, packet);
			break;
		}
		else if (pREQ->client.ip.s_addr == iphead->saddr && pREQ->client.port == tcphead->source 
				 && pREQ->server.ip.s_addr == iphead->daddr && pREQ->server.port == tcphead->dest) { 
			// client -> server
			if (FLOW_GET(packet)!=C2S) {
				char sip[32],dip[32];
				inet_ntop(AF_INET, &iphead->saddr, sip, sizeof(sip));
				inet_ntop(AF_INET, &iphead->daddr, dip, sizeof(dip));
				LOGERROR("client[%s:%u.%d.%u.%u] maybe server. => [%s:%u]", sip, 
						ntohs(tcphead->source), tcphead->seq, tcphead->ack_seq,
					FLOW_GET(packet), dip, ntohs(tcphead->dest));
			}
			nRs = AppendClientToServer(index, packet);
			break;
		} 
	}
	if (index == g_nMaxHttpSessionCount) 
	{
		char sip[20], dip[20], stip[20], dtip[20];
		LOGINFO("packet drop. %s:%d.%u.%u => %s:%d\n%s", 
				inet_ntop(AF_INET, &iphead->saddr, stip, 20),  ntohs(tcphead->source),
				tcphead->seq, tcphead->ack_seq,
				inet_ntop(AF_INET, &iphead->daddr, dtip, 20),  ntohs(tcphead->dest),
				content);
		
		index = HTTP_APPEND_DROP_PACKET;
	}

	return index;
}

void *HTTP_Thread(void* param)
{
	while (_http_living) {
		const char* packet = pop_queue_timedwait(_packets);
		if (packet == NULL) { continue; }
		INC_POP_PACKETS;

		struct timeval *tv = (struct timeval*)packet;
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		iphead->tot_len = ntohs(iphead->tot_len);
		int contentlen = iphead->tot_len - iphead->ihl*4 - tcphead->doff*4;
		tcphead->window = contentlen;

		if (tcphead->syn&&contentlen<=0) { 
			free((void*)packet); 
			continue; 
		} 
		char *content = (void*)tcphead + tcphead->doff*4;
		// ntohl
		tcphead->seq = ntohl(tcphead->seq);
		tcphead->ack_seq = ntohl(tcphead->ack_seq);

		unsigned *cmd = (unsigned*)content;
		if ((*cmd == _get_image || *cmd == _post_image) && contentlen>0) {	// TODO: bug
			// TODO: need to process RST and FIN
			int nRes = NewHttpSession(packet);
			if (nRes == -1) {
				LOGERROR0("Query-Content is so short! Not insert into session.");
				free((void*)packet);
			} else if (nRes == -2) {
				INC_DROP_PACKET;
				char *enter = strchr(content, '\r');
				if (enter != NULL) {
					*enter = '\0';
					LOGWARN("_http_session is full. drop content = %s", content);
				} else {
					content[32] = '\0';
					LOGWARN("_http_session is full. drop content = %s", content);
				}
				free((void*)packet);
			}
			continue;
		}

		int nIndex = AppendResponse(packet);
		if (nIndex == HTTP_APPEND_DROP_PACKET) {
			LOGDEBUG0("cannt find session");
		}
	}
	printf("Exit http thread.\n");
	return NULL;
}

int HttpStop()
{
	while (DEBUG) {	// TODO: I want to process all packets.
		if (len_queue(_packets)==0 && len_queue(_whole_content)==0) break;
		sleep(1);
	}
	_http_living = 0;
	void *retvl = NULL;
	for (int n=0; n<HTTP_PROCESS_THREADS; ++n) {
		int err = pthread_join(_http_thread_id[n], &retvl);
	}
	return 0;
}

int HttpInit()
{
	ASSERT(_packets == NULL);
	ASSERT(_http_session == NULL);

	char szSendErrStateDataFlag[10] = {0};
	if (GetValue(CONFIG_PATH, "SendErrStateDataFlag", szSendErrStateDataFlag, 2) != NULL)
		g_nSendErrStateDataFlag = atoi(szSendErrStateDataFlag);
	
	char szMaxSessionCount[10] = {0};
	char szMaxPacketCount[10] = {0};
	char szHttpTimeout[10] = {0};
	GetValue(CONFIG_PATH, "max_session_count", szMaxSessionCount, 6);
	GetValue(CONFIG_PATH, "max_packet_count", szMaxPacketCount, 6);
	GetValue(CONFIG_PATH, "http_timeout", szHttpTimeout, 3);
	
	g_nMaxHttpSessionCount = atoi(szMaxSessionCount);
	if (g_nMaxHttpSessionCount < 500 || g_nMaxHttpSessionCount > 100000)
		g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
	
	g_nMaxHttpPacketCount = atoi(szMaxPacketCount);
	if (g_nMaxHttpPacketCount < 1000 || g_nMaxHttpPacketCount > 200000)
		g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
	
	g_nHttpTimeout = atoi(szHttpTimeout);
	if (g_nHttpTimeout < 10 || g_nHttpTimeout > 600)
		g_nHttpTimeout = HTTP_TIMEOUT;

	printf("max_http_session_count = %d\n", g_nMaxHttpSessionCount);
	printf("max_http_packet_count = %d\n", g_nMaxHttpPacketCount);
	printf("max_http_timeout = %d\n", g_nHttpTimeout);
		
	_packets = init_queue(g_nMaxHttpPacketCount);
	ASSERT(_packets != NULL);
	_http_session = calloc(sizeof(_http_session[0]), g_nMaxHttpSessionCount);
	ASSERT(_http_session != NULL);
	_whole_content = init_queue(g_nMaxHttpSessionCount);
	ASSERT(_whole_content != NULL);
	_idl_session = init_queue(g_nMaxHttpSessionCount);
	ASSERT(_idl_session != NULL);
	_working_session = init_queue(g_nMaxHttpSessionCount);
	ASSERT(_working_session != NULL);
	int err = pthread_rwlock_init(&_working_session_lock, NULL);
	ASSERT(err == 0);
	//err = http_sessions_init();
	//ASSERT(err == 0);
	//_use_session = init_queue(g_nMaxHttpSessionCount);
	//ASSERT(_use_session != NULL);

	for (size_t index = 0; index < g_nMaxHttpSessionCount; ++index) {
		_http_session[index].index = index;
		push_queue(_idl_session, &_http_session[index]);
	}

	pthread_attr_t pattr;
	struct sched_param par = { sched_get_priority_max(SCHED_FIFO) };
	ASSERT(pthread_attr_init(&pattr) == 0);
	ASSERT(pthread_attr_setschedpolicy(&pattr, SCHED_FIFO) == 0);
	ASSERT(pthread_attr_setschedparam(&pattr, &par) == 0);
	for (int n=0; n<HTTP_PROCESS_THREADS; ++n) {
		int err = pthread_create(&_http_thread_id[n], &pattr, &HTTP_Thread, (void*)&_http_living);
		ASSERT(err >= 0);
	}
	pthread_attr_destroy(&pattr);

	return _packets==NULL? -1:0;
}


int PushHttpPack(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{	
	struct timeval *tv = (struct timeval*)buffer;
	gettimeofday(tv, NULL);
	int err = 0;
DEBUG_LOOP:
	err = push_queue(_packets, (const void*) buffer);
	if (err < 0) {
		if (DEBUG) {
			sleep(0);
			goto DEBUG_LOOP;
		} else {
			LOGWARN("http_queue is full. drop the packets, drop count = %d", ++g_nDropCountForPacketFull);
		}
	} else {
		INC_PUSH_PACKETS;
	}

	return err;
}

/// buffer is http return 0. other return -1;
int FilterPacketForHttp(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{
	int nRs = -1;

	struct hosts_t host = { {iphead->saddr}, tcphead->source };
	struct hosts_t host1 = { {iphead->daddr}, tcphead->dest};
	pthread_mutex_lock(&_host_ip_lock);
	
	if (inHosts(_valid_hosts, &host)!=NULL ) {
		nRs = PushHttpPack(buffer, iphead, tcphead);
		FLOW_SET(buffer, S2C);
	} else if (inHosts(_valid_hosts, &host1)!=NULL) {
		nRs = PushHttpPack(buffer, iphead, tcphead);
		FLOW_SET(buffer, C2S);
	}

	if (nRs == -1) {
		struct in_addr sip, dip; 

		sip.s_addr = iphead->saddr;
		dip.s_addr = iphead->daddr;
		char ssip[16], sdip[16];
		LOGINFO("%s => %s is skiped.", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
	}
	pthread_mutex_unlock(&_host_ip_lock);
	return nRs;
}

// Load rule from config.
int LoadHttpConf(const char* filename)
{
	// dont support reload in runing...
	ASSERT((NULL == _valid_hosts));
	// capture these hosts
	char *left, *right, *ipport;
	int n = 0, nDataLen = 0;

	char* pFileData = (char*)calloc(1, VALUE_LENGTH_MAX+1);
	ASSERT(pFileData != NULL);
	
	char* httphosts = pFileData;

	nDataLen = GetFileData(HTTP_HOST_PATH_FILE, httphosts, VALUE_LENGTH_MAX);
	// TODO:
	_valid_hosts = LoadHost(httphosts);
	ASSERT( _valid_hosts != NULL );

	free(pFileData);
	return 0;
}

int TransGzipData(const char *pGzipData, int nDataLen, char **pTransData)
{	// TODO: gzip 
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
	if (_whole_content == NULL) return 0;
	struct http_session *pSession = (struct http_session*)pop_queue(_whole_content);
	if (pSession == NULL) return 0;
	
	INC_WHOLE_HTML_SESSION;
	
	if (pSession->flag < HTTP_SESSION_FINISH) {
		LOGFATAL("Session.flag=%d. want HTTP_SESSION_FINISH", pSession->flag);
		// TODO: uncomplete session
		CleanHttpSession(pSession);
		return 0;
	}
	size_t http_len = 0;
	assert(pSession->data != NULL);

	// get all http_content len
	unsigned transfer_flag = pSession->transfer_flag;
	void* packet = pSession->data;
	do {
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = tcphead->window;
		assert(iphead->tot_len - iphead->ihl*4 - tcphead->doff*4==contentlen);
		http_len += contentlen;
		//const char *content = (void*)tcphead + tcphead->doff*4;
		packet = *(void**)packet;
	} while (packet!=NULL);

	// malloc
	unsigned data_len = http_len+35+10+26+26+5+1;
	char* http_content = (char*)calloc(1, data_len);
	if (http_content == NULL) {
		push_queue(_whole_content, pSession);
		*data = NULL;
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
	{
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		const char *content = (void*)tcphead + tcphead->doff*4;
		if (*(uint32_t*)content!=_get_image && *(uint32_t*)content!=_post_image) {
			char sip[32],dip[32];
			LOGERROR("not GET and POST. session[%u] %s:%u.%u.%u -> %s:%u", pSession->index, 
					inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
					tcphead->seq, tcphead->ack_seq,
					inet_ntop(AF_INET, &iphead->daddr, dip,322), ntohs(tcphead->dest));
		}
	}
	do {
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = tcphead->window;
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
		if (HTTP != NULL) HTTP += 4;
	} else if (*(unsigned*)HTTP == _post_image) {
		char* query_len = strstr(HTTP, "Content-Length:");
		int query_length = 0;
		if (query_len != NULL)
			query_length = strtol(query_len+15, NULL, 10);

		char* HTTP_pre = HTTP;
		HTTP = strstr(HTTP, "\r\n\r\n");	// skip query
		if (HTTP != NULL) {
			if (0 == pSession->request_head_len_valid_flag) {
				HTTP += 4 + query_length;
			} else {
				HTTP = HTTP_pre + pSession->request_head_len - 1;
			}
		}
	} else {
		LOGERROR("No GET or POST. [%u]%s", pSession->index, HTTP_PRE);
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
			{	// TODO: Proc chunk
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
			nContentLength = pSession->http_content_length;
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
			if (HTTP_CONTENT_FILE <= pSession->content_type)
				strcpy(szEmptyHtml, "<html><head><title>a file</title></head><body></body></html>\r\n");
			
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
			// LOGWARN("Session[%d] has not content-Length or is 0, current content = %s", pSession->index, HTTP);
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

