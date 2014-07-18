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
static struct http_session *_working_session = NULL;

extern volatile int g_nFlagGetData;
extern volatile int g_nFlagSendData;

extern int _block_func_on;

// IDL -> REQUESTING -> REQUEST -> REPONSEING -> REPONSE -> FINISH
//           |------------|------------|------------------> TIMEOUT
volatile int _http_living = 1;
time_t _http_active = 0;

char* _IGNORE_EXT[] = { ".gif", ".js?", ".css" , ".jpg", ".ico", ".bmp", ".png" };
static const uint32_t _http_image = 0x50545448;
static const uint32_t _get_image = 0x20544547;
static const uint32_t _post_image = 0x54534F50;
static const uint32_t _options_image = 0x4954504F;
static const uint32_t _head_image = 0x44414548;
static const uint32_t _put_image = 0x20545550;
static const uint32_t _delete_image = 0x454C4544;
static const uint32_t _trace_image = 0x43415254;

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
//////////////////////////// util
const void* _insert_into_session(struct http_session* session, const char* packet);
const void* _get_content_from_packet(const void* packet)
{
	assert(packet!=NULL);
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead=TCPHDR(iphead);
	unsigned contentlen = tcphead->window;
	if (contentlen==0) return NULL;
	char *content = (void*)tcphead + tcphead->doff*4;
	return content;
}
const void* _get_content_from_tcphdr(const struct tcphdr* hdr)
{
	unsigned contentlen = hdr->window;
	if (contentlen==0) return NULL;
	char *content = (void*)hdr + hdr->doff*4;
	return content;
}
void _add_finish_session(struct http_session* session, int http_session_flag)
{
	session->flag = HTTP_SESSION_FINISH;
	push_queue(_whole_content, session);
}
struct http_session* _get_idl_session(int wait)
{
	struct http_session* p = (struct http_session*)pop_queue_timedwait(_idl_session);
	while (p==NULL && wait) {
		p = (struct http_session*)pop_queue_timedwait(_idl_session);
	}
	return p;
}
uint32_t _check_http_or_query(const void* content)
{
	uint32_t image = *(uint32_t *)content;
	switch(image) {
		case _head_image:
			return 3;
			break;
		case _get_image:
		case _post_image:
			return 2;
			break;
		case _options_image:
		case _trace_image:
		case _put_image:
		case _delete_image:
			return 1;
			break;
		default:
			return 0;
	}
	assert(0);
	return 0;
}
void _append_packet_to_session(struct http_session* session, void* packet)
{
	struct iphdr* ip = IPHDR(packet);
	struct tcphdr* tcp=TCPHDR(ip);
	int flow = FLOW_GET(tcp);
	assert(CONTENT_LEN_GET(tcp) > 0);

	session->update = *(struct timeval*)packet;
	if (flow==S2C) {
		session->seq = tcp->ack_seq;
		session->ack = tcp->seq;
	} else if (flow==C2S) {
		session->seq = tcp->seq;
		session->ack = tcp->ack_seq;
	} else {
		assert(0);
	}
	session->contentlen = CONTENT_LEN_GET(tcp);
	*(void**)packet = NULL;
	*(void**)session->lastdata = packet;
	session->lastdata = packet;
	++session->packet_num;
}
///////////////////////////////////////////////////////////////
void CleanPacketList(void* packet)
{
	while (packet!=NULL) {
		void* tmp = packet;
		packet = *(void**)packet;
		free(tmp);
	}
}
struct http_session* CleanHttpSession(struct http_session* pSession)
{
	assert(pSession->flag!=HTTP_SESSION_IDL);
	
	unsigned index = pSession->index;
	CleanPacketList(pSession->data);

	bzero(pSession, sizeof(*pSession));
	pSession->index = index;
	pSession->flag = HTTP_SESSION_IDL;
	
	push_queue(_idl_session, pSession);
	return pSession;
}

void *_process_timeout(void* p)
{
	int broken_time = 1;
	if (DEBUG) broken_time = 100;

	while (_http_living) {
		sleep(1);
		if (_http_active == 0) continue;

		for (int index = 0; index < g_nMaxHttpSessionCount; ++index)	{
			struct http_session* session = &_http_session[index];
			if ( session->flag>HTTP_SESSION_IDL && session->flag<HTTP_SESSION_FINISH ) {
				if (_http_active-session->update.tv_sec > g_nHttpTimeout) {
					LOGINFO("http_session[%d] is timeout. %d - %d > %d flag=%d ", 
							index, _http_active, session->update.tv_sec, g_nHttpTimeout, session->flag);
					session->flag = HTTP_SESSION_TIMEOUT;
					push_queue(_whole_content, session);
				}
			} else if (session->flag == HTTP_SESSION_BROKEN) {
				if (_http_active-session->update.tv_sec > broken_time) {
					LOGINFO("http_session[%d] is timeout. %d - %d > %d flag=%d ", 
							index, _http_active, session->update.tv_sec, g_nHttpTimeout, session->flag);
					push_queue(_whole_content, session);
				}
			}
		}
	}
	return NULL;
}
// only the packet from client can create new session.
void _init_new_http_session( struct http_session* pIDL, const char* packet)
{
	struct timeval *tv = (struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead=TCPHDR(iphead);
	unsigned contentlen = CONTENT_LEN_GET(tcphead);
	assert(contentlen>0);
	assert(FLOW_GET(tcphead) == C2S);

	pIDL->flag = HTTP_SESSION_NEW;
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
	pIDL->packet_num = 1;
	pIDL->contentlen = contentlen;
	pIDL->http_content_length = 0;
	pIDL->http_content_remain = 0;
	pIDL->content_type = HTTP_CONTENT_NONE;
	*(const char**)packet = NULL;
	// TODO:
	pIDL->prev = NULL;
	pIDL->next = NULL;
	LOGTRACE("Session[%d] NewHttpSession.%u.", pIDL->index, FRAME_NUM_GET(packet));
}
// only client tcphead
struct http_session* FindSession(uint32_t ip, uint16_t port)
{
	for (int n=0; n<g_nMaxHttpSessionCount; ++n){
		struct http_session* p = &_http_session[n];
		if (p->flag == HTTP_SESSION_IDL) continue;
		if (p->flag >= HTTP_SESSION_FINISH) continue;
		if (p->client.ip.s_addr == ip && p->client.port==port){
			return p;
		}
	}
	return NULL;
}
int NewHttpSessionWithQuery(const char* packet)
{
	struct timeval tv = *(struct timeval*)packet;
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead=TCPHDR(iphead);
	unsigned contentlen = CONTENT_LEN_GET(tcphead);
	char *content = (void*)tcphead + tcphead->doff*4;
	assert(contentlen>0 && contentlen<RECV_BUFFER_LEN);
	assert(FLOW_GET(tcphead) == C2S);
	int special = 0;

	// reuse and resend
	struct http_session* p = FindSession(iphead->saddr, tcphead->source);
	if (p != NULL) {	// focus order
		if (p->seq+p->contentlen == tcphead->seq) {
			p->flag = HTTP_SESSION_FINISH;
			push_queue(_whole_content, p);
		} else if (p->seq+p->contentlen < tcphead->seq) {
			p->flag = HTTP_SESSION_BROKEN;
		} else if (p->seq > tcphead->seq) { // fix order or resend
			void* prev = (void*)_insert_into_session(p, packet); 
			if (prev == packet) return -3;	// resend
			if (prev == NULL) {		// head
				++p->packet_num;
				return p->index;
			}
			// GET .... GET ...
			*(void**)prev = NULL;
			p->lastdata = prev;
			p->flag = HTTP_SESSION_FINISH;
			push_queue(_whole_content, p);
			special = 1;
		}
	}
	/*for (int n=0; n<sizeof(_IGNORE_EXT)/sizeof(char*); ++n) {
		if (strstr(cmdline, _IGNORE_EXT[n]) != NULL) return -3;	// TODO: ignore
	}*/
	char sip[16], dip[16];
	LOGINFO("New session.%u.[%s:%u->%s:%u]", FRAME_NUM_GET(packet),
			inet_ntop(AF_INET, &iphead->saddr, sip, 16), ntohs(tcphead->source),
			inet_ntop(AF_INET, &iphead->daddr, dip, 16), ntohs(tcphead->dest));
	
	struct http_session* pIDL = NULL;
	do { pIDL = (struct http_session*)pop_queue_timedwait(_idl_session); } while (DEBUG && pIDL==NULL);	// For test
	if (pIDL == NULL) {
		CleanPacketList((void*)packet);
		return -4;
	}
	void *pSpecial = *(void**)packet;	// next packet in special
	if (special) { *(struct timeval*)packet = tv; };
	_init_new_http_session(pIDL, packet);
	if (special) {
		*(void**)packet = pSpecial;
		while (*(void**)pIDL->lastdata != NULL) { 
			pIDL->lastdata = *(void**)pIDL->lastdata; 
			++pIDL->packet_num;
		}
	}
	// only for query
	pIDL->query = content;
	pIDL->flag = HTTP_SESSION_REQUESTING;
	return pIDL->index;
}

// return NULL: session->head packet: resend other: prev
const void* _insert_into_session(struct http_session* session, const char* packet)
{
	ASSERT(session!=NULL);
	struct iphdr *iphead = IPHDR(packet);
	struct tcphdr *tcphead = TCPHDR(iphead);
	unsigned contentlen = tcphead->window;
	ASSERT(contentlen > 0);

	const char* head = session->data;
	const char* next = head;
	const char* prev = NULL;
	struct iphdr *next_ip ;
	struct tcphdr *next_tcp ;
	unsigned next_content_len ;
	char sip[32], dip[32];
	for (; next!=NULL; next=*(const char**)next) {
		next_ip = IPHDR(next);
		next_tcp = TCPHDR(next_ip);
		next_content_len = next_tcp->window;

		if (FLOW_GET(tcphead)==FLOW_GET(next_tcp) && (tcphead->seq == next_tcp->seq)) { // resend
				LOGDEBUG("Resend. Session[%u].%u packet.%s:%u.%u.%u.%u.%u => %s:%u", 
						session->index,FRAME_NUM_GET(packet), 
						inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
						contentlen, tcphead->seq, tcphead->ack_seq, FLOW_GET(tcphead),
						inet_ntop(AF_INET, &iphead->daddr, dip, 32), ntohs(tcphead->dest));
				LOGDEBUG("Resend. Session[%u].%u next.%s:%u.%u.%u.%u.%u => %s:%u", 
						session->index,FRAME_NUM_GET(packet), 
						inet_ntop(AF_INET, &next_ip->saddr, sip, 32), ntohs(next_tcp->source),
						next_content_len, next_tcp->seq, next_tcp->ack_seq, FLOW_GET(next_tcp),
						inet_ntop(AF_INET, &next_ip->daddr, dip, 32), ntohs(next_tcp->dest));
				LOGINFO("Drop packet - Resend. Session[%u]", session->index);
				return packet;
		} else if (FLOW_GET(tcphead)==FLOW_GET(next_tcp) && tcphead->seq < next_tcp->seq) {	// out of order
				LOGDEBUG("Fix order. Session[%u].%u packet.%s:%u.%u.%u.%u.%u => %s:%u", 
						session->index,FRAME_NUM_GET(packet), 
						inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
						contentlen, tcphead->seq, tcphead->ack_seq, FLOW_GET(tcphead),
						inet_ntop(AF_INET, &iphead->daddr, dip, 32), ntohs(tcphead->dest));
				LOGDEBUG("Fix order. Session[%u].%u next.%s:%u.%u.%u.%u.%u => %s:%u", 
						session->index,FRAME_NUM_GET(packet), 
						inet_ntop(AF_INET, &next_ip->saddr, sip, 32), ntohs(next_tcp->source),
						next_content_len, next_tcp->seq, next_tcp->ack_seq, FLOW_GET(next_tcp),
						inet_ntop(AF_INET, &next_ip->daddr, dip, 32), ntohs(next_tcp->dest));
				if (prev == NULL) {
					*(const char**)packet = next;
					session->data = (void*)packet;
				} else {
					*(const char**)prev = packet;
					*(const char**)packet = next;
				}
				++session->packet_num;
				return prev;
				break;
		} else if (FLOW_GET(tcphead)!=FLOW_GET(next_tcp) && (tcphead->seq+tcphead->window <= next_tcp->ack_seq)) { 
			// out of order
			LOGDEBUG("Fix order. Session[%u].%u packet.%s:%u.%u.%u.%u.%u => %s:%u", 
					 session->index,FRAME_NUM_GET(packet),
					inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
					contentlen, tcphead->seq, tcphead->ack_seq, FLOW_GET(tcphead),
					inet_ntop(AF_INET, &iphead->daddr, dip, 32), ntohs(tcphead->dest));
			LOGDEBUG("Fix order. Session[%u].%u next.%s:%u.%u.%u.%u.%u => %s:%u", 
					session->index,FRAME_NUM_GET(packet), 
					inet_ntop(AF_INET, &next_ip->saddr, sip, 32), ntohs(next_tcp->source),
					next_content_len, next_tcp->seq, next_tcp->ack_seq, FLOW_GET(next_tcp),
					inet_ntop(AF_INET, &next_ip->daddr, dip, 32), ntohs(next_tcp->dest));
			if (prev == NULL) {
				*(const char**)packet = next;
				session->data = (void*)packet;
			} else {
				*(const char**)prev = packet;
				*(const char**)packet = next;
			}
			++session->packet_num;
			return prev;
			break;
		}
		prev = next;
	}
	ASSERT(next_tcp!=NULL);
	return packet;
}

int AppendServerToClient(struct http_session* pSession, const char* pPacket)
{ 
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	unsigned contentlen = CONTENT_LEN_GET(tcphead);
	char *content = (void*)tcphead + tcphead->doff*4;
	assert(FLOW_GET(tcphead) == S2C);

	if (contentlen>0 && tcphead->seq<pSession->ack) {
		if (pSession->content_type >= HTTP_CONTENT_FILE) {
			// Nothing todo. it will be drop
			if (pSession->content_type==HTTP_CONTENT_STREAM) {
				free((void*)pPacket);
				++pSession->packet_num;
				return HTTP_APPEND_SUCCESS;
			}
		} else {
			const void* p = _insert_into_session(pSession, pPacket);
		   	if (p==NULL){ LOGFATAL0("Cannt get here"); }
			if (p==pPacket) return HTTP_APPEND_FAIL;	// resend
			return HTTP_APPEND_SUCCESS;
		}
	} else if (contentlen==0 && tcphead->seq<pSession->ack) {
		// nothing. wait for free
	} else {
		pSession->seq = tcphead->ack_seq;
		pSession->ack = tcphead->seq;
		pSession->contentlen = contentlen;
		pSession->update = *tv;
	}

	// tcp
	if (tcphead->rst) {
		LOGTRACE("Session[%d] be reset.", index);
		pSession->flag = HTTP_SESSION_RESET;
		push_queue(_whole_content, pSession);
		if (contentlen > 0) { LOGERROR("Session[%d].len = %u. .%u.droped.", index, contentlen, FRAME_NUM_GET(pPacket)); }
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
	if (pSession->flag<HTTP_SESSION_RESPONSEING && (*(unsigned*)content==_http_image)) {
		pSession->http = content;
		pSession->flag = HTTP_SESSION_RESPONSEING;
		if (pSession->response_head==NULL) {
			pSession->response_head = (char*) malloc(RECV_BUFFER_LEN);
			if (pSession->response_head == NULL) { LOGERROR0("less memory."); }
		}
	}
	if (pSession->flag == HTTP_SESSION_RESPONSEING) {
		char* end = (char*)memmem(content, contentlen, "\r\n\r\n", 4);
		if (end != NULL) { pSession->flag = HTTP_SESSION_REPONSE; }
		if (pSession->response_head!=NULL) {	// no memory
			uint32_t clen = contentlen;
			if (end != NULL) { clen = end-content; }
			if (pSession->response_head_len+contentlen >= RECV_BUFFER_LEN) {
				LOGERROR0("Response-head is too longer. maybe wrong");
				clen = RECV_BUFFER_LEN-pSession->response_head_len;
			} 
			memcpy(pSession->response_head+pSession->response_head_len, content, clen);
			pSession->response_head_len += clen;
			pSession->response_head[pSession->response_head_len] = '\0';
		}
	}
	if (pSession->flag==HTTP_SESSION_REPONSE && pSession->response_head != NULL) {
		pSession->flag = HTTP_SESSION_REPONSE_ENTITY;
		strlwr(pSession->response_head);
		// Process Content-Length and Transfer-Encoding
		char* content_length = (char*)memmem(pSession->response_head, pSession->response_head_len,
				Content_Length, sizeof(Content_Length)-1);
		if (content_length == NULL) {	// Transfer-Encoding: Chunked
			char* trans_encoding = (char*)memmem(pSession->response_head, pSession->response_head_len,
					Transfer_Encoding, sizeof(Transfer_Encoding)-1);
			if (trans_encoding == NULL){	// 304 or ...
				LOGINFO("No Content-Length and Transfer-Encoding. \n%s", pSession->response_head); 
				pSession->transfer_flag = HTTP_TRANSFER_OTHER;
			} else {
				pSession->transfer_flag = HTTP_TRANSFER_CHUNKED;
			}
		} else {	// Content-Length
			pSession->http_content_length = strtoul(content_length, NULL, 10);
			ASSERT(pSession->http_content_length == 0);
			pSession->transfer_flag = HTTP_TRANSFER_HAVE_CONTENT_LENGTH;
		}
		char* content_type = (char*)memmem(pSession->response_head, pSession->response_head_len,
				Content_Type, sizeof(Content_Type)-1);
		if (content_type==NULL) { 
			LOGDEBUG0("No Content-Type."); 
		} else {
			char* lf = strchr(content_type, '\r');
			uint32_t len = lf==NULL? pSession->response_head_len-(content_type-pSession->response_head):(lf-content_type);
			char* type = content_type+sizeof(Content_Type);
			for (int n=0; n < sizeof(CONTENT_TYPE)/sizeof(CONTENT_TYPE[0]); ++n){
				if (memmem(type, len, CONTENT_TYPE[n].content, CONTENT_TYPE[n].len)!=NULL) {
					pSession->content_type = CONTENT_TYPE[n].type;
					break;
				}
			}
		}
		char* content_encoding = (char*)memmem(pSession->response_head, pSession->response_head_len,
				Content_Encoding, sizeof(Content_Encoding)-1);
		if (content_encoding == NULL) { LOGDEBUG0("No Content-Encoding."); } else {
			char *type = content_encoding+sizeof(Content_Encoding)+1;
			if (memmem(type, 10, "gzip", 4) != NULL)
				pSession->content_encoding = HTTP_CONTENT_ENCODING_GZIP;
			else if (memmem(type, 10, "deflate", 7) != NULL)
				pSession->content_encoding = HTTP_CONTENT_ENCODING_DEFLATE;
			else 
				pSession->content_encoding = HTTP_CONTENT_ENCODING_COMPRESS;
		}
		*(const char**)pPacket = NULL;
		*(const char**)pSession->lastdata = pPacket;
		pSession->lastdata = (void*)pPacket;
		++pSession->packet_num;
		return HTTP_APPEND_SUCCESS;
	}
	// TODO: if HTTP_CONTENT_FILE, drop packet. 
	switch (pSession->content_type) {
		case HTTP_CONTENT_FILE:
		case HTTP_CONTENT_JSCRIPT:
		case HTTP_CONTENT_IMAGE:
		case HTTP_CONTENT_RES:
		case HTTP_CONTENT_FILE_PDF:
		case HTTP_CONTENT_FILE_KDH:
		case HTTP_CONTENT_FILE_CEB:
		case HTTP_CONTENT_FILE_CAJ:
		case HTTP_CONTENT_FILE_MARC:
		case HTTP_CONTENT_FILE_RIS:
		case HTTP_CONTENT_FILE_BIB:
		case HTTP_CONTENT_FILE_TXT:
		case HTTP_CONTENT_FILE_PDG:
		case HTTP_CONTENT_FILE_EXCEL:
		case HTTP_CONTENT_FILE_RTF:
		case HTTP_CONTENT_FILE_OTHER:
		case HTTP_CONTENT_STREAM:
			free((void*)pPacket);
			++pSession->packet_num;
			return HTTP_APPEND_SUCCESS;
		case HTTP_CONTENT_NONE:
		case HTTP_CONTENT_HTML:
		default:
			*(const char**)pPacket = NULL;
			*(const char**)pSession->lastdata = pPacket;
			pSession->lastdata = (void*)pPacket;
			++pSession->packet_num;
			if (pSession->packet_num>10&&pSession->flag==HTTP_SESSION_NEW) {
				pSession->content_type=HTTP_CONTENT_STREAM;
			}
			return HTTP_APPEND_SUCCESS;
	}

	return HTTP_APPEND_SUCCESS;
}

int AppendClientToServer(struct http_session* pSession, const char* pPacket)
{
	struct timeval *tv = (struct timeval*)pPacket;
	struct iphdr *iphead = IPHDR(pPacket);
	struct tcphdr *tcphead = TCPHDR(iphead);
	int contentlen = tcphead->window;
	const char *content = (void*)tcphead + tcphead->doff*4;
	assert(FLOW_GET(tcphead)==C2S);

	if (contentlen>0 && tcphead->seq<pSession->seq) {
		const void * p = _insert_into_session(pSession, pPacket);
		if (pPacket != p) {
			return HTTP_APPEND_SUCCESS;
		} else { // resend
			return HTTP_APPEND_FAIL;
		}
	} else if (contentlen==0 && tcphead->seq<pSession->seq) {
		// nothing
	} else {
		pSession->seq = tcphead->seq;
		pSession->ack = tcphead->ack_seq;
		pSession->contentlen = contentlen;
		pSession->update = *tv;
	}

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
			++pSession->packet_num;
		} else {
			free((void*)pPacket);
		}
		push_queue(_whole_content, pSession);
		return HTTP_APPEND_SUCCESS;
	} else if (contentlen == 0) {
		free((void*)pPacket);
		return HTTP_APPEND_SUCCESS;
	}
	/* HTTP something like put will append this session.
	if (pSession->flag != HTTP_SESSION_REQUESTING) {
		if (pSession->flag != HTTP_SESSION_REQUEST) {
			char sip[32], dip[32];
			LOGERROR("expect query[%u]. %s:%u.%u.%u.%u -> %s:%u", pSession->flag,
					inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
					tcphead->seq, tcphead->ack_seq, tcphead->window,
					inet_ntop(AF_INET, &iphead->daddr, dip, 32), ntohs(tcphead->dest));
			pSession->flag = HTTP_SESSION_REUSED;
			push_queue(_whole_content, pSession);
			free((void*)pPacket);
			return HTTP_APPEND_REUSE;
		}
	}*/
	if (pSession->flag<HTTP_SESSION_REQUEST && memmem(content, contentlen, "\r\n\r\n", 4)!=NULL) {
		pSession->flag = HTTP_SESSION_REQUEST;
	}

	pSession->seq = tcphead->seq;
	pSession->ack = tcphead->ack_seq;
	pSession->contentlen = contentlen;
	pSession->update = *tv;
	*(const char**)pPacket = NULL;
	*(const char**)pSession->lastdata = pPacket;
	pSession->lastdata = (void*)pPacket;
	++pSession->packet_num;

	return HTTP_APPEND_SUCCESS;
}

void *HTTP_Thread(void* param)
{
	while (_http_living) {
		char* packet = (char*)pop_queue_timedwait(_packets);
		if (packet == NULL) { continue; }
		INC_POP_PACKETS;

		struct timeval *tv = (struct timeval*)packet;
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		iphead->tot_len = ntohs(iphead->tot_len);
		int contentlen = iphead->tot_len - iphead->ihl*4 - tcphead->doff*4;
		if (contentlen==1) { contentlen = 0; }
		CONTENT_LEN_SET(tcphead, contentlen);
		_http_active = tv->tv_sec;
		assert(contentlen<1600);	// TODO: for test

		if ((contentlen==0&&!tcphead->fin&&!tcphead->rst) || contentlen>=RECV_BUFFER_LEN) { 
			free((void*)packet); 
			continue; 
		} 
		char *content = (void*)tcphead + tcphead->doff*4;
		// ntohl
		tcphead->seq = ntohl(tcphead->seq);
		tcphead->ack_seq = ntohl(tcphead->ack_seq);

		if (FLOW_GET(tcphead)==C2S) {
			struct http_session* session = FindSession(iphead->saddr, tcphead->source);
			if (session) {
				if (tcphead->rst) {	// reuse
					assert(contentlen==0);
					_add_finish_session(session, HTTP_SESSION_RESET);
					free((void*)packet);
				} else if (tcphead->fin) {
					assert(contentlen==0);
					_add_finish_session(session, HTTP_SESSION_FINISH);
					free((void*)packet);
				} else {	// maybe insert
					if (tcphead->seq < session->seq) {
						if (_insert_into_session(session, packet)==packet){ // resend
							free((void*)packet);
							continue;
						}
						if (session->query_image == 0) {
							if ((session->query_image=_check_http_or_query(content))) {
								session->flag = HTTP_SESSION_REQUESTING;
								session->query= content;
							}
						}
						continue;
					} else if (tcphead->seq == session->seq) { // resend
						free((void*)packet);
						continue;
					} else {	// new, so end prev. or query0 + query1
						struct iphdr* lip = IPHDR(session->lastdata);
						struct tcphdr* ltcp=TCPHDR(lip);
						if (FLOW_GET(ltcp)==S2C) {	// Q.R
							_add_finish_session(session, HTTP_SESSION_FINISH);
						} else {
							assert(FLOW_GET(ltcp)==C2S);
							_append_packet_to_session(session, packet);
							continue;
						}
					}
				}
			} 
			session = _get_idl_session(DEBUG);
			if (session) {	// new session
				_init_new_http_session(session, packet);
				if (session->query_image == 0) {
					if ((session->query_image = _check_http_or_query(content))) {
						session->flag = HTTP_SESSION_REQUESTING;
						session->query= content;
					}
				}
				continue;
			} else {
				LOGWARN0("Sessions is full.");
			}
		} else {
			assert(FLOW_GET(tcphead)==S2C);
			struct http_session* session = FindSession(iphead->daddr, tcphead->dest);
			if (session) {
				if (_check_http_or_query(content)==3) { session->http = content; }	// HTTP/1.1

				if (tcphead->seq > session->ack) {
					_append_packet_to_session(session, packet);
				} else if (tcphead->seq == session->ack) { // resend
					free((void*)packet);
					continue;
				} else {
					const void* p = _insert_into_session(session, packet);
					if (p == packet) { free((void*)packet); } // resend
					continue;
				}
				continue;
			}
		}

		free((void*)packet); // LOGDEBUG0("cannt find session");
	}
	printf("Exit http thread.\n");
	return NULL;
}

int HttpStop()
{
	while (DEBUG) {	// TODO: I want to process all packets.
		if (len_queue(_packets)==0 && len_queue(_whole_content)==0) break;
		_http_active += g_nHttpTimeout/5;
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
	
	g_nMaxHttpSessionCount = GetValue_i(CONFIG_PATH, "max_session_count");
	if (g_nMaxHttpSessionCount < 500 || g_nMaxHttpSessionCount > 100000)
		g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
	
	g_nMaxHttpPacketCount = GetValue_i(CONFIG_PATH, "max_packet_count");
	if (g_nMaxHttpPacketCount < 1000 || g_nMaxHttpPacketCount > 200000)
		g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
	
	g_nHttpTimeout = GetValue_i(CONFIG_PATH, "http_timeout");
	if (g_nHttpTimeout < 10 ) g_nHttpTimeout = HTTP_TIMEOUT;

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
	// _working_session = init_queue(g_nMaxHttpSessionCount);
	// ASSERT(_working_session != NULL);
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

	pthread_t thread_timeout_id;
	err = pthread_create(&thread_timeout_id, NULL, &_process_timeout, NULL);
	ASSERT(err==0);

	return _packets==NULL? -1:0;
}


int PushHttpPack(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{	
	struct timeval *tv = (struct timeval*)buffer;
	if (!DEBUG) gettimeofday(tv, NULL);
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

	struct tcphdr* tcphd = (struct tcphdr*)tcphead;
	struct hosts_t host = { {iphead->saddr}, tcphead->source };
	struct hosts_t host1 = { {iphead->daddr}, tcphead->dest};
	pthread_mutex_lock(&_host_ip_lock);
	
	if (inHosts(_valid_hosts, &host)!=NULL ) {
		nRs = PushHttpPack(buffer, iphead, tcphead);
		FLOW_SET(tcphd, S2C);
	} else if (inHosts(_valid_hosts, &host1)!=NULL) {
		nRs = PushHttpPack(buffer, iphead, tcphead);
		FLOW_SET(tcphd, C2S);
	}

	if (nRs == -1) {
		char ssip[16], sdip[16];
		LOGDEBUG("%s:%u => %s:%u is skiped.", 
				inet_ntop(AF_INET, &iphead->saddr, ssip, 16), ntohs(tcphead->source),
				inet_ntop(AF_INET, &iphead->daddr, sdip, 16), ntohs(tcphead->dest));
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

///////////// gzip
static void* out = NULL;
static uint32_t outlen = 0u;
#define MAX_OUT_LEN (10*1024*1024-64)
uint32_t TransGzipData(const char *pGzipData, int nDataLen, char **pTransData, int gz)
{	// TODO: gzip 
	if (pGzipData == NULL) return 0;
	if (out==NULL) {
		out = malloc(MAX_OUT_LEN);
		outlen = MAX_OUT_LEN;
		ASSERT(out != NULL);
	}
	
	*pTransData = NULL;
	uint32_t plain_len = *(uint32_t*)(pGzipData+nDataLen-4);
	LOGDEBUG("TransGzipData, content length = %d, plain length = %d", nDataLen, plain_len);
	if (gz && plain_len>MAX_OUT_LEN) {
		LOGERROR("%u properly error. try...", plain_len);
	}
	if (gz && nDataLen>plain_len) {
		LOGERROR("%u/%u properly error. try...", nDataLen, plain_len);
	}
	
	uint32_t have;
	z_stream strm = {0};
	int err;
	if (gz) {
		err	= inflateInit2(&strm, 47);
	} else {
		err = inflateInit(&strm);
	}
	if (err != Z_OK) return 0;

	strm.avail_in = nDataLen;
	strm.next_in = (void*)pGzipData;
	strm.avail_out = MAX_OUT_LEN;
	strm.next_out = out;

	err = inflate(&strm, Z_FINISH);
	have = MAX_OUT_LEN-strm.avail_out;
	plain_len = have;
	if (err == Z_STREAM_END) { // greate!
		LOGDEBUG0("Hallelujah!");
	} else if (err == Z_OK) {
		LOGERROR0("Need more memory. too big.");
	} else {
		LOGERROR("inflate=%d", err);
	}
	if (plain_len > 0) {
		*pTransData = malloc(plain_len+1);
		memcpy(*pTransData, out, plain_len);
		(*pTransData)[plain_len] = '\0';
	}
	inflateEnd(&strm);
	
	return plain_len;
}

int GetHttpData(char **data)
{
	*data = NULL;
	if (_whole_content == NULL) return 0;
	struct http_session *pSession = (struct http_session*)pop_queue(_whole_content);
	if (pSession == NULL) return 0;
	
	INC_WHOLE_HTML_SESSION;
	
	if (pSession->flag < HTTP_SESSION_FINISH) {
		LOGERROR("Session.flag=%d. want HTTP_SESSION_FINISH", pSession->flag);
		// TODO: uncomplete session
		CleanHttpSession(pSession);
		return 0;
	}
	size_t http_len = 0;
	assert(pSession->data != NULL);

	// get all http_content len
	unsigned transfer_flag = pSession->transfer_flag;
	void* packet = pSession->data;
	do {		// TODO: maybe can process breaken.
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
	char* http_content = (char*)calloc(1, data_len+32);
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
			// not GET or POST
			char sip[32],dip[32];
			LOGINFO("not GET and POST. session[%u] %s:%u.%u.%u -> %s:%u", pSession->index, 
					inet_ntop(AF_INET, &iphead->saddr, sip, 32), ntohs(tcphead->source),
					tcphead->seq, tcphead->ack_seq,
					inet_ntop(AF_INET, &iphead->daddr, dip,322), ntohs(tcphead->dest));
		}
	}
	char* QUERY = NULL;
	char* HTTP = NULL;
	char* HTTP_PRE = http_content+35+10+26+26+5;
	do {
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = tcphead->window;
		const char *content = (void*)tcphead + tcphead->doff*4;
		if (*(uint32_t*)content==_http_image && HTTP==NULL) {
			HTTP = http_content+pos;
		}
		memcpy(http_content+pos, content, contentlen);
		pos += contentlen;
		void* tmp = packet;
		packet = *(void**)packet;
		free(tmp);
	} while (packet!=NULL);
	pSession->data = NULL;
	
	http_content[pos] = '\0';
	ASSERT(pos+1 == data_len);

	// *(unsigned*)HTTP == _get_image, _post_image 
	if (HTTP == NULL) {
		LOGINFO("Not http!!!!! cannt get here!!!. \n%s", HTTP_PRE);
		goto ERROR_EXIT;
	}

	LOGTRACE("Session[%d] ready to get data", pSession->index);
	if (pSession->response_head == NULL) { }	// TODO: if want to preprocess http	
	const char* sHttpCode = (const char*)memmem(HTTP, 64, " ", 1);
	if (sHttpCode==NULL) LOGERROR("Session[%d] dont have http/?? xxxx \n%s", pSession->index, HTTP);
	int nHttpcode = strtol(sHttpCode, NULL, 10);
	sprintf(http_content+35, "STATE=%03d", nHttpcode); // TODO: may be process 4xx 5xx
		
	int nContentLength = 0;
	char* content = (char*)memmem(HTTP, http_len, "\r\n\r\n", 4);
	if (content == NULL) {
		LOGWARN("Session[%d] has not content, current content = %s", pSession->index, HTTP);
		goto NOZIP;
	}
	if (pSession->content_type >= HTTP_CONTENT_FILE) {	// content be droped.
		char* tmp = content+4;
		*tmp = '\0';
	} else if (HTTP_TRANSFER_CHUNKED == transfer_flag) { // everything will be happen.
		char* pOldContent = content+4;
		char* pDest = pOldContent;
		char* pTmpContent = pOldContent;
		while (pTmpContent < http_content+data_len) {	// TODO: Proc chunk
			char* tmp = NULL;
			int nChunkLen = strtol(pTmpContent, &tmp, 16);
			if (nChunkLen > 0) {
				pTmpContent = strstr(tmp, "\r\n");
				nContentLength += nChunkLen;
				if (pTmpContent != NULL) {
					int diff = http_content+data_len - pTmpContent-nChunkLen-2;
					if (diff < 0) {
						LOGERROR("Session[%d] error in chunked. diff=%d", pSession->index, diff);
						nChunkLen += diff;
					}
					//for(int _n=0; _n<nChunkLen; ++_n) { pDest[_n] = pTmpContent[2+_n]; }
					memmove(pDest, pTmpContent+2, nChunkLen);
					pDest += nChunkLen;
					pTmpContent += 2+nChunkLen+2;
				} else {	// TODO: end of content.
					LOGERROR0("Not standard.[chunked]");
					break;
				}
			} else {
				LOGDEBUG("Session[%d] end of process-chunked. size = %d", pSession->index, nContentLength);
				break;
			}
		}
	} else if (HTTP_TRANSFER_HAVE_CONTENT_LENGTH == transfer_flag) {
		nContentLength = pSession->http_content_length;
	}
	LOGDEBUG("Session[%d] get data nContentLength=%d", pSession->index, nContentLength);
	
	if (nContentLength == 0) { goto NOZIP; }
	
	content += 4;

	LOGDEBUG("Session[%d] get data content_encoding=%d", pSession->index, pSession->content_encoding);
	
	// gzip Content-Encoding: gzip
	if (pSession->content_encoding == HTTP_CONTENT_ENCODING_GZIP 
	  ||pSession->content_encoding == HTTP_CONTENT_ENCODING_DEFLATE ) {
		const char* pZip_data = content;
		char* pPlain = NULL;
		uint32_t nUnzipLen;
		if (pSession->content_encoding==HTTP_CONTENT_ENCODING_GZIP) {
			nUnzipLen = TransGzipData(pZip_data, nContentLength, &pPlain, 1);
		} else {
			nUnzipLen = TransGzipData(pZip_data, nContentLength, &pPlain, 0);
		}
		if (nUnzipLen > 0) {
			int new_data_len = content-http_content+nUnzipLen;
			char* new_http_content = (char*)malloc(new_data_len+32);
			if (new_http_content != NULL) {
				int npos = content - http_content;
				memcpy(new_http_content, http_content, npos);
				memcpy(new_http_content+npos, pPlain, nUnzipLen);
				npos += nUnzipLen;
				new_http_content[npos] = '\0';
				free(pPlain);
				pPlain = NULL;
				free(http_content);
				http_content = NULL;
				data_len = npos+1;
				http_content = new_http_content;
			} else {
				LOGERROR("cannt calloc() new_data, %s", strerror(errno));
				goto NOZIP;
			}
		}
	} else if (pSession->content_encoding==HTTP_CONTENT_ENCODING_COMPRESS) { // same with gzip
		LOGERROR0("not support Content-Encoding = compress");
	} else {
		//const char* htmlend = (const char*)memmem(content, nContentLength, "</html>", 7);
		//if (htmlend==NULL) htmlend= (const char*)memmem(content, nContentLength, "</HTML>", 7);
		//if (htmlend==NULL) htmlend= (const char*)memmem(content, nContentLength, "</Html>", 7);
		//if (htmlend != NULL) { 
		//	nContentLength = htmlend-content+7;
		//	content[nContentLength] = '\0';
		//}
	}
NOZIP:
	CleanHttpSession(pSession);
	*data = http_content;
	LOGDEBUG("Session[%d] get data successfully!", pSession->index);
	
	return data_len;
	
ERROR_EXIT:
	CleanHttpSession(pSession);
	free(http_content);
	return 0;
}

