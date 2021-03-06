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
static pthread_t _http_thread_id;

static void* _valid_hosts = NULL;
pthread_mutex_t _host_ip_lock = PTHREAD_MUTEX_INITIALIZER;
static struct queue_t *_packets = NULL;

// TODO: why?
static int g_nMaxHttpSessionCount = MAX_HTTP_SESSIONS;
static int g_nMaxHttpPacketCount = MAX_HTTP_PACKETS;
static int g_nHttpTimeout = HTTP_TIMEOUT;
// end.
// iterate
static pthread_mutex_t _http_session_lock = PTHREAD_MUTEX_INITIALIZER;
static struct http_session* _http_session_head = NULL;	// a session = query + reponse
static struct http_session* _http_session_tail = NULL;	// a session = query + reponse
// improve
static struct http_sessions_group* _sessions_group = NULL;

static struct queue_t* _idl_session = NULL;
static struct queue_t* _whole_content = NULL;
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

struct _type_content_t { int type; char *content; int len; };
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
/////////////////////////////////
uint32_t _check_http_or_query(const void* content)
{
	uint32_t image = *(uint32_t *)content; 
	if (image == _http_image) return HTTP_RESP_HTTP;
	if (image == _get_image || image == _post_image) return HTTP_QUERY_GET_POST;
	if (image==_head_image || image==_put_image || image==_delete_image
			|| image==_options_image || image==_trace_image) {
		return HTTP_QUERY_OTHER;
	}
	return HTTP_QUERY_NONE;
}
int _debug_points()
{
	return 0;
}
int _check_heads(const char* content, const char* name, struct _type_content_t* types, size_t tynum)
{
	const char* start = strcasestr(content, name);
	if (start==NULL) return HTTP_CONTENT_NONE;
	const char* stop = strchr(start, '\r');
	int namelen = strlen(name);
	if (start==NULL || stop==NULL || namelen==0) return HTTP_CONTENT_NONE;
	start += namelen;
	namelen = stop-start;
	if (namelen<=0) return HTTP_CONTENT_NONE;
	for (int n=0; n<tynum; ++n) {
		if (memmem(start, namelen, types[n].content, types[n].len)) {
			return types[n].type;
		}
	}

	return HTTP_CONTENT_NONE;
}
char* _get_head_value(const char* heads, const char* name)
{
	const char* start = strcasestr(heads, name);
	const char* stop = strchr(start, '\r');
	int namelen = strlen(name);
	if (start==NULL || stop==NULL || namelen==0) return NULL;
	start += namelen;
	char* value = (char*)malloc(stop-start+1);
	char* tmp = value;
	if (*start == ':') { ++start; }
	while (start<stop) {
		if (*start != ' ') *tmp++ = *start;
		++start;
	}
	*tmp = '\0';
	return value;
}
char* _check_head_name_value(const char* heads, const char* name, const char* value)
{
	const char* start = strcasestr(heads, name);
	char* stop = (char*)strchr(start, '\r');
	int namelen = strlen(name);
	if (start==NULL || stop==NULL || namelen==0) return NULL;
	start += namelen;
	if (*start == ':') ++start;
	char tmp = *stop;
	*stop = '\0';
	char* _value = strcasestr(start, value);
	*stop = tmp;
	return _value;
}
//////////////////////////////// sessions_group funtions
#define IMAGE1024 1024
struct http_session* sm_AddSession(struct http_session* session)
{	// always insert into head
	uint16_t index = (session->client.port)&1023u;
	// LOGDEBUG("AddSession: %08X, %d, %d", session->client.ip.s_addr, session->client.port, index);
	pthread_mutex_lock(&_sessions_group[index].lock);
	struct http_session* head = _sessions_group[index].head;
	session->prev = NULL;
	session->next = head;
	if (head) { head->prev = session; };
	_sessions_group[index].head = session;
	++_sessions_group[index].used;
	pthread_mutex_unlock(&_sessions_group[index].lock);
	return session;
}
struct http_session* sm_DelSession(struct http_session* session)
{
	uint16_t index = (session->client.port)&1023u;
	pthread_mutex_lock(&_sessions_group[index].lock);
	if (session->prev) {
		session->prev->next = session->next;
	} else {
		_sessions_group[index].head = session->next;
	}
	if (session->next) {
		session->next->prev = session->prev;
	}
	--_sessions_group[index].used;
	pthread_mutex_unlock(&_sessions_group[index].lock);
	return session;
}
// port: ntohs ip = inet_addr()
struct http_session* sm_FindSession(uint32_t ip, uint16_t port)
{
	uint16_t index = port & 1023u;
	// LOGDEBUG("FindSession: %08X, %d, %d", ip, port, index);
	struct http_session *session = _sessions_group[index].head;
	while (session) {
		if (session->client.ip.s_addr==ip&&session->client.port==port) {
			return session;
		}
		session = session->next;
	}
	return NULL;
}
void sm_Init()
{
	_sessions_group = calloc(sizeof(_sessions_group[0]), IMAGE1024);
	ASSERT(_sessions_group)

	for (size_t index = 0; index < IMAGE1024; ++index) {
		pthread_mutex_init(&_sessions_group[index].lock, NULL);
	}
}
void sm_Destory()
{	// to clean everything. but just do noting
}
//////////////////////////// http_session funtions
//#define NewHttpSession() ((struct http_session*)pop_queue_timedwait(_idl_session))
#define NewHttpSession() ((struct http_session*)malloc(sizeof(struct http_session)))
struct http_session* InitHttpSession(struct http_session* session, void *packet)
{
	assert(session && packet);
	bzero(session, sizeof(*session));	// TODO: for debug
	struct timeval tv = *(struct timeval*)packet;
	struct iphdr* ip = IPHDR(packet);
	struct tcphdr* tcp = TCPHDR(ip);
	uint32_t contentlen = CONTENT_LEN_GET(tcp);
	char* content = CONTENT_GET(tcp);
	assert(contentlen > 0);
	assert(FLOW_GET(tcp) == C2S);

	session->client.ip.s_addr = ip->saddr;
	session->client.port = tcp->source;
	session->server.ip.s_addr = ip->daddr; 
	session->server.port = tcp->dest;
	session->flag   = HTTP_SESSION_NEW;
	session->seq	= tcp->seq+contentlen;
	session->ack	= tcp->ack_seq;
	session->content_type= HTTP_CONTENT_NONE;
	session->create	= tv;
	session->update = tv;
	*(void**)packet = NULL;
	session->data = packet;
	session->lastdata = packet;
	session->packet_num = 1;

	session->query_image = _check_http_or_query(content);
	if (session->query_image) {
		session->query = content;
		char sip[18], dip[18];
		LOGDEBUG("New Session:%u %s:%u -> %s:%u %s", tv.tv_sec, 
				inet_ntop(AF_INET, &ip->saddr, sip, sizeof(sip)), tcp->source,
				inet_ntop(AF_INET, &ip->daddr, dip, sizeof(dip)), tcp->dest,
				content);
	} else {
		session->query = NULL;
	}
	session->http = NULL;
	session->prev = session->next = NULL;
	// should in NewHttpSession
	session->_work_next = NULL;
	pthread_mutex_lock(&_http_session_lock);
	if (_http_session_tail) {
		_http_session_tail->_work_next = session;
		_http_session_tail = session;
	} else {
		_http_session_head = _http_session_tail = session;
	}
	pthread_mutex_unlock(&_http_session_lock);
	sm_AddSession(session);
	INC_NEW_HTTP_SESSION;
	return session;
}
void AppendPacketToHttpSession(struct http_session* session, void *packet)
{
	INC_APPEND_PACKET;
	++session->packet_num;
	struct timeval tv = *(struct timeval*)packet;
	struct iphdr* ip = IPHDR(packet);
	struct tcphdr* tcp = TCPHDR(ip);
	char* content = CONTENT_GET(tcp);
	char sip[18], dip[18];
	session->update = tv;

	if (FLOW_GET(tcp) == S2C) {
		if (session->seq<tcp->ack_seq) session->seq = tcp->ack_seq;
		if (session->ack<tcp->seq+tcp->window) session->ack = tcp->seq+tcp->window;
	} else {
		if (session->seq<tcp->seq+tcp->window) session->seq = tcp->seq+tcp->window;
		if (session->ack<tcp->ack_seq) session->ack = tcp->ack_seq;
	}
	if (session->content_type>=HTTP_CONTENT_FILE) { //HTTP_CONTENT_STREAM) {
		free(packet);
	} else {
		*(void**)packet = NULL;
		*(void**)session->lastdata = packet;
		session->lastdata = packet;
		// > 20M
		if (session->http==NULL && session->packet_num>10) { session->content_type=HTTP_CONTENT_STREAM; }

		if (session->query_image == HTTP_QUERY_NONE) {
			session->query_image = _check_http_or_query(content);
			if (session->query_image==HTTP_QUERY_GET_POST
					|| session->query_image==HTTP_QUERY_OTHER) {
				session->query = content;
				LOGDEBUG("New Session:%u %s:%u -> %s:%u %s", tv.tv_sec, 
						inet_ntop(AF_INET, &ip->saddr, sip, sizeof(sip)), tcp->source,
						inet_ntop(AF_INET, &ip->daddr, dip, sizeof(dip)), tcp->dest,
						content);
			}
		}
		if (session->http == NULL) {
			if (*(uint32_t*)content == _http_image) {
				session->http = content;
				LOGDEBUG("Response:%u %s:%u -> %s:%u %s", tv.tv_sec, 
						inet_ntop(AF_INET, &ip->saddr, sip, sizeof(sip)), tcp->source,
						inet_ntop(AF_INET, &ip->daddr, dip, sizeof(dip)), tcp->dest,
						content);
				session->content_type = _check_heads(content, "Content-Type", 
						CONTENT_TYPE, sizeof(CONTENT_TYPE)/sizeof(CONTENT_TYPE[0]));
			}
		}
	}
}
void FinishHttpSession(struct http_session* session, int flag)
{
	if (session->flag==HTTP_SESSION_NEW) INC_FINISH_SESSION;

	// if flag == FINISH or RESET or WAITONESEC
	if (flag==HTTP_SESSION_FINISH || flag==HTTP_SESSION_RESET ) {
		sm_DelSession(session);
	}
	session->flag = flag;
}
struct http_session* FindHttpSession(const struct iphdr* ip, const struct tcphdr* tcp)
{
	int flow = FLOW_GET(tcp);
	uint32_t ip_ = flow==C2S? ip->saddr:ip->daddr;
	uint16_t port=flow==C2S? tcp->source:tcp->dest;
	return sm_FindSession(ip_, port);
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
	
	CleanPacketList(pSession->data);
	/*void* packet = pSession->data;
	while (packet!=NULL) {
		void* tmp = packet;
		packet = *(void**)packet;
		free(tmp);
	}*/

	//bzero(pSession, sizeof(*pSession));
	//push_queue(_idl_session, pSession);
	free(pSession);
	return pSession;
}

void _del_session_from_working_next(struct http_session* prev, struct http_session* bedel)
{
	pthread_mutex_lock(&_http_session_lock);
	if (prev) {
		prev->_work_next = bedel->_work_next;
	} else {
		_http_session_head = bedel->_work_next;
	}
	if (_http_session_tail==bedel) {
		_http_session_tail = prev;
	}
	pthread_mutex_unlock(&_http_session_lock);
}
void _show_debug_info(void *data)
{
	printf("==================================\n");
	void* packet = data;
	char sip[32], dip[32];
	while (packet) {
		struct iphdr *ip=IPHDR(packet); struct tcphdr* tcp=TCPHDR(ip); 
		printf("[%u] %s:%u -> %s:%u flow:%u seq:%u/%u ack:%u\n", tcp->urg_ptr, 
				inet_ntop(AF_INET, &ip->saddr, sip, sizeof(sip)),  tcp->source,
				inet_ntop(AF_INET, &ip->daddr, dip, sizeof(sip)),  tcp->dest,
				FLOW_GET(tcp), tcp->seq, tcp->seq+tcp->window, tcp->ack_seq);
		packet = *(void**)packet;
	}
}
// return l>r:1; l=r:0; l<r:-1
int _cmp_packet_seq0(void* l, void* r)
{
	assert(l!=r);
	if (l==NULL) return -1;
	if (r==NULL) return -1;
	struct iphdr* lip = IPHDR(l);
	struct iphdr* rip = IPHDR(r);
	struct tcphdr* ltcp = TCPHDR(lip);
	struct tcphdr* rtcp = TCPHDR(rip); 
	if (FLOW_GET(ltcp) == FLOW_GET(rtcp)) {
		if (ltcp->seq == rtcp->seq) return 0;
		if (ltcp->seq > rtcp->seq) {
			if (ltcp->seq-rtcp->seq < 0x00010000) {
				return 1;
			} else {
				return -1;
			}
		} else {
			if (rtcp->seq-ltcp->seq < 0x00010000) {
				return -1;
			} else {
				return 1;
			}
		}
	} else {
		if (FLOW_GET(rtcp) == C2S) return 1;
	}	
	return -1;
}
// return l>r:1; l=r:0; l<r:-1
int _cmp_packet_seq1(void* l, void* r)
{
	assert(l!=r);
	if (l==NULL) return -1;
	if (r==NULL) return -1;
	struct iphdr* lip = IPHDR(l);
	struct iphdr* rip = IPHDR(r);
	struct tcphdr* ltcp = TCPHDR(lip);
	struct tcphdr* rtcp = TCPHDR(rip); 
	uint32_t lseq = ltcp->seq+ltcp->window;
	uint32_t rseq = rtcp->seq+rtcp->window;

	if (FLOW_GET(ltcp) == FLOW_GET(rtcp)) {
		if (lseq == rseq) return 0;
		if (lseq > rtcp->seq) return 0;	// I dont known why. see 20140715.log
		if (lseq > rseq) {
			return 0;
		} else {
			if (rseq-lseq < 0x00010000) {
				return -1;
			} else {
				return 1;
			}
		}
	} else { 
		if (FLOW_GET(rtcp) == C2S) return 1;
	}	
	return -1;
}
// return lost bytes
int _fix_packet_order(void** data)
{
	int lost = 0;
	int change = 0;
	do {
		change = 0;
		void* head = *data;
		void* packet = head;
		void* prev = NULL;
		void* next = NULL;
		while (packet) {
			next = *(void**)packet;
			int cmp = _cmp_packet_seq0(packet, next); 
			if (cmp == 0) {
				*(void**)packet = *(void**)next;
				free(next);
			} else if (cmp < 0) {
				prev = packet;
				packet = next;
			} else {
				if (prev) {
					*(void**)prev = next;
				} else {
					*data = next;
				}
				*(void**)packet = *(void**)next;
				*(void**)next = packet;
				prev = next;
				++change;
			}
		}
	} while (change);
	do {
		change = 0;
		void* head = *data;
		void* packet = head;
		void* prev = NULL;
		void* next = NULL;
		while (packet) {
			next = *(void**)packet;
			int cmp = _cmp_packet_seq1(packet, next); 
			if (cmp == 0) {
				*(void**)packet = *(void**)next;
				free(next);
			} else if (cmp < 0) {
				prev = packet;
				packet = next;
			} else {
				if (prev) {
					*(void**)prev = next;
				} else {
					*data = next;
				}
				*(void**)packet = *(void**)next;
				*(void**)next = packet;
				prev = next;
				++change;
			}
		}
	} while (change);
	return lost;
}
void *_process_timeout(void* p)
{
	int broken_time = 2;
	if (DEBUG) broken_time = 10000;
	time_t start, end;
	start = end = time(NULL);
	uint32_t count = 0;

	while (_http_living) {
		if (end-start == 0) usleep(100000);

		start = time(NULL);
		struct http_session* cur = _http_session_head;
		struct http_session* prev = NULL;
		count = 0;
		while (cur)	{
			++count;
			if (cur->flag==HTTP_SESSION_FINISH || cur->flag==HTTP_SESSION_RESET || cur->flag==HTTP_SESSION_REUSED) {
				_del_session_from_working_next(prev, cur);
				if (cur->http || cur->query) {
					cur->flag = HTTP_SESSION_TIMEOUT;
					_fix_packet_order(&cur->data);
					push_queue(_whole_content, cur);
				} else {
					CleanHttpSession(cur);
					INC_DROP_SESSION_ONQUERY_NOHTTP;
				}
				cur = prev? prev->_work_next:_http_session_head;
				continue;
			} 
			if (cur->flag==HTTP_SESSION_WAITONESEC && _http_active-cur->update.tv_sec > broken_time) {
					LOGINFO("http_session[%d] is timeout. %d - %d > %d flag=%d ", 
							index, _http_active, cur->update.tv_sec, g_nHttpTimeout, cur->flag);
				cur->flag = HTTP_SESSION_FINISH;
				sm_DelSession(cur);
				_del_session_from_working_next(prev, cur);
				if (cur->http || cur->query) {
					cur->flag = HTTP_SESSION_TIMEOUT;
					_fix_packet_order(&cur->data);
					push_queue(_whole_content, cur);
				} else {
					CleanHttpSession(cur);
					INC_DROP_SESSION_ONQUERY_NOHTTP;
				}
				cur = prev? prev->_work_next:_http_session_head;
				continue;
			}
			if (_http_active-cur->update.tv_sec > g_nHttpTimeout) {
				LOGINFO("http_session[%d] is timeout. %d - %d > %d flag=%d ", 
						index, _http_active, cur->update.tv_sec, g_nHttpTimeout, cur->flag);
				sm_DelSession(cur);
				_del_session_from_working_next(prev, cur);
				if (cur->http || cur->query) {
					cur->flag = HTTP_SESSION_TIMEOUT;
					_fix_packet_order(&cur->data);
					push_queue(_whole_content, cur);
				} else {
					CleanHttpSession(cur);
					INC_DROP_SESSION_ONQUERY_NOHTTP;
				}
				cur = prev? prev->_work_next:_http_session_head;
				continue;
			}
			prev = cur;
			cur = cur->_work_next;
		}
		end = time(NULL);
		SET_ACTIVE_SESSION_COUNT(count);
		SET_WHOLE_QUEUE_COUNT(len_queue(_whole_content));
	}
	return NULL;
}
/////////////////////////////////////////////////
// only the packet from client can create new session.

// return NULL: session->head packet: resend other: prev


void *HTTP_Thread(void* param)
{
	while (_http_living) {
		char* packet = (char*)pop_queue_timedwait(_packets);
		if (packet == NULL) { continue; }
		INC_POP_PACKETS;

		struct timeval *tv = (struct timeval*)packet;
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		int contentlen = CONTENT_LEN_GET(tcphead);
		assert(contentlen>1||tcphead->fin||tcphead->rst);
		assert(contentlen<1600);	// TODO: for test

		if (contentlen>=RECV_BUFFER_LEN) { 
			LOGFATAL("[%lu] content is too long. %u", tv->tv_sec, contentlen);
			free((void*)packet); 
			continue; 
		} 
		char *content = (void*)tcphead + tcphead->doff*4;
		_http_active = tv->tv_sec;
		// ntohl
		tcphead->seq = ntohl(tcphead->seq);
		tcphead->ack_seq = ntohl(tcphead->ack_seq);
		tcphead->source = ntohs(tcphead->source);
		tcphead->dest = ntohs(tcphead->dest);

		struct http_session* session = FindHttpSession(iphead, tcphead);
		if (FLOW_GET(tcphead)==C2S) {
			if (session) {
				assert(session->flag!=HTTP_SESSION_RESET);
				assert(session->flag!=HTTP_SESSION_FINISH);
				if (tcphead->rst) {	// reuse
					FinishHttpSession(session, HTTP_SESSION_RESET);
				} else if (tcphead->fin) {
					FinishHttpSession(session, HTTP_SESSION_FINISH);
				} else { // see 20140725.log 69~86
					if ( tcphead->seq > session->seq) {	// Q.R. now finish session and create new session
						FinishHttpSession(session, HTTP_SESSION_FINISH);
					} else {	// Q0.Q1.Q2...
						AppendPacketToHttpSession(session, packet);
						continue;
					}
				}
			} 
NEWSESSION0:
			if (contentlen == 0) {
				free(packet); INC_APPEND_PACKET;
				continue;
			}
			session = NewHttpSession();
			if (session) {	// new session
				InitHttpSession(session, packet);
				continue;
			} else {
				LOGWARN0("Sessions is full.");
			}
		} else {
			assert(FLOW_GET(tcphead)==S2C);
			if (session) {
				assert(session->flag!=HTTP_SESSION_RESET);
				assert(session->flag!=HTTP_SESSION_FINISH);
				if (tcphead->rst) {
					if (contentlen>0) {
						AppendPacketToHttpSession(session, packet);
					} else {
						free(packet); INC_APPEND_PACKET;
					}
					FinishHttpSession(session, HTTP_SESSION_RESET);
					continue;
				} else if (tcphead->fin) { 
					if (contentlen>0) {
						AppendPacketToHttpSession(session, packet);
					} else {
						free(packet); INC_APPEND_PACKET;
					}
					FinishHttpSession(session, HTTP_SESSION_WAITONESEC);
					continue;
				} else {
					AppendPacketToHttpSession(session, packet);
					continue;
				}
			}
		}

		INC_DROP_PACKET;
		LOGWARN("Cannt process this packet. %u", *(uint32_t*)packet);
		uint32_t image = *(uint32_t*)content;
		if (image==_get_image || image==_post_image || image==_http_image || image==_head_image 
				|| image==_put_image || image==_options_image || image==_delete_image || image==_trace_image)
		{
			char sip[18], dip[18];
			LOGDEBUG("Miss Session:%u %s:%u -> %s:%u %s", tv->tv_sec, 
					inet_ntop(AF_INET, &iphead->saddr, sip, sizeof(sip)), tcphead->source,
					inet_ntop(AF_INET, &iphead->daddr, dip, sizeof(dip)), tcphead->dest,
					content);
		}
		free((void*)packet); 
	}
	printf("Exit http thread.\n");
	return NULL;
}

int HttpStop()
{
	while (DEBUG) {	// TODO: I want to process all packets.
		if (len_queue(_packets)==0 && len_queue(_whole_content)==0 && _http_session_head==NULL) break;
		_http_active += g_nHttpTimeout/5;
		sleep(1);
	}
	_http_living = 0;
	void *retvl = NULL;
	int err = pthread_join(_http_thread_id, &retvl);
	return 0;
}

int HttpInit()
{
	ASSERT(_packets == NULL);

	g_nMaxHttpSessionCount = GetValue_i(CONFIG_PATH, "max_session_count");
	g_nMaxHttpPacketCount = GetValue_i(CONFIG_PATH, "max_packet_count");
	g_nHttpTimeout = GetValue_i(CONFIG_PATH, "http_timeout");

	LOGINFO("max_http_session_count = %d", g_nMaxHttpSessionCount);
	LOGINFO("max_http_packet_count = %d", g_nMaxHttpPacketCount);
	LOGINFO("max_http_timeout = %d", g_nHttpTimeout);
		
	_packets = init_queue(g_nMaxHttpPacketCount);
	ASSERT(_packets != NULL);
	_whole_content = init_queue(g_nMaxHttpSessionCount);
	ASSERT(_whole_content);
	_idl_session = init_queue(g_nMaxHttpSessionCount);
	ASSERT(_idl_session);
	struct http_session* p = (struct http_session*)malloc(sizeof(*p) * g_nMaxHttpSessionCount);
	ASSERT(p);
	for (uint32_t n=0; n<g_nMaxHttpSessionCount; ++n) {
		push_queue(_idl_session, &p[n]);
	}

	sm_Init();

	int err = pthread_create(&_http_thread_id, NULL, &HTTP_Thread, (void*)&_http_living);
	ASSERT(err >= 0);

	pthread_t thread_timeout_id;
	err = pthread_create(&thread_timeout_id, NULL, &_process_timeout, NULL);
	ASSERT(err==0);

	return _packets==NULL? -1:0;
}


int PushHttpPack(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead)
{	
	int err = 0;
DEBUG_LOOP:
	err = push_queue(_packets, (const void*) buffer);
	if (err < 0) {
		if (DEBUG) {
			sleep(0);
			goto DEBUG_LOOP;
		} else {
			LOGWARN0("http_queue is full. drop the packets.");
		}
	} else {
		INC_PUSH_PACKETS;
	}

	return err;
}

/// buffer is http return 0. other return -1;
/// len>0 !rst !fin
int FilterPacketForHttp(char* buffer, struct iphdr* iphead, struct tcphdr* tcphead)
{
	int nRs = -1;

	struct tcphdr* tcphd = (struct tcphdr*)tcphead;
	iphead->tot_len = ntohs(iphead->tot_len);
	int contentlen = iphead->tot_len - iphead->ihl*4 - tcphead->doff*4;
	if ((contentlen<2&&!tcphead->fin&&!tcphead->rst)) { 
		return -1;
	} 
	CONTENT_LEN_SET(tcphd, contentlen);

	struct timeval *tv = (struct timeval*)buffer;
	if (DEBUG) { } else { gettimeofday(tv, NULL); }

	struct hosts_t host = { {iphead->saddr}, tcphead->source };
	struct hosts_t host1 = { {iphead->daddr}, tcphead->dest};
	pthread_mutex_lock(&_host_ip_lock);
	
	if (inHosts(_valid_hosts, &host)!=NULL ) {
		FLOW_SET(tcphd, S2C);
		nRs = PushHttpPack(buffer, iphead, tcphead);
	} else if (inHosts(_valid_hosts, &host1)!=NULL) {
		FLOW_SET(tcphd, C2S);
		nRs = PushHttpPack(buffer, iphead, tcphead);
	}
	pthread_mutex_unlock(&_host_ip_lock);

	if (nRs < 0) {
		char ssip[16], sdip[16];
		LOGDEBUG("%s:%u => %s:%u is skiped.", 
				inet_ntop(AF_INET, &iphead->saddr, ssip, 16), ntohs(tcphead->source),
				inet_ntop(AF_INET, &iphead->daddr, sdip, 16), ntohs(tcphead->dest));
	}
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

uint32_t GetHttpData(char **data)
{
	*data = NULL;
	if (_whole_content==NULL) return 0;
	struct http_session *pSession = (struct http_session*)pop_queue(_whole_content);
	if (pSession == NULL) return 0;
	assert(pSession->data != NULL);
	
	INC_WHOLE_HTML_SESSION;
	if (pSession->query==NULL) { INC_WHOLE_HTML_SESSION_NOQUERY; }
	if (pSession->http ==NULL) { INC_WHOLE_HTML_SESSION_NOHTTP; }
	// get all http_content len
	size_t http_len = 0;
	void* packet = pSession->data;
	uint32_t c_flow, c_seq, c_lost, s_flow, s_seq, s_lost;
	c_flow = c_seq = c_lost = s_flow = s_seq = s_lost = 0u;
	do {		// TODO: maybe can process breaken.
		struct iphdr *iphead = IPHDR(packet);
		struct tcphdr *tcphead=TCPHDR(iphead);
		unsigned contentlen = tcphead->window;
		assert(iphead->tot_len - iphead->ihl*4 - tcphead->doff*4==contentlen);
		http_len += contentlen;
		if (FLOW_GET(tcphead) == C2S) {
			if (c_flow == NONE) { 
				c_flow = C2S;
				c_seq = tcphead->seq + contentlen; 
			} else {
				c_lost +=tcphead->seq - c_seq;
				c_seq = tcphead->seq + contentlen; 
			} 
		} else {
			if (s_flow == NONE) { 
				s_flow = S2C;
				s_seq = tcphead->seq + contentlen; 
			} else {
				s_lost +=tcphead->seq - s_seq;
				s_seq = tcphead->seq + contentlen; 
			} 
		}
		packet = *(void**)packet;
	} while (packet!=NULL);
	if (DEBUG && (c_lost+s_lost)>pSession->packet_num) {
		printf("c_lost = %u s_lost = %u\n", c_lost, s_lost);
		_show_debug_info(pSession->data);
	}

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
	
	if (s_lost > 0) {
		INC_UNCOMPLETE_SESSION;
		goto NOZIP;
	}

	http_content[pos] = '\0';
	ASSERT(pos+1 == data_len);

	// *(unsigned*)HTTP == _get_image, _post_image 
	if (HTTP == NULL) {
		LOGINFO("Not http!!!!! cannt get here!!!. \n%s", HTTP_PRE);
		goto ERROR_EXIT;
	}
	int transfer_flag = 1;
	LOGTRACE("Session[%d] ready to get data", pSession->index);
	if (pSession->http == NULL) { }	// TODO: if want to preprocess http	
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
	} else if (/*HTTP_TRANSFER_CHUNKED*/ 1 == transfer_flag) { // everything will be happen.
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
	} else if (/*HTTP_TRANSFER_HAVE_CONTENT_LENGTH*/ 1 == transfer_flag) {
		nContentLength = pSession->index; // TODO: fix 
	}
	LOGDEBUG("Session[%d] get data nContentLength=%d", pSession->index, nContentLength);
	
	if (nContentLength == 0) { goto NOZIP; }
	
	content += 4;

	LOGDEBUG("Session[%d] get data content_encoding=%d", pSession->index, 1);
	
	// gzip Content-Encoding: gzip
	if (1== HTTP_CONTENT_ENCODING_GZIP 
	  ||1== HTTP_CONTENT_ENCODING_DEFLATE ) {
		const char* pZip_data = content;
		char* pPlain = NULL;
		uint32_t nUnzipLen;
		if (2==HTTP_CONTENT_ENCODING_GZIP) {
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
	} else if (2==HTTP_CONTENT_ENCODING_COMPRESS) { // same with gzip
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

