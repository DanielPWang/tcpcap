#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include <define.h>
#include <utils.h>
#include <server.h>
#include <fun_all.h>
#include <fun_http.h>
#include "statis.h"

// TODO: change _valid_hosts
struct hosts_t *_monitor_hosts = NULL;
size_t _monitor_hosts_count = 0;

extern struct hosts_t *_exclude_hosts;
extern size_t _exclude_hosts_count;

extern pthread_mutex_t _host_ip_lock;

#define SERV_CLIENT_COUNT 5
static int _srv_socket = -1;
static int _client_socket = -1;
static int _srv_epoll = -1;
static char _client_ip[16] = {0};

static int _client_config_socket = -1;
static char _client_config_ip[16] = {0};

static time_t _flow_socket_start_time = 0;

static volatile int _runing = 1;
static pthread_t _srv_thread;
static pthread_t _cli_thread;
static struct msg_head _msg_heart_hit = {0};

static int SetupTCPServer(int server_port);
static int Unblock(int sock);
static int WriteSocketData(int sock, const void *pBuffer, int nWriteSize);
static int ReadSocketData(int sock, char *pBuffer, int nReadSize);
static int RecvData(int sock, struct msg_head *pMsgHead, char **pData);
static int SendData(int sock, unsigned char msg_type, const char*pData, int data_length);
static int ProcessReqGetIpList();
static int ProcessReqSetIpList(const char *pRecvData);

int InitServer()
{
	return 1;
}

int Unblock(int sock)
{
    int flag = fcntl(sock, F_GETFL, 0);
    int rc = fcntl(sock, F_SETFL, flag | O_NONBLOCK);
    if (rc < 0)
    {
    	LOGERROR("unblock error. [%d] %s", errno, strerror(errno));
		close(sock);
		return -1;
    }
    return 0;
}

int _send_all(int sock, const char* data, int len)
{
	if (data==NULL) return 0;
	int sent = 0u;
	while (sent < len) {
		int s = send(sock, &data[sent], len-sent, 0);
		if (s < 0) {
			if (errno == EINTR) {
				if (_runing==0) {
					return -1;
				}
				continue;
			}
			char* p = (char*)malloc(1024);
			p[1023] = '\0';
			LOGERROR("send return %d: %s", errno, strerror_r(errno, p, 1023)); 
			free(p);
			break;
		}
		sent += s;
	}
	return sent;
}
int SendData(int sock, unsigned char msg_type, const char*pData, int data_length)
{
	struct msg_head msgHead;
	msgHead.version = MSG_NORMAL_VER;
	msgHead.type = msg_type;
	msgHead.length = htonl(data_length);
	
	if (_send_all(sock, (const char*)&msgHead, sizeof(msgHead))!=sizeof(msgHead)) {
		LOGERROR0("Failure sending msghead.");
		return -1;
	}
	if (_send_all(sock, (const char*)pData, data_length)!=data_length) {
		LOGERROR0("Failure sending content.");
	}

	return data_length;
}

int ReadSocketData(int sock, char *pBuffer, int nReadSize)
{
	struct timeval timeout = { 3, 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	int nRecvTotal = 0;

	do {
		int nRead = recv(sock, pBuffer +  nRecvTotal, nReadSize - nRecvTotal, 0);
		if (nRead < 0) break;
		nRecvTotal += nRead;
	} while (nRecvTotal < nReadSize);

	return nRecvTotal;
}

int RecvData(int sock, struct msg_head *pMsgHead, char **pData)
{
	if (ReadSocketData(sock, (char*)pMsgHead, sizeof(struct msg_head)) != sizeof(struct msg_head)) {
		LOGERROR0("Read socket head data failed!");
		return -1;
	}

	if (pMsgHead->version != MSG_NORMAL_VER) {
		LOGERROR0("Message version error!");
		return -1;
	}

	pMsgHead->length = ntohl(pMsgHead->length);
	if (0 == pMsgHead->length)
		return 0;

	*pData = (char*)malloc(pMsgHead->length+1);
	if (ReadSocketData(sock, *pData, pMsgHead->length) != pMsgHead->length) {
		LOGERROR0("Read socket body data failed!");
		free(*pData);
		return -1;
	}
		
	return pMsgHead->length;
}

int _install_socket_(int epoll, int sock, int flag)
{
	struct epoll_event ev = {0};
	ev.events = flag;
	ev.data.fd = sock;
	return epoll_ctl(epoll, EPOLL_CTL_ADD, sock, &ev);
}
int _uninstall_socket_(int epoll, int sock)
{
	return epoll_ctl(epoll, EPOLL_CTL_DEL, sock, NULL);
}
int SetupTCPServer(int server_port)
{
	_srv_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (_srv_socket < 0) return -1;

	int nerr = 0;
	int sockopt = 1;
	nerr = setsockopt(_srv_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
	if (nerr < 0) {
		LOGERROR0("SO_REUSEADDR failed");
		close(_srv_socket);
		return -1;
	}

	struct sockaddr_in 	serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(server_port);

	LOGINFO("Bind server, port=%d", server_port);
	nerr = bind(_srv_socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if (nerr < 0) {
		LOGERROR0("bind failed");
		close(_srv_socket);
		return -1;
	}

	nerr = listen(_srv_socket, 5);
	if (nerr < 0) {
		LOGERROR0("listen failed");
		close(_srv_socket);
		return -1;
	}
	
	_srv_epoll = epoll_create(SERV_CLIENT_COUNT);
	ASSERT(_srv_epoll > -1);
	if (_install_socket_(_srv_epoll, _srv_socket, EPOLLIN)==-1) {
		perror("[ERROR] ");
		ASSERT(0);
	}
	return _srv_socket;
}
// TODO: change to _valid_hosts
int ProcessReqGetIpList()
{
	LOGINFO0("Receive request info for getting ip list.");

	int nSend = 0;
	char sip[16] = {0};
	int nIpLen = 0, nMonHostsLen = 0, nExcludeHostsLen = 0;
	struct hosts_t *pCurHost = NULL;
	char* pSendData = (char*)calloc(1, VALUE_LENGTH_MAX);
	char* pMonHostsTmp = pSendData;
	if (_monitor_hosts_count > 0)
	{
		for (int npos = 0; npos < _monitor_hosts_count; npos++)
		{
			pCurHost = &_monitor_hosts[npos];
			if (0 == pCurHost->ip.s_addr)
				continue;
			
			memset(sip, 0, 16);
			if (inet_ntop(AF_INET, &pCurHost->ip, sip, 16) != NULL)
			{
				strcat(pMonHostsTmp+nMonHostsLen+4, sip);
				nIpLen = strlen(sip);
				nMonHostsLen += nIpLen;
				int nPort = ntohs(pCurHost->port);
				if (nPort > 0)
				{
					char szPort[10] = {0};
					pMonHostsTmp[nMonHostsLen+4] = ':';	
					nMonHostsLen++;
					sprintf(szPort, "%d", nPort);
					strcat(pMonHostsTmp+nMonHostsLen+4, szPort);	
					nMonHostsLen += strlen(szPort);
				}
				pMonHostsTmp[nMonHostsLen+4] = ' ';
				nMonHostsLen++;
			}
		}

		if (nMonHostsLen > 0)
			nMonHostsLen--;
	}
	*(int*)pMonHostsTmp = htonl(nMonHostsLen);

	char* pExcludeHostsTmp = pMonHostsTmp + nMonHostsLen + 4;
	if (_exclude_hosts_count > 0)
	{
		for (int npos = 0; npos < _exclude_hosts_count; npos++)
		{
			pCurHost = &_exclude_hosts[npos];
			if (0 == pCurHost->ip.s_addr)
				continue;
			
			memset(sip, 0, 16);
			if (inet_ntop(AF_INET, &pCurHost->ip, sip, 16) != NULL)
			{
				strcat(pExcludeHostsTmp+nExcludeHostsLen+4, sip);
				nIpLen = strlen(sip);
				nExcludeHostsLen += nIpLen;
				int nPort = ntohs(pCurHost->port);
				if (nPort > 0)
				{
					char szPort[10] = {0};
					pExcludeHostsTmp[nExcludeHostsLen+4] = ':';	
					nExcludeHostsLen++;
					sprintf(szPort, "%d", nPort);
					strcat(pExcludeHostsTmp+nExcludeHostsLen+4, szPort);	
					nExcludeHostsLen += strlen(szPort);
				}
				pExcludeHostsTmp[nExcludeHostsLen+4] = ' ';
				nExcludeHostsLen++;
			}
		}

		if (nExcludeHostsLen > 0)
			nExcludeHostsLen--;
	}
	*(int*)pExcludeHostsTmp = htonl(nExcludeHostsLen);

	pSendData[nMonHostsLen+nExcludeHostsLen+8] = '\0';
	
	LOGINFO0("Send response ip list info.");
	nSend = SendData(_client_config_socket, MSG_TYPE_RES_IPLIST, pSendData, nMonHostsLen+nExcludeHostsLen+8);
	if (nSend < 0) 
	{
		LOGWARN0("remote socket is error or close. recontinue.");
		close(_client_config_socket);
		_client_config_socket = -1;
	}

	if (pSendData != NULL)
		free(pSendData);

	return nSend;
}

int ProcessReqSetIpList(const char *pRecvData)
{
	if (NULL == pRecvData)
		return 0;
	
	LOGINFO0("Receive request info for setting ip list.");

	int nSend = 0;
	int nMonHostsLen = 0, nExcludeHostsLen = 0;
	char *left = NULL, *right = NULL, *ipport = NULL;
	int n = 0;

	pthread_mutex_lock(&_host_ip_lock);
	
	nMonHostsLen = *(int*)pRecvData;
	nMonHostsLen = ntohl(nMonHostsLen);
	if (_monitor_hosts != NULL)
	{
		free(_monitor_hosts);
		_monitor_hosts = NULL;
		_monitor_hosts_count = 0;	
	}
	if (nMonHostsLen > 0)
	{
		char* pMonHostsTmp = (char*)calloc(1, nMonHostsLen+1);
		strncpy(pMonHostsTmp, pRecvData+4, nMonHostsLen);

		_monitor_hosts_count = count_char(pMonHostsTmp, ' ') + 1;
		_monitor_hosts = (struct hosts_t *)calloc(sizeof(struct hosts_t), _monitor_hosts_count);
		for (n = 0, left = pMonHostsTmp; ;left = NULL) 
		{
			ipport = strtok_r(left, " ", &right);
			if (NULL == ipport) 
				break;

			LOGINFO("Set monitor host with client request: %s", ipport);
			if (str_ipp(ipport, &_monitor_hosts[n])) 
				++n;
		}
		if (pMonHostsTmp != NULL)
			free(pMonHostsTmp);
	}

	nExcludeHostsLen = *(int*)(pRecvData+4+nMonHostsLen);
	nExcludeHostsLen = ntohl(nExcludeHostsLen);
	if (_exclude_hosts != NULL)
	{
		free(_exclude_hosts);
		_exclude_hosts = NULL;
		_exclude_hosts_count = 0;	
	}
	if (nExcludeHostsLen > 0)
	{
		char* pExcludeHostsTmp = (char*)calloc(1, nExcludeHostsLen+1);
		strncpy(pExcludeHostsTmp, pRecvData+4+nMonHostsLen+4, nExcludeHostsLen);
		
		_exclude_hosts_count = count_char(pExcludeHostsTmp, ' ') + 1;
		_exclude_hosts = (struct hosts_t *)calloc(sizeof(struct hosts_t), _exclude_hosts_count);
		for (n = 0, left = pExcludeHostsTmp; ;left = NULL) 
		{
			ipport = strtok_r(left, " ", &right);
			if (NULL == ipport) 
				break;

			LOGINFO("Exclude host with client req %s", ipport);
			if (str_ipp(ipport, &_exclude_hosts[n])) 
				++n;
		}
		if (pExcludeHostsTmp != NULL)
			free(pExcludeHostsTmp);
	}

	pthread_mutex_unlock(&_host_ip_lock);
	
	FILE *pFile = NULL;
	pFile = fopen(HTTP_HOST_PATH_FILE, "w");
	if (pFile != NULL) 
	{
		if (_monitor_hosts_count > 0)
		{
			char sip[16] = {0};
			struct hosts_t *pCurHost = NULL;
			for (int npos = 0; npos < _monitor_hosts_count; npos++)
			{
				pCurHost = &_monitor_hosts[npos];
				if (0 == pCurHost->ip.s_addr)
					continue;
				
				memset(sip, 0, 16);
				if (inet_ntop(AF_INET, &pCurHost->ip, sip, 16) != NULL)
				{
					int nPort = ntohs(pCurHost->port);
					if (nPort > 0)
						fprintf(pFile, "%s:%d\n", sip, nPort);	
					else
						fprintf(pFile, "%s\n", sip);
				}
			}
		}

		fclose(pFile);
	}

	pFile = fopen(EXCLUDE_HOST_PATH_FILE, "w");
	if (pFile != NULL) 
	{
		if (_exclude_hosts_count > 0)
		{
			char sip[16] = {0};
			struct hosts_t *pCurHost = NULL;
			for (int npos = 0; npos < _exclude_hosts_count; npos++)
			{
				pCurHost = &_exclude_hosts[npos];
				if (0 == pCurHost->ip.s_addr)
					continue;
				
				memset(sip, 0, 16);
				if (inet_ntop(AF_INET, &pCurHost->ip, sip, 16) != NULL)
				{
					int nPort = ntohs(pCurHost->port);
					if (nPort > 0)
						fprintf(pFile, "%s:%d\n", sip, nPort);	
					else
						fprintf(pFile, "%s\n", sip);
				}
			}
		}

		fclose(pFile);
	}
	
	LOGINFO0("Send response OK for setting ip list request.");
	nSend = SendData(_client_config_socket, MSG_TYPE_RES_OK, NULL, 0);
	if (nSend < 0) {
		LOGWARN0("remote socket is error or close. recontinue.");
		close(_client_config_socket);
		_client_config_socket = -1;
	}

	return nSend;
}

void* server_thread(void* p)
{
	char szPort[10] = {0};
	GetValue(CONFIG_PATH, "server_port", szPort, 6);
	int nPort = atoi(szPort);
	if (nPort <= 0 || nPort > 65535) {
		LOGERROR0("Get server port failed, set default port.");
		nPort = SERVER_PORT;
	}
	
thread_start:
	if (SetupTCPServer(nPort) < 0) {
		LOGERROR0("Setup TCP Server failed");
		return NULL;
	}
	
	int nerr = 0;
	fd_set rfds;
	fd_set wfds;
	struct timeval	tv;
	int retval = 0;
	int max_socket = 0;
	time_t active = time(NULL);
	struct epoll_event cli_event;
	while (_runing) {
		int clients = epoll_wait(_srv_epoll, &cli_event, 1, 5*1000);
		if (clients == 0) continue;
		if (clients < 0) {
			if (errno != EINTR) LOGERROR("epoll_wait return error. %s", strerror(errno));
			continue;
		}

		if (cli_event.data.fd == _srv_socket)
		{
			int	accept_socket;
			struct sockaddr_in client_address; 
			socklen_t client_len;
			client_len = sizeof(client_address);
			accept_socket = accept(_srv_socket, (struct sockaddr *)&client_address, &client_len);
			if (accept_socket > 0) {
				char sip[16] = {0};
				int nPort = 0;

				inet_ntop(AF_INET, &client_address.sin_addr, sip, 16);
				nPort = ntohs(client_address.sin_port);
				
				LOGINFO("%s:%d connect, accept successfully.", sip, nPort);

				if (CLIENT_SOCKET_PORT == nPort) {
					if (_client_socket > 0) {
						LOGWARN0("Another connector? close it.");
						int nSend = SendData(accept_socket, MSG_TYPE_NOTIFY_CONNECTION_EXIST, 
								_client_ip, strlen(_client_ip));
						shutdown(accept_socket, SHUT_RDWR);
						close(accept_socket);
					} else {
						_client_socket = accept_socket;
						memset(_client_ip, 0, 16);
						strcpy(_client_ip, sip);
						_install_socket_(_srv_epoll, _client_socket, EPOLLIN|EPOLLERR);
					}
				} else if (CLIENT_CONFIG_SOCKET_PORT == nPort) {
					struct msg_head msgHead;
					char *pRecvData = NULL;
					int nRecv = RecvData(accept_socket, &msgHead, &pRecvData);
					if (nRecv < 0) {
						LOGWARN0("remote config socket is error or close. recontinue.");
						close(accept_socket);
					} else {
						int nSend = 0;
						if (MSG_TYPE_REQ_GET_IPLIST == msgHead.type) {
							nSend = ProcessReqGetIpList();
						} else if (MSG_TYPE_REQ_SET_IPLIST == msgHead.type) {
							nSend = ProcessReqSetIpList(pRecvData);
						} 

						if (pRecvData != NULL) free(pRecvData);
					}
				} else if (CLIENT_TEST_SOCKET_PORT == nPort) {
					shutdown(accept_socket, SHUT_RDWR);
					close(accept_socket);
				} else {
					shutdown(accept_socket, SHUT_RDWR);
					close(accept_socket);
				}
			} else {
				LOGERROR("accept error. [%d]", errno);
			}
		}

		if (cli_event.data.fd == _client_socket) { // TODO: something are wroning.
			struct msg_head msgHead;
			char *pRecvData = NULL;
			int nRecv = RecvData(_client_socket, &msgHead, &pRecvData);
			if (nRecv < 0) {
				LOGWARN0("remote client socket is error or close. recontinue.");
				close(_client_socket);
				_client_socket = -1;
			} 
			if (pRecvData != NULL) free(pRecvData);
		}
	}

	if (_client_socket > 0) {
		shutdown(_client_socket, SHUT_RDWR);
		close(_client_socket);
	}
	
	shutdown(_srv_socket, SHUT_RDWR);
	close(_srv_socket);
	return NULL;
}

int _get_data_from_db(char** data)
{
	// TODO: process db
	return 0;
}
int _save_data_to_db(char* data, int len)
{
	// TODO: 
	return len;
}
void* client_thread(void *p)
{		// TODO: send data
	time_t active = time(NULL);
	const int timeout = 60;
	int datalen = 0;
	int fromdb = 0;
	char* data = NULL;
	while (_runing) {
		if ((time(NULL)-active) > timeout && _client_socket>0) {
			int sent = SendData(_client_socket, MSG_TYPE_HEARTHIT, NULL, 0);
			if (sent != 0) {
				_uninstall_socket_(_srv_epoll, _client_socket);
				shutdown(_client_socket, SHUT_RDWR);
				close(_client_socket);
				_client_socket = 0;
				continue;
			} else {
				active = time(NULL);
			}
		}
		if (data == NULL) {
			fromdb = 0;
			datalen = GetHttpData(&data);
			if (datalen == 0) {
				datalen = _get_data_from_db(&data);
				fromdb = 1;
			}
			if (datalen == 0) {
				sleep(1);
				continue;
			}
		}
		if (_client_socket == -1) {
			if (!fromdb) {
				_save_data_to_db(data, datalen);
				data = NULL;
			}
			continue;
		}
		int sent = SendData(_client_socket, MSG_TYPE_HTTP, data, datalen);
		if (sent != datalen) {
			LOGWARN("Failure sending http. %d/%d", sent, datalen);
			_uninstall_socket_(_srv_epoll, _client_socket);
			shutdown(_client_socket, SHUT_RDWR);
			close(_client_socket);
			_client_socket = -1;
			continue;
		}
		free(data);
		data = NULL;
		INC_SENT_HTTP;
		active = time(NULL);
	}
	return NULL;
}

int StartServer()
{
	_msg_heart_hit.version = MSG_NORMAL_VER;
	_msg_heart_hit.type = MSG_TYPE_HEARTHIT;
	_msg_heart_hit.length = htonl(0);

	int nerr = pthread_create(&_srv_thread, NULL, server_thread, NULL);
	if (nerr < 0) return nerr;
	nerr = pthread_create(&_cli_thread, NULL, client_thread, NULL);
	return nerr;
}

void StopServer()
{
	_runing = 0;
	void* result;
	pthread_join(_srv_thread, &result);
	pthread_join(_cli_thread, &result);
}

