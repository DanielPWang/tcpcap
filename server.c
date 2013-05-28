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

#include <define.h>
#include <utils.h>
#include <server.h>
#include <fun_all.h>
#include <fun_http.h>
#include <fun_flow.h>

extern struct hosts_t *_monitor_hosts;
extern size_t _monitor_hosts_count;

extern struct hosts_t *_exclude_hosts;
extern size_t _exclude_hosts_count;

extern pthread_mutex_t _host_ip_lock;

static int _srv_socket = -1;
static int _client_socket = -1;
static char _client_ip[16] = {0};

static int _client_config_socket = -1;
static char _client_config_ip[16] = {0};

static time_t _flow_socket_start_time = 0;

static volatile int _runing = 1;
static pthread_t _srv_thread;
static struct msg_head _msg_heart_hit = {0};

static int SetupTCPServer(int server_port);
static int Unblock(int sock);
static int WriteSocketData(int sock, const void *pBuffer, int nWriteSize);
static int ReadSocketData(int sock, char *pBuffer, int nReadSize);
static int RecvData(int sock, struct msg_head *pMsgHead, char **pData);
static int SendData(int sock, unsigned char msg_type, const void *pData, unsigned int data_length);
static int ProcessReqGetIpList();
static int ProcessReqSetIpList(const char *pRecvData);

volatile int g_nFlagGetData = 0;
volatile int g_nFlagSendData = 0;

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

int WriteSocketData(int sock, const void *pBuffer, int nWriteSize)
{
	int nWrite = 0;
	int nWriteTotal = 0;
	int nRepeatForFD = 0;
	int nRepeatForSel = 0;
	fd_set fdwrite;
	struct timeval tv;

	do
	{
		FD_ZERO(&fdwrite);
		FD_SET(sock, &fdwrite);
		tv.tv_sec = 0;
		tv.tv_usec = SELECT_TIMEOUT;
		int nRet = select(sock + 1, 0, &fdwrite, 0, &tv);
		if (nRet > 0)
		{
			if (FD_ISSET(sock, &fdwrite))
			{
				nWrite = send(sock, pBuffer +  nWriteTotal, nWriteSize - nWriteTotal, 0);
				if (-1 == nWrite)
				{
					if (EAGAIN == errno)
					{
						LOGERROR0("Send data with error EAGAIN");
						return -1;
						//continue;
					}

					return -1;
				}
				else if (0 == nWrite)
				{
					return -1;
				}
				nWriteTotal += nWrite;
			}
			else
			{
				if (++nRepeatForFD >= 10000)
				{
					LOGWARN0("Total time of FD_ISSET=0 is more than 5 minutes!");
					return -1;
				}
			}
		}
		else if (-1 == nRet)
		{
			return -1;
		}
		else if (0 == nRet)
		{
			if (++nRepeatForSel >= 10000)
			{
				LOGWARN0("Total time of selecting timeout is more than 5 minutes!");
				return -1;
			}
		}
	} while (nWriteTotal < nWriteSize);

	return nWriteTotal;
}

int SendData(int sock, unsigned char msg_type, const void *pData, unsigned int data_length)
{
	struct msg_head msgHead;
	msgHead.version = MSG_NORMAL_VER;
	msgHead.type = msg_type;
	msgHead.length = htonl(data_length);
	
	int nSend = WriteSocketData(sock, &msgHead, sizeof(msgHead));
	if ((nSend != -1) && (data_length > 0) && (pData != NULL))
	{
		nSend = WriteSocketData(sock, pData, data_length);
	}

	return nSend;
}

int ReadSocketData(int sock, char *pBuffer, int nReadSize)
{
	int nRead = 0;
	int nRecvTotal = 0;
	int nRepeatForFD = 0;
	int nRepeatForSel = 0;
	fd_set fdread;
	struct timeval tv;

	do
	{
		FD_ZERO(&fdread);
		FD_SET(sock, &fdread);
		tv.tv_sec = 0;
		tv.tv_usec = SELECT_TIMEOUT;
		int nRet = select(sock + 1, &fdread, 0, 0, &tv);
		if (nRet > 0)
		{
			if (FD_ISSET(sock, &fdread))
			{
				nRead = recv(sock, pBuffer +  nRecvTotal, nReadSize - nRecvTotal, 0);
				if (-1 == nRead)
				{
					if (EAGAIN == errno)
					{
						LOGERROR0("Recv data with error EAGAIN");
						return -1;
						//continue;
					}

					return -1;
				}
				else if (0 == nRead)
				{
					return -1;
				}
				nRecvTotal += nRead;
			}
			else
			{
				if (++nRepeatForFD >= 10000)
				{
					LOGWARN0("Total time of FD_ISSET=0 is more than 5 minutes!");
					return -1;
				}
			}
		}
		else if (-1 == nRet)
		{
			return -1;
		}
		else if (0 == nRet)
		{
			if (++nRepeatForSel >= 10000)
			{
				LOGWARN0("Total time of selecting timeout is more than 5 minutes!");
				return -1;
			}
		}
	} while (nRecvTotal < nReadSize);

	return nRecvTotal;
}

int RecvData(int sock, struct msg_head *pMsgHead, char **pData)
{
	memset(pMsgHead, 0, sizeof(struct msg_head));
	if (ReadSocketData(sock, (char*)pMsgHead, sizeof(struct msg_head)) < 0)
	{
		LOGERROR0("Read socket head data failed!");
		return -1;
	}

	if (pMsgHead->version != MSG_NORMAL_VER)
	{
		LOGERROR0("Message version error!");
		return -1;
	}

	if ((pMsgHead->type != MSG_TYPE_REQ_GET_IPLIST)
		&& (pMsgHead->type != MSG_TYPE_REQ_SET_IPLIST)
		&& (pMsgHead->type != MSG_TYPE_REQ_FLOW)
		&& (pMsgHead->type != MSG_TYPE_REQ_FLOW_STOP)
		&& (pMsgHead->type != MSG_TYPE_REQ_FLOW))
	{
		LOGERROR0("Message type error!");
		return -1;
	}
		
	pMsgHead->length = ntohl(pMsgHead->length);
	if (0 == pMsgHead->length)
		return 0;

	*pData = (char*)calloc(1, pMsgHead->length+1);
	if (ReadSocketData(sock, *pData, pMsgHead->length) < 0)
	{
		LOGERROR0("Read socket body data failed!");
		free(*pData);
		return -1;
	}
		
	return pMsgHead->length;
}


int SetupTCPServer(int server_port)
{
	_srv_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (_srv_socket < 0)
		return -1;

	int nerr = 0;
	int sockopt = 1;
	nerr = setsockopt(_srv_socket, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
	if (nerr < 0)
	{
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
	if (nerr < 0)
	{
		LOGERROR0("bind failed");
		close(_srv_socket);
		return -1;
	}

	nerr = listen(_srv_socket, 5);
	if (nerr < 0)
	{
		LOGERROR0("listen failed");
		close(_srv_socket);
		return -1;
	}
	
	return _srv_socket;
}

int ProcessReqGetIpList()
{
	LOGDEBUG0("Receive request info for getting ip list.");

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
	
	LOGDEBUG0("Send response ip list info.");
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
	
	LOGDEBUG0("Receive request info for setting ip list.");

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

			LOGDEBUG("Set monitor host with client request: %s", ipport);
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

			LOGDEBUG("Exclude host with client req %s", ipport);
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
	
	LOGDEBUG0("Send response OK for setting ip list request.");
	nSend = SendData(_client_config_socket, MSG_TYPE_RES_OK, NULL, 0);
	if (nSend < 0) 
	{
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
	if (nPort <= 0 || nPort > 65535)
	{
		LOGERROR0("Get server port failed, set default port.");
		nPort = SERVER_PORT;
	}
	
thread_start:
	if (SetupTCPServer(nPort) < 0)
	{
		LOGERROR0("Setup TCP Server failed");
		return NULL;
	}
	Unblock(_srv_socket);
	
	int nerr = 0;
	fd_set rfds;
	fd_set wfds;
	struct timeval	tv;
	int retval = 0;
	int max_socket = 0;
	time_t active = time(NULL);
	while (_runing) 
	{
while_start:
	
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		tv.tv_sec = 0;
		tv.tv_usec = SELECT_TIMEOUT;

		FD_SET(_srv_socket, &rfds);
		max_socket = _srv_socket;
		if (_client_socket > 0)
		{
			FD_SET(_client_socket, &rfds);
			if (_client_socket > max_socket) 
				max_socket = _client_socket;
		}
		if (_client_config_socket > 0)
		{
			FD_SET(_client_config_socket, &rfds);
			if (_client_config_socket > max_socket) 
				max_socket = _client_config_socket;
		}
		
		retval = select(max_socket+1, &rfds, 0, 0, &tv);
		if (retval < 0)
		{
			LOGERROR("select error. [%d] %s", errno, strerror(errno));
			close(_srv_socket);
			if (_client_socket > 0)
			{
				close(_client_socket);
				_client_socket = -1;
			}
			if (_client_config_socket > 0)
			{
				close(_client_config_socket);
				_client_config_socket = -1;
			}
			goto thread_start;
		}

		if (FD_ISSET(_srv_socket, &rfds))
		{
			int	accept_socket;
			struct sockaddr_in client_address; 
			socklen_t client_len;
			client_len = sizeof(client_address);
			LOGINFO0("Process accept...");
			accept_socket = accept(_srv_socket, (struct sockaddr *)&client_address, &client_len);
			if (accept_socket > 0)
			{
				char sip[16] = {0};
				int nPort = 0;
				
				Unblock(accept_socket);

				inet_ntop(AF_INET, &client_address.sin_addr, sip, 16);
				nPort = ntohs(client_address.sin_port);
				
				LOGINFO("%s:%d connect, accept successfully.", sip, nPort);

				if ((nPort >= CLIENT_SOCKET_PORT_MIN && nPort <= CLIENT_SOCKET_PORT_MAX) || CLIENT_SOCKET_PORT == nPort)
				{
					if (_client_socket > 0)
					{
						LOGWARN0("A client has connected sensor, new connection will be closed.");
						int nSend = SendData(accept_socket, MSG_TYPE_NOTIFY_CONNECTION_EXIST, _client_ip, strlen(_client_ip));
						if (nSend < 0) 
						{
							LOGWARN0("remote socket is error or close. recontinue.");
							close(accept_socket);
						}
						else
						{
							shutdown(accept_socket, SHUT_RDWR);
							close(accept_socket);
						}
					}
					else
					{
						_client_socket = accept_socket;
						memset(_client_ip, 0, 16);
						strcpy(_client_ip, sip);
					}
				}
				else if (CLIENT_CONFIG_SOCKET_PORT == nPort)
				{
					if (_client_config_socket > 0)
					{
						LOGWARN0("A config client has connected sensor, new connection will be closed.");
						int nSend = SendData(accept_socket, MSG_TYPE_NOTIFY_CONNECTION_EXIST, _client_config_ip, strlen(_client_config_ip));
						if (nSend < 0) 
						{
							LOGWARN0("remote socket is error or close. recontinue.");
							close(accept_socket);
						}
						else
						{
							shutdown(accept_socket, SHUT_RDWR);
							close(accept_socket);
						}
					}
					else
					{
						_client_config_socket = accept_socket;
						memset(_client_config_ip, 0, 16);
						strcpy(_client_config_ip, sip);
					}
				}
				else if (CLIENT_TEST_SOCKET_PORT == nPort)
				{
					shutdown(accept_socket, SHUT_RDWR);
					close(accept_socket);
				}
				else
				{
					shutdown(accept_socket, SHUT_RDWR);
					close(accept_socket);
				}
			}
			else
				LOGERROR("accept error. [%d] %s", errno, strerror(errno));
		}

		if (_client_config_socket > 0)
		{
			if (FD_ISSET(_client_config_socket, &rfds))
			{
				struct msg_head msgHead;
				char *pRecvData = NULL;
				int nRecv = RecvData(_client_config_socket, &msgHead, &pRecvData);
				if (nRecv < 0)
				{
					LOGWARN0("remote config socket is error or close. recontinue.");
					close(_client_config_socket);
					_client_config_socket = -1;
				}
				else
				{
					int nSend = 0;
					if (MSG_TYPE_REQ_GET_IPLIST == msgHead.type)
					{
						nSend = ProcessReqGetIpList();
					}
					else if (MSG_TYPE_REQ_SET_IPLIST == msgHead.type)
					{
						nSend = ProcessReqSetIpList(pRecvData);
					}

					if (pRecvData != NULL)
						free(pRecvData);
				}
			}
		}

		if (_client_socket > 0)
		{
			if (FD_ISSET(_client_socket, &rfds))
			{
				struct msg_head msgHead;
				char *pRecvData = NULL;
				int nRecv = RecvData(_client_socket, &msgHead, &pRecvData);
				if (nRecv < 0)
				{
					LOGWARN0("remote client socket is error or close. recontinue.");
					close(_client_socket);
					_client_socket = -1;
				}
				else
				{
					if (MSG_TYPE_REQ_FLOW == msgHead.type)
					{
						AddServer(pRecvData);
						if (0 == _flow_socket_start_time)
							_flow_socket_start_time = time(NULL);
					}
					else if (MSG_TYPE_REQ_FLOW_STOP == msgHead.type)
					{
						StopServerFlow(pRecvData);
					}

					if (pRecvData != NULL)
						free(pRecvData);
				}
			}

			if (_client_socket > 0)
			{
				char *data = NULL;
				size_t datalen = 0;
				int nSend = 0;
				g_nFlagGetData = 0;
				if ((datalen = GetHttpData(&data)) > 0) 
				{
					g_nFlagGetData = 1;
					g_nFlagSendData = 0;
					LOGDEBUG("send http_info[%d] %s", datalen, data);
					nSend = SendData(_client_socket, MSG_TYPE_HTTP, data, datalen);
					free((void*)data);
					g_nFlagSendData = 1;
					if (nSend < 0) 
					{
						LOGWARN0("remote client socket is error or close. recontinue.");
						close(_client_socket);
						_client_socket = -1;
						goto while_start;
					}
					active = time(NULL);
				}
				g_nFlagGetData = 1;
				
				if ((_flow_socket_start_time != 0) && (time(NULL) - _flow_socket_start_time > FLOW_SEND_INTERVAL_TIME))
				{
					int nServerCount = GetServerCount();
					LOGDEBUG("Ready to send flow info, Server flow count = %d", nServerCount);
					if (nServerCount > 0)
					{
						time_t tmNow = time(NULL);
						for (int i = 0; i < MAX_FLOW_SESSIONS; i++)
						{
							if ((datalen = GetFlowData(i, tmNow, &data)) > 0)
							{
								LOGDEBUG("Send flow data of _flow_session[%d]", i);
								nSend = SendData(_client_socket, MSG_TYPE_RES_FLOW_DATA, data, datalen);
								free((void*)data);
								if (nSend < 0) 
								{
									LOGWARN0("remote client socket is error or close. recontinue.");
									close(_client_socket);
									_client_socket = -1;
									goto while_start;
								}	
							}
						}
						
						_flow_socket_start_time = time(NULL);
					}
					else
					{
						_flow_socket_start_time = 0;
					}
				}
				
				if (time(NULL) - active > 10) 
				{
					active = time(NULL);
					nSend = SendData(_client_socket, MSG_TYPE_HEARTHIT, NULL, 0);
					if (nSend < 0) {
						LOGWARN0("remote client socket is error or close. recontinue.");
						close(_client_socket);
						_client_socket = -1;
						goto while_start;
					}
				}
			}
		}
	}

	if (_client_socket > 0)
	{
		shutdown(_client_socket, SHUT_RDWR);
		close(_client_socket);
	}
	
	shutdown(_srv_socket, SHUT_RDWR);
	close(_srv_socket);
	return NULL;
}

int StartServer()
{
	_msg_heart_hit.version = MSG_NORMAL_VER;
	_msg_heart_hit.type = MSG_TYPE_HEARTHIT;
	_msg_heart_hit.length = htonl(0);

	int nerr = pthread_create(&_srv_thread, NULL, server_thread, NULL);
	return nerr;
}

void StopServer()
{
	_runing = 0;
	void* result;
	pthread_join(_srv_thread, &result);
}

