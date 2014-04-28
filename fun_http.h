#ifndef __FUN_HTTP_H__
#define __FUN_HTTP_H__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fun_all.h>

enum HTTP_SESSION_FLAGS { 
	HTTP_SESSION_IDL, 
	HTTP_SESSION_REQUESTING,
	HTTP_SESSION_REQUEST, 
	HTTP_SESSION_REPONSE, 
	HTTP_SESSION_REPONSEING,
	HTTP_SESSION_FINISH
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
	HTTP_CONTENT_RES,
	HTTP_CONTENT_FILE_PDF,
	HTTP_CONTENT_FILE_KDH,
	HTTP_CONTENT_FILE_CEB,
	HTTP_CONTENT_FILE_CAJ,
	HTTP_CONTENT_FILE_MARC,
	HTTP_CONTENT_FILE_RIS,
	HTTP_CONTENT_FILE_BIB,
	HTTP_CONTENT_FILE_TXT,
	HTTP_CONTENT_FILE_PDG,
	HTTP_CONTENT_FILE_EXCEL,
	HTTP_CONTENT_FILE_RTF,
	HTTP_CONTENT_FILE_OTHER
};

enum HTTP_APPEND_STATUS { 
	HTTP_APPEND_DROP_PACKET = -1,
	HTTP_APPEND_ADD_PACKET = 0,
	HTTP_APPEND_ADD_PACKET_LATER,
	HTTP_APPEND_FINISH_LATER,
	HTTP_APPEND_FINISH_CURRENT
};

enum HTTP_SESSION_FINISH_TYPE { 
	HTTP_SESSION_FINISH_SUCCESS,
	HTTP_SESSION_FINISH_TIMEOUT,
	HTTP_SESSION_FINISH_CHANNEL_REUSED,
	HTTP_SESSION_FINISH_UNKNOWN_DATA,
	HTTP_SESSION_FINISH_DISORDER_REBUILD_FAILED
};

enum HTTP_SPECIAL_STATE { 
	HTTP_SPECIAL_STATE_TIMEOUT = 900,
	HTTP_SPECIAL_STATE_CHANNEL_REUSED,
	HTTP_SPECIAL_STATE_UNKNOWN_DATA,
	HTTP_SPECIAL_STATE_DISORDER_REBUILD_FAILED
};


// int isHTTP(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead);
int HttpInit();
int FilterPacketForHttp(int nFdIndex, const char* buffer, int nBufferLen, const struct iphdr* iphead, const struct tcphdr* tcphead);
int IsConfigPort(struct hosts_t *pServer);
int LoadHttpConf(const char* filename);
int GetHttpData(char **data);
int TransGzipData(const char *pGzipData, int nDataLen, char **pTransData);
int AppendServerToClient(int nThreadIndex, int nIndex, const char* pPacket, int bIsCurPack, int nIsForceRestore);
int AppendClientToServer(int nThreadIndex, int nIndex, const char* pPacket);
int AppendReponse(int nThreadIndex, const char* packet);
int AppendLaterPacket(int nThreadIndex, int nIndex, int nIsForceRestore);
void ShowOpLogInfo(int bIsPrintScreen);
void StopHttpThread();

void LogDropSessionData(const char *pszDropType, const struct tcp_session *pSession);
void LogDataItems(const struct tcp_session *pSession, int nState, int nDataSize);
void SessionTimeoutProcess();



#endif

