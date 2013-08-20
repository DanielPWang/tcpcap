#ifndef __FUN_HTTP_H__
#define __FUN_HTTP_H__

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <fun_all.h>

// int isHTTP(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead);
int HttpInit();
int FilterPacketForHttp(const char* buffer, const struct iphdr* iphead, const struct tcphdr* tcphead);
int IsConfigPort(struct hosts_t *pServer);
int LoadHttpConf(const char* filename);
int GetHttpData(char **data);
int TransGzipData(const char *pGzipData, int nDataLen, char **pTransData);
int AppendServerToClient(int nIndex, const char* pPacket, int bIsCurPack);
int AppendClientToServer(int nIndex, const char* pPacket);
int AppendReponse(const char* packet, int bIsCurPack);
void ShowOpLogInfo(int bIsPrintScreen);


#endif

