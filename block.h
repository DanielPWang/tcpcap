#ifndef _BLOCK_H
#define _BLOCK_H
#include <fun_all.h>

typedef struct BlockItem 
{
	struct hosts_t hClient;		//Client
	struct hosts_t *phServer;		//The list of Server IP of the web
	int nServerIpCount;  	//The count of Server IP
	int nServerID;			//Server ID saved in database
	int nBlockMode;			//1:Block with Server IP 2:Block with Client IP
	time_t nEndTime;   		//The end time for block
} BlockItemDef;

typedef struct BlockReq
{
	int nBlockMode;
	int nTimeLong;
	char szClientIp[24];
	int nServerID;
	int nServerIpLen;
}__attribute__((packed)) BlockReqDef;

typedef struct PseudoHeader       /* pseudo header for TCP checksum calculations */
{
	uint32_t sip;		  /* IP addr */
	uint32_t dip;    	  /* IP addr */
	uint8_t  zero;        /* checksum placeholder */
	uint8_t  protocol;    /* protocol number */
	uint16_t tcplen;      /* TCP packet length */
} PseudoHeaderDef;

#define PACKET_HEADER_LEN  54

int InitBlockProc();
void CleanBlockData(BlockItemDef* pBlockItem);
int FilterBlockList(const char* pPacket);
int GetBlockItemCnt();
int AddBlockData(const char* pRecvData);
int BlockHttpRequest(const char* pPacket);
unsigned short CalcIPSum(unsigned short * w, int blen);
unsigned short CalcTCPSum(unsigned short *h, unsigned short * d, int dlen);

#endif

