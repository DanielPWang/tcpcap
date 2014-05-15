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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <define.h>
#include <utils.h>
#include <block.h>

static int g_block_socket = -1;
static int g_bIsExistMac = 0;
static uint8_t g_destMac[6] = {0};
static struct sockaddr_ll g_sa = {0};
unsigned int g_ipID = 0x005d;
static int g_nBlockItemCount = 0;

static BlockItemDef* g_block_list = NULL;
pthread_mutex_t g_block_list_lock = PTHREAD_MUTEX_INITIALIZER;

int InitBlockProc()
{
	if((g_block_socket = socket(PF_PACKET, SOCK_RAW, htons(IPPROTO_TCP))) == -1)
	{		
		g_block_socket = -1;
		LOGERROR0("Fail to create block socket!");
		return 0;
	}

	char szBlock[10] = {0};
	GetValue(CONFIG_PATH, "block", szBlock, 6);

	char szDescMac[30] = {0};
	if (GetValue(CONFIG_PATH, "block_dest_mac", szDescMac, 29) != NULL)
	{
		if (strcmp(szDescMac, "00-00-00-00-00-00") != 0)
		{
			char *left, *right, *mac;
			char *pszEnd;
			int i = 0;
			for (left = szDescMac; i < 6; left = NULL, i++) 
			{
				mac = strtok_r(left, "-", &right);
				if (NULL == mac) 
					break;
				
				g_destMac[i] = (uint8_t)strtol(mac, &pszEnd, 16);
			}

			printf("Block dest mac is config to %x-%x-%x-%x-%x-%x \n", 
				g_destMac[0], g_destMac[1], g_destMac[2], g_destMac[3], g_destMac[4], g_destMac[5]);
			LOGFIX("Block dest mac is config to %x-%x-%x-%x-%x-%x \n", 
				g_destMac[0], g_destMac[1], g_destMac[2], g_destMac[3], g_destMac[4], g_destMac[5]);
			
			g_bIsExistMac = 1;	
		}
		else
		{
			LOGWARN("Block dest mac is not config!", CONFIG_PATH);
			printf("Block dest mac is not config!\n");
		}
	}
	else
	{
		LOGWARN("Block dest mac is not config!", CONFIG_PATH);
		printf("Block dest mac is not config!\n");
	}
	
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name, szBlock);	
	if (ioctl(g_block_socket, SIOCGIFINDEX, &ifstruct) == -1)
	{
		g_block_socket = -1;
		LOGERROR("Fail to get ifstruct info! Interface is %s", szBlock);
		return 0;
	}
	
	g_sa.sll_ifindex = ifstruct.ifr_ifindex;

	ASSERT(g_block_list == NULL);
	g_block_list = (BlockItemDef*)calloc(sizeof(BlockItemDef), MAX_BLOCK_ITEM);

	ASSERT(g_block_list != NULL);
	memset(g_block_list, 0, sizeof(BlockItemDef)*MAX_BLOCK_ITEM);
	
	return 1;
}

int GetBlockItemCnt()
{
	return g_nBlockItemCount;
}

void CleanBlockData(BlockItemDef* pBlockItem)
{
	if (0 == pBlockItem->nBlockMode)
		return;

	if (pBlockItem->phServer != NULL)
	{
		free(pBlockItem->phServer);
		pBlockItem->phServer = NULL;
	}
	
	memset(pBlockItem, 0, sizeof(BlockItemDef));
	g_nBlockItemCount--;
}

int AddBlockData(const char* pRecvData)
{
	ASSERT(pRecvData != NULL);

	int nRs = 0;
	BlockReqDef *pReq = (BlockReqDef*)pRecvData;
	BlockItemDef *pBlockItemIdle = NULL;

	pthread_mutex_lock(&g_block_list_lock);

	pReq->nBlockMode = ntohl(pReq->nBlockMode);
	pReq->nTimeLong = ntohl(pReq->nTimeLong);
	pReq->nServerID = ntohl(pReq->nServerID);
	pReq->nServerIpLen = ntohl(pReq->nServerIpLen);
		
	pReq->nBlockMode++;
	
	for (int i = 0; i < MAX_BLOCK_ITEM; i++)
	{
		BlockItemDef *pBlockItem = &g_block_list[i];
		if (pBlockItem->nBlockMode != 0)
		{
			if (pBlockItem->nEndTime <= time(NULL))
				CleanBlockData(pBlockItem);
		}
	}

	struct in_addr tmpClientIp;
	if (2 == pReq->nBlockMode)
	{
		inet_aton(pReq->szClientIp, &tmpClientIp);
	}
	
	for (int i = 0; i < MAX_BLOCK_ITEM; i++)
	{
		BlockItemDef *pBlockItem = &g_block_list[i];
		if ((pBlockItem->nBlockMode != 0)
			 && (pBlockItem->nBlockMode == pReq->nBlockMode))
		{
			if (1 == pReq->nBlockMode)
			{
				if (pReq->nServerID == pBlockItem->nServerID)
				{
					//pBlockItem->nEndTime = time(NULL) + pReq->nTimeLong;
					nRs = 1;
					break;
				}
			}
			else if (2 == pReq->nBlockMode)
			{
				if ((tmpClientIp.s_addr == pBlockItem->hClient.ip.s_addr) 
					 && (pReq->nServerID == pBlockItem->nServerID))
				{
					//pBlockItem->nEndTime = time(NULL) + pReq->nTimeLong;
					nRs = 1;
					break;
				}
			}
		}
		else if ((pBlockItemIdle == NULL)
			      && (pBlockItem->nBlockMode == 0))
		{
			pBlockItemIdle = pBlockItem;
		}
	}

	if (0 == nRs)
	{
		if (pBlockItemIdle != NULL)
		{
			char* pServerIpTmp = (char*)calloc(1, pReq->nServerIpLen+1);
			if (pServerIpTmp != NULL)
			{
				strncpy(pServerIpTmp, pRecvData+sizeof(BlockReqDef), pReq->nServerIpLen);

				if (2 == pReq->nBlockMode)
				{
					str_ipp(pReq->szClientIp, &pBlockItemIdle->hClient);
				}
				
				if ((1 == pReq->nBlockMode) || (2 == pReq->nBlockMode))
				{
					pBlockItemIdle->nBlockMode = pReq->nBlockMode;
					pBlockItemIdle->nServerID = pReq->nServerID;
					pBlockItemIdle->nServerIpCount = count_char(pServerIpTmp, ',') + 1;
					pBlockItemIdle->phServer = (struct hosts_t *)calloc(sizeof(struct hosts_t), pBlockItemIdle->nServerIpCount);
					memset(pBlockItemIdle->szBlockInfo, 0, sizeof(pBlockItemIdle->szBlockInfo));
					strcpy(pBlockItemIdle->szBlockInfo, pReq->szBlockInfo);
						
					LOGINFO("Add Block Item; Block Mode=%d, \n \
								Client IP=%s, \n \
								Server ID=%d, \n \
								Server Count=%d, \n \
								Server IP=%s, \n \
								Time Long=%d", 
								pReq->nBlockMode,
								pReq->szClientIp,
								pReq->nServerID,
								pBlockItemIdle->nServerIpCount,
								pServerIpTmp,
								pReq->nTimeLong);
					
					char *left = NULL, *right = NULL, *ipport = NULL;
					int i = 0;
					for (left = pServerIpTmp; ;left = NULL) 
					{
						ipport = strtok_r(left, ",", &right);
						if (NULL == ipport) 
							break;

						if (str_ipp(ipport, &pBlockItemIdle->phServer[i])) 
							++i;
					}
					
					pBlockItemIdle->nEndTime = time(NULL) + pReq->nTimeLong;
					g_nBlockItemCount++;
				}
				else
				{
					LOGERROR("Request block mode is wrong, block mode = %d", pReq->nBlockMode);
					nRs = -1;
				}
				
				if (pServerIpTmp != NULL)
				{
					free(pServerIpTmp);
					pServerIpTmp = NULL;
				}
			}
			else
			{
				LOGERROR("Malloc memory failed! length=%d", pReq->nServerIpLen+1);
				nRs = -1;
			}
		}
		else
		{
			nRs = -1;
		}
	}

	pthread_mutex_unlock(&g_block_list_lock);
	
	return nRs;
}

int FilterBlockList(const char* pPacket)
{
	int nRs = -1;
	struct iphdr *pReqIphead = IPHDR(pPacket);
	struct tcphdr *pReqTcphead = TCPHDR(pReqIphead);

	pthread_mutex_lock(&g_block_list_lock);
	
	for (int i = 0; i < MAX_BLOCK_ITEM; i++)
	{
		BlockItemDef *pBlockItem = &g_block_list[i];
		if (pBlockItem->nBlockMode != 0)
		{
			if (pBlockItem->nEndTime > time(NULL))
			{
				if (1 == pBlockItem->nBlockMode)
				{
					for (int j = 0; j < pBlockItem->nServerIpCount; j++)
					{
						if ((pReqIphead->daddr == pBlockItem->phServer[j].ip.s_addr)
							 && ((pBlockItem->phServer[j].port == 0)
							 	 || (pReqTcphead->dest == pBlockItem->phServer[j].port)))
						{
							nRs = i;
							break;
						}
					}
				}
				else if (2 == pBlockItem->nBlockMode)
				{
					if (pReqIphead->saddr == pBlockItem->hClient.ip.s_addr)
					{
						for (int j = 0; j < pBlockItem->nServerIpCount; j++)
						{
							if ((pReqIphead->daddr == pBlockItem->phServer[j].ip.s_addr)
								 && ((pBlockItem->phServer[j].port == 0)
								 	 || (pReqTcphead->dest == pBlockItem->phServer[j].port)))
							{
								nRs = i;
								break;
							}
						}
					}
				}

				if (nRs != -1)
					break;
			}
			else
				CleanBlockData(pBlockItem);
		}
	}

	pthread_mutex_unlock(&g_block_list_lock);
	
	return nRs;
}

int BlockHttpRequest(const char* pPacket, int nBlockItemIndex)
{
	if (-1 == g_block_socket)
		return 0;
	
	/* SENDING BLOCK PAGE TO CLIENT */
	uint8_t szBlockBuffer[3000] = {0};
	char szBlockHtml[1700] = {0};
	char szBlockHttpContent[2000] = {0};
	
	struct ether_header* pRespEtherHdr = (struct ether_header*)(szBlockBuffer);
	struct iphdr*  pRespIpHdr = (struct iphdr*)(szBlockBuffer + sizeof(struct ether_header));
	struct tcphdr* pRespTcpHdr	= (struct tcphdr*)(szBlockBuffer + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *pEtherhead = (struct ether_header*)pPacket;
	struct iphdr *pReqIphead = IPHDR(pPacket);
	struct tcphdr *pReqTcphead = TCPHDR(pReqIphead);

	/* Create block buffer */
	BlockItemDef *pBlockItem = &g_block_list[nBlockItemIndex];
	memset(szBlockHtml, 0, sizeof(szBlockHtml));
	strcpy(szBlockHtml, "<html><head><title>ERU Block Page</title></head><body><TABLE height=\"100%\" width=\"100%\"><TR><TD align=\"left\" valign=\"top\"><FONT size=\"4\">");
	strcat(szBlockHtml, pBlockItem->szBlockInfo);
	strcat(szBlockHtml, "</FONT></TD></TR></TABLE></body></html>\n");
	
	sprintf(szBlockHttpContent, 
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/html; charset=utf-8\r\n"
				"Content-Length: %d\r\n"
				"Connection: close\r\n\r\n%s",
				strlen(szBlockHtml), szBlockHtml);

	uint32_t nBlockContentLen = strlen(szBlockHttpContent);
	memcpy(szBlockBuffer + PACKET_HEADER_LEN, szBlockHttpContent, nBlockContentLen);

	//memcpy(pRespEtherHdr->ether_shost, pEtherhead->ether_dhost, 6);
	if (g_bIsExistMac)
		memcpy(pRespEtherHdr->ether_dhost, g_destMac, 6);
	else
		memcpy(pRespEtherHdr->ether_dhost, pEtherhead->ether_shost, 6);
	
	pRespEtherHdr->ether_shost[0] = 0x00;
	pRespEtherHdr->ether_shost[1] = 0x9c;
	pRespEtherHdr->ether_shost[2] = 0x1d;
	pRespEtherHdr->ether_shost[3] = 0xb8;
	pRespEtherHdr->ether_shost[4] = 0x00;
	pRespEtherHdr->ether_shost[5] = 0xf2;
	pRespEtherHdr->ether_type = htons(ETHERTYPE_IP);
	
	pRespIpHdr->check = 0;
	pRespIpHdr->ihl = 5;
	pRespIpHdr->version = 4;
	pRespIpHdr->daddr = pReqIphead->saddr;
	pRespIpHdr->saddr = pReqIphead->daddr;
	pRespIpHdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + nBlockContentLen);
	pRespIpHdr->tos = 0;
	pRespIpHdr->ttl = 64;
	swab((unsigned char*)&g_ipID, (unsigned char*)&pRespIpHdr->id, 2);
	g_ipID += 0x100;
	pRespIpHdr->frag_off = 0;
	pRespIpHdr->protocol = 6;
	pRespIpHdr->check = CalcIPSum((unsigned short*)pRespIpHdr, pRespIpHdr->ihl << 2);

	int nReqContentLen = ntohs(pReqIphead->tot_len) - pReqIphead->ihl*4 - pReqTcphead->doff*4;
	pRespTcpHdr->ack_seq = htonl(ntohl(pReqTcphead->seq) + nReqContentLen);
	pRespTcpHdr->seq = pReqTcphead->ack_seq;
	pRespTcpHdr->source = pReqTcphead->dest;
	pRespTcpHdr->dest = pReqTcphead->source;
	pRespTcpHdr->fin = 1;
	pRespTcpHdr->syn = 0;
	pRespTcpHdr->rst = 0;
	pRespTcpHdr->psh = 0;
	pRespTcpHdr->ack = 1;
	pRespTcpHdr->urg = 0;
	pRespTcpHdr->doff = 5;
	pRespTcpHdr->res1 = 0;
	pRespTcpHdr->window = pReqTcphead->window;
	pRespTcpHdr->urg_ptr = 0;
	pRespTcpHdr->check = 0;

	PseudoHeaderDef ph;    /* pseudo header declaration */
	ph.sip = (uint32_t)(pReqIphead->daddr);
	ph.dip = (uint32_t)(pReqIphead->saddr);
	ph.zero = 0;
	ph.protocol = 6;
	ph.tcplen = htons((u_short)(sizeof(struct tcphdr) + nBlockContentLen));

	pRespTcpHdr->check = CalcTCPSum((uint16_t*)&ph, (uint16_t*)pRespTcpHdr, sizeof(struct tcphdr) + nBlockContentLen);

	if ((sendto(g_block_socket ,
				(const char*)(szBlockBuffer), 
				sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + nBlockContentLen, 
				0,
				(struct sockaddr *)&g_sa, 
				sizeof(g_sa))) == -1)
	{		
		struct in_addr sip; 
		struct in_addr dip; 
		sip.s_addr = pRespIpHdr->daddr;
		dip.s_addr = pRespIpHdr->saddr;
		char ssip[16], sdip[16];
		LOGERROR("Fail to Send pseudo data to client(%s => %s)!", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
		LOGERROR("Error no = %d; error string is %s", errno, strerror(errno));
		
		return 0;
	}	

	/* SENDING TCP RESET TO SERVER */
/*	memset(szBlockBuffer, 0, PACKET_HEADER_LEN);
	struct ether_header* pRstEtherHdr = (struct ether_header*)(szBlockBuffer);
	struct iphdr*  pRstIpHdr = (struct iphdr*)(szBlockBuffer + sizeof(struct ether_header));
	struct tcphdr* pRstTcpHdr	= (struct tcphdr*)(szBlockBuffer + sizeof(struct ether_header) + sizeof(struct iphdr));

	memcpy(pRstEtherHdr->ether_dhost, pEtherhead->ether_dhost, 6);
	memcpy(pRstEtherHdr->ether_shost, pEtherhead->ether_shost, 6);
	pRstEtherHdr->ether_type = htons(ETHERTYPE_IP);
	
	pRstIpHdr->check = 0;
	pRstIpHdr->ihl = 5;
	pRstIpHdr->version = 4;
	pRstIpHdr->daddr = pReqIphead->daddr;
	pRstIpHdr->saddr = pReqIphead->saddr;
	pRstIpHdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
	pRstIpHdr->tos = pReqIphead->tos;
	pRstIpHdr->ttl = pReqIphead->ttl;
	pRstIpHdr->id = htons(1337);
	pRstIpHdr->frag_off = 0;
	pRstIpHdr->protocol = 6;
	pRstIpHdr->check = CalcIPSum((unsigned short*)pRstIpHdr, pRstIpHdr->ihl << 2);

	pRstTcpHdr->ack_seq = pReqTcphead->ack_seq;
	pRstTcpHdr->seq = pReqTcphead->seq;
	pRstTcpHdr->source = pReqTcphead->source;
	pRstTcpHdr->dest = pReqTcphead->dest;
	pRstTcpHdr->fin = 0;
	pRstTcpHdr->syn = 0;
	pRstTcpHdr->rst = 1;
	pRstTcpHdr->psh = 0;
	pRstTcpHdr->ack = 0;
	pRstTcpHdr->urg = 0;
	pRstTcpHdr->doff = 5;
	pRstTcpHdr->res1 = 0;
	pRstTcpHdr->window = pReqTcphead->window;
	pRstTcpHdr->urg_ptr = 0;
	pRstTcpHdr->check = 0;

	ph.sip = (uint32_t)(pReqIphead->saddr);
	ph.dip = (uint32_t)(pReqIphead->daddr);
	ph.zero = 0;
	ph.protocol = 6;
	ph.tcplen = htons((u_short)(sizeof(struct tcphdr)));
	
	pRstTcpHdr->check = CalcTCPSum((uint16_t*)&ph, (uint16_t*)pRstTcpHdr, sizeof(struct tcphdr));

	if ((sendto(g_block_socket ,
				(const char*)(szBlockBuffer), 
				sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr), 
				0,
				(struct sockaddr *)&g_sa, 
				sizeof(g_sa))) == -1)
	{		
		struct in_addr sip; 
		struct in_addr dip; 
		sip.s_addr = pRespIpHdr->saddr;
		dip.s_addr = pRespIpHdr->daddr;
		char ssip[16], sdip[16];
		LOGERROR("Fail to Send pseudo data to server(%s => %s)!", strcpy(ssip, inet_ntoa(sip)), strcpy(sdip,inet_ntoa(dip)));
		LOGERROR("Error no = %d; error string is %s", errno, strerror(errno));
		
		return 0;
	}
*/
	return 1;
}

unsigned short
CalcIPSum(unsigned short * w, int blen)
{
	unsigned int cksum;

	/* IP must be >= 20 bytes */
	cksum  = w[0];
	cksum += w[1];
	cksum += w[2];
	cksum += w[3];
	cksum += w[4];
	cksum += w[5];
	cksum += w[6];
	cksum += w[7];
	cksum += w[8];
	cksum += w[9];

	blen  -= 20;
	w     += 10;

	while( blen ) /* IP-hdr must be an integral number of 4 byte words */
	{
		cksum += w[0];
		cksum += w[1];
		w     += 2;
		blen  -= 4;
	}

	cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
	cksum += (cksum >> 16);

	return (unsigned short) (~cksum);
}

unsigned short
CalcTCPSum(unsigned short *h, unsigned short * d, int dlen)
{
	unsigned int cksum;
	unsigned short answer=0;

	/* PseudoHeader must have 12 bytes */
	cksum  = h[0];
	cksum += h[1];
	cksum += h[2];
	cksum += h[3];
	cksum += h[4];
	cksum += h[5];

	/* TCP hdr must have 20 hdr bytes */
	cksum += d[0];
	cksum += d[1];
	cksum += d[2];
	cksum += d[3];
	cksum += d[4];
	cksum += d[5];
	cksum += d[6];
	cksum += d[7];
	cksum += d[8];
	cksum += d[9];

	dlen  -= 20; /* bytes   */
	d     += 10; /* short's */ 

	while(dlen >=32)
	{
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		cksum += d[4];
		cksum += d[5];
		cksum += d[6];
		cksum += d[7];
		cksum += d[8];
		cksum += d[9];
		cksum += d[10];
		cksum += d[11];
		cksum += d[12];
		cksum += d[13];
		cksum += d[14];
		cksum += d[15];
		d     += 16;
		dlen  -= 32;
	}

	while(dlen >=8)  
	{
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		d     += 4;   
		dlen  -= 8;
	}

	while(dlen > 1)
	{
		cksum += *d++;
		dlen  -= 2;
	}

	if( dlen == 1 ) 
	{ 
		*(unsigned char*)(&answer) = (*(unsigned char*)d);
		cksum += answer;
	}

	cksum  = (cksum >> 16) + (cksum & 0x0000ffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

