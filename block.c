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

#include <utils.h>
#include <block.h>

static int g_block_socket = -1;
const char g_szBlockHtml[] = "<html><head><title>ERU Block Page</title></head><body><TABLE height=\"100%\" width=\"100%\"><TR><TD align=\"center\"><h1>This page is restricted by ERU!</h1></TD></TR></TABLE></body></html>\n";
static uint8_t g_szBlockBuffer[512] = {0};
static uint32_t g_nBlockBufferLen = 0;
static struct sockaddr_ll g_sa = {0};


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

/*int InitBlockProc()
{
	sprintf((char*)g_szBlockBuffer + PACKET_HEADER_LEN, 
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/html\r\n"
				"Content-Length: %d\r\n"
				"Connection: close\r\n\r\n%s",
				strlen(g_szBlockHtml), g_szBlockHtml);
	
	g_nBlockBufferLen = strlen(g_szBlockBuffer + PACKET_HEADER_LEN);
	if((g_block_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{		
		g_block_socket = -1;
		LOGERROR0("Fail to create block socket!");
		return 0;
	}

	int optval;
	if(setsockopt(g_block_socket, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval)) == -1)
	{	
		g_block_socket = -1;
		LOGERROR0("Fail to create block socket!");
		return 0;
	}

	return 1;
}
*/

int InitBlockProc()
{
	sprintf((char*)g_szBlockBuffer + PACKET_HEADER_LEN, 
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: text/html\r\n"
				"Content-Length: %d\r\n"
				"Connection: close\r\n\r\n%s",
				strlen(g_szBlockHtml), g_szBlockHtml);
	
	g_nBlockBufferLen = strlen(g_szBlockBuffer + PACKET_HEADER_LEN);
	if((g_block_socket = socket(PF_INET, SOCK_RAW, htons(IPPROTO_TCP))) == -1)
	{		
		g_block_socket = -1;
		LOGERROR0("Fail to create block socket!");
		return 0;
	}

	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name, "eth0");	
	if (ioctl(g_block_socket, SIOCGIFINDEX, &ifstruct) == -1)
	{
		g_block_socket = -1;
		LOGERROR0("Fail to get ifstruct info!");
		return 0;
	}
	
	g_sa.sll_ifindex = ifstruct.ifr_ifindex;
	
	return 1;
}


int BlockHttpRequest(const char* pPacket)
{
	//struct sockaddr_in dest;
	//dest.sin_family = AF_INET;
	
	/* SENDING BLOCK PAGE TO CLIENT */
	memset(g_szBlockBuffer, 0, PACKET_HEADER_LEN);
	struct ether_header* pRespEtherHdr = (struct ether_header*)(g_szBlockBuffer);
	struct iphdr*  pRespIpHdr = (struct iphdr*)(g_szBlockBuffer + sizeof(struct ether_header));
	struct tcphdr* pRespTcpHdr	= (struct tcphdr*)(g_szBlockBuffer + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *pEtherhead = (struct ether_header*)pPacket;
	struct iphdr *pReqIphead = IPHDR(pPacket);
	struct tcphdr *pReqTcphead = TCPHDR(pReqIphead);

	memcpy(pRespEtherHdr->ether_dhost, pEtherhead->ether_shost, 6);
	memcpy(pRespEtherHdr->ether_shost, pEtherhead->ether_dhost, 6);
	pRespEtherHdr->ether_type = htons(ETHERTYPE_IP);
	
	pRespIpHdr->check = 0;
	pRespIpHdr->ihl = 5;
	pRespIpHdr->version = 4;
	pRespIpHdr->daddr = pReqIphead->saddr;
	pRespIpHdr->saddr = pReqIphead->daddr;
	pRespIpHdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + g_nBlockBufferLen);
	pRespIpHdr->tos = 0;
	pRespIpHdr->ttl = 64;
	pRespIpHdr->id = htons(2);	
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
	ph.tcplen = htons((u_short)(sizeof(struct tcphdr) + g_nBlockBufferLen));

	pRespTcpHdr->check = CalcTCPSum((uint16_t*)&ph, (uint16_t*)pRespTcpHdr, sizeof(struct tcphdr) + g_nBlockBufferLen);

	//dest.sin_port = pReqTcphead->source;
	//dest.sin_addr.s_addr = pReqIphead->saddr;

	/*
	struct sockaddr sa;
	memset(&sa, 0, sizeof (sa));
	strcpy(sa.sa_data, "eth0");
	*/
	
	if ((sendto(g_block_socket ,
				(const char*)(g_szBlockBuffer), 
				sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + g_nBlockBufferLen, 
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
/*	ZeroMemory(reset_buf, 40);	
	IPHdr*	rstIpHdr = ((IPHdr*)(reset_buf ));
	TCPHdr* rstTcpHdr = ((TCPHdr*)(reset_buf + sizeof (IPHdr) ));



	rstIpHdr->ip_dst = p->iph->ip_dst;
	rstIpHdr->ip_id = htons(2);
	rstIpHdr->ip_len = htons(sizeof (IPHdr) + sizeof (TCPHdr));
	rstIpHdr->ip_off = 0;
	rstIpHdr->ip_proto = 0x06;
	rstIpHdr->ip_src = p->iph->ip_src;
	rstIpHdr->ip_tos = p->iph->ip_tos;
	rstIpHdr->ip_ttl = p->iph->ip_ttl;
	SET_IP_VER(rstIpHdr, 0x4); 
	SET_IP_HLEN(rstIpHdr, 0x5);
	rstIpHdr->ip_csum = 
		CalcIPSum((u_short*) rstIpHdr, IP_HLEN(rstIpHdr) << 2);

	rstTcpHdr->th_ack = p->tcph->th_ack;	
	rstTcpHdr->th_seq = p->tcph->th_seq;
	rstTcpHdr->th_sport = p->tcph->th_sport;
	rstTcpHdr->th_dport = p->tcph->th_dport;
	rstTcpHdr->th_flags = TH_RST;

	SET_TCP_OFFSET(rstTcpHdr, 0x5);
	SET_TCP_X2(rstTcpHdr, 0x0);
	rstTcpHdr->th_win = p->tcph->th_win;
	rstTcpHdr->th_urp = 0;

	ph.sip = (u_int32_t)(p->iph->ip_src.s_addr);
	ph.dip = (u_int32_t)(p->iph->ip_dst.s_addr);
	ph.zero = 0;
	ph.protocol = 0x06;
	ph.tcplen = htons((u_short)sizeof (TCPHdr));

	rstTcpHdr->th_sum		 = 
		CalcTCPSum((u_int16_t *)&ph, 
		(u_int16_t *)rstTcpHdr,
		sizeof(TCPHdr));






	dest.sin_port	= p->tcph->th_dport;
	dest.sin_addr = p->iph->ip_dst;



	if((sendto(m_helperSocket ,(const char*)( reset_buf ), sizeof(IPHdr) + sizeof(TCPHdr), 0,
		(SOCKADDR *)&dest, sizeof(dest))) == SOCKET_ERROR)
	{
		m_pFilterLog->AddLog("sendto failed!");
		return 0;
	}

	*/
	
	return 1;
}


