#ifndef _BLOCK_H
#define _BLOCK_H
#include <fun_all.h>

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
unsigned short CalcIPSum(unsigned short * w, int blen);
unsigned short CalcTCPSum(unsigned short *h, unsigned short * d, int dlen);
int BlockHttpRequest(const char* pPacket);


#endif

