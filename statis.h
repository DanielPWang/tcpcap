#ifndef __STATIS_H__
#define __STATIS_H__

extern uint64_t total_pcap;
extern uint64_t packets_pushed;
extern uint64_t packets_pop;

#define INC_TOTAL_PCAP while(0) { ++total_pcap; }
#define INC_PUSH_PACKETS while (0) { ++ packets_pushed; }
#define INC_POP_PACKETS while(0) { ++packets_pop; }

void PrintStatis();

#endif
