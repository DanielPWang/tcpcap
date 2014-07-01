#ifndef __STATIS_H__
#define __STATIS_H__

extern uint32_t total_pcap;
extern uint32_t packets_pushed;
extern uint32_t packets_pop;
extern uint32_t sent_count;
extern uint32_t whole_html_session;

#define INC_TOTAL_PCAP while(0) { ++total_pcap; }
#define INC_PUSH_PACKETS while (0) { ++ packets_pushed; }
#define INC_POP_PACKETS while(0) { ++packets_pop; }
#define INC_SENT_HTTP while(0) { ++sent_count; }
#define INC_WHOLE_HTML_SESSION while(0) { ++whole_html_session; }

void PrintStatis();
void StartShowStatis();

#endif
