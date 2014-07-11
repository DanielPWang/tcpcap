#ifndef __STATIS_H__
#define __STATIS_H__

extern uint32_t total_pcap;
extern uint32_t packets_pushed;
extern uint32_t packets_pop;
extern uint32_t sent_count;
extern uint32_t whole_html_session;
extern uint32_t drop_packet_count;
extern uint32_t get_post_count;
extern uint32_t drop_http_image;

#define INC_TOTAL_PCAP do{ ++total_pcap; }while(0)
#define INC_PUSH_PACKETS do{ ++ packets_pushed; }while(0)
#define INC_POP_PACKETS do{ ++packets_pop; }while(0)
#define INC_SENT_HTTP do{ ++sent_count; }while(0)
#define INC_WHOLE_HTML_SESSION do{ ++whole_html_session; }while(0)
#define INC_DROP_PACKET do{ ++drop_packet_count; }while(0)
#define INC_HTTP_GET_POST do { ++get_post_count; } while(0)
#define INC_DROP_HTTP_IMAGE do { ++drop_http_image; } while(0)

void PrintStatis();
void StartShowStatis();

#endif
