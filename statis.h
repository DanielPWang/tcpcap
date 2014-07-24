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
extern uint32_t new_http_session;
extern uint32_t http_image;
extern uint32_t packet_num;
extern uint32_t session_count;
extern uint32_t whole_queue_count;
extern uint32_t append_packet_count;
extern uint32_t finish_session_count;
extern uint32_t drop_noquery_nohttp;

#define INC_TOTAL_PCAP do{ ++total_pcap; }while(0)
#define INC_PUSH_PACKETS do{ ++ packets_pushed; }while(0)
#define INC_POP_PACKETS do{ ++packets_pop; }while(0)
#define INC_SENT_HTTP do{ ++sent_count; }while(0)
#define INC_WHOLE_HTML_SESSION do{ ++whole_html_session; }while(0)
#define INC_DROP_PACKET do{ ++drop_packet_count; }while(0)
#define INC_HTTP_GET_POST do { ++get_post_count; } while(0)
#define INC_HTTP_IMAGE do { ++http_image; } while(0)
#define INC_DROP_HTTP_IMAGE do { ++drop_http_image; } while(0)
#define INC_NEW_HTTP_SESSION do { ++new_http_session; } while(0)
#define INC_APPEND_PACKET do { ++append_packet_count; } while(0)
#define INC_FINISH_SESSION do { ++finish_session_count; } while(0)
#define INC_DROP_SESSION_ONQUERY_NOHTTP do { ++drop_noquery_nohttp; } while(0)
#define SET_ACTIVE_SESSION_COUNT(x) (session_count = (x))
#define SET_WHOLE_QUEUE_COUNT(x) (whole_queue_count = (x))

void PrintStatis();
void StartShowStatis();
void StopShowStatis();

#endif
