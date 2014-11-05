#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static volatile int Living = 1;
static pthread_t pid;

uint32_t total_pcap = 0u;
uint32_t packets_pushed = 0u;
uint32_t packets_pop = 0u;
uint32_t sent_count = 0u;
uint32_t whole_html_session = 0u;
uint32_t whole_html_session_no_query = 0u;
uint32_t whole_html_session_no_http = 0u;
uint32_t drop_packet_count = 0u;
//uint32_t get_post_count = 0u;
uint32_t new_http_session = 0u;
uint32_t drop_http_image = 0u;
// uint32_t http_image = 0u;
// here isnt statis
uint32_t packet_num = 0u;
uint32_t session_count = 0u;
uint32_t append_packet_count = 0u;
uint32_t whole_queue_count = 0u;
uint32_t finish_session_count = 0u;
uint32_t drop_noquery_nohttp = 0u;
uint32_t uncomplete_session = 0u;

#define P(x) printf("\t" #x " = %u\n", x)
void PrintStatis()
{
	P(total_pcap);
	P(packets_pushed);
	P(packets_pop);
	//P(get_post_count);
	P(new_http_session);
	P(finish_session_count);
	//P(http_image);
	P(sent_count);
	P(session_count);
	P(whole_html_session);
	P(whole_html_session_no_query);
	P(whole_html_session_no_http);
	P(drop_packet_count);
	P(drop_http_image);
	P(append_packet_count);
	P(whole_queue_count);
	P(drop_noquery_nohttp);
	P(uncomplete_session);
}
void PrintTitle()
{
	printf("TIME CAP PKTSIN PKTSOUT NEWSESSION FINISHSESSION APPEND SEND ACTSESSION WHOLE NOQUERY NOHTTP WHOLES DROPPKT NOHTTPQUERY UNCOMPLETE\n");
}
void PrintStati()
{
	time_t now = time(NULL);
	char stime[64];
	strftime(stime, sizeof(stime), "%F %T", localtime(&now));
	printf("%s|%u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n", stime, total_pcap, packets_pushed, 
			packets_pop, new_http_session, finish_session_count, append_packet_count, 
			sent_count, session_count, whole_html_session, whole_html_session_no_query, 
			whole_html_session_no_http,
			whole_queue_count, drop_packet_count, drop_noquery_nohttp,
			uncomplete_session);
}
void* _show_statis_thread(void* p)
{
	PrintTitle();
	while (Living) {
		PrintStati();
		int err = sleep(5);
	}
	return NULL;
}
void StartShowStatis()
{
	pthread_create(&pid, NULL, _show_statis_thread, NULL);
}
void StopShowStatis()
{
	Living = 0;
	void* p;
	pthread_join(pid, &p);
}
