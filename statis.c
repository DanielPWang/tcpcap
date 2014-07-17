#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

extern volatile int Living;

uint32_t total_pcap = 0u;
uint32_t packets_pushed = 0u;
uint32_t packets_pop = 0u;
uint32_t sent_count = 0u;
uint32_t whole_html_session = 0u;
uint32_t drop_packet_count = 0u;
uint32_t get_post_count = 0u;
uint32_t new_http_session = 0u;
uint32_t drop_http_image = 0u;
uint32_t http_image = 0u;
// here isnt statis
uint32_t packet_num = 0u;

#define P(x) printf("\t" #x " = %u\n", x)
void PrintStatis()
{
	P(total_pcap);
	P(packets_pushed);
	P(packets_pop);
	P(get_post_count);
	P(new_http_session);
	P(http_image);
	P(sent_count);
	P(whole_html_session);
	P(drop_packet_count);
	P(drop_http_image);
}
void PrintTitle()
{
	printf("TIME\tCAP\tPKTSIN\tPKTSOUT\tGETPOST\tNEWSESSION\tHTTPIMAGE\tSEND\tWHOLE\tDROPPKT\n");
}
void PrintStati()
{
	time_t now = time(NULL);
	char stime[64];
	strftime(stime, sizeof(stime), "%F %T", localtime(&now));
	printf("%s|%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t\n", stime, total_pcap, packets_pushed, 
			packets_pop, get_post_count, new_http_session, http_image, sent_count, 
			whole_html_session, drop_packet_count);
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
	pthread_t pid;
	pthread_create(&pid, NULL, _show_statis_thread, NULL);
}
